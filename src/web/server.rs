//! Axum HTTP server for the on-box web console.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        ConnectInfo, Query, Request, State,
    },
    http::{header, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::audit;
use super::auth::{proof_matches, AuthState};
use super::branding;
use super::settings::{self, WebSettings};
use crate::config::PanelConfig;
use crate::metrics::Collector;
use include_dir::{include_dir, Dir};

/// Web-console UI assets (css + js modules), embedded at compile time so the
/// binary stays self-contained. `index.html` is served separately (templated
/// with branding); everything else is served verbatim from here under `/ui/`.
static UI_ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/web/ui");

/// Shared web-console state.
pub struct WebState {
    auth: AuthState,
    settings: std::sync::Mutex<WebSettings>,
    /// Reused metrics collector (CPU% needs a persistent handle across reads).
    collector: Mutex<Collector>,
    /// Runtime config (used by the self-update endpoints).
    cfg: PanelConfig,
}

type Shared = Arc<WebState>;

/// Start the web console in a background task (no-op when disabled). Returns
/// immediately; the server runs for the process lifetime.
pub fn spawn(cfg: PanelConfig) {
    let (s, _fresh) = settings::load_or_init(cfg.web_port);
    let port = s.port;
    let https = s.https;
    let ttl_secs = (s.session_timeout.max(1) as u64) * 60;
    let auth = AuthState::with_store();
    auth.set_ttl_secs(ttl_secs);
    let state: Shared = Arc::new(WebState {
        auth,
        settings: std::sync::Mutex::new(s),
        collector: Mutex::new(Collector::new()),
        cfg,
    });
    tokio::spawn(async move {
        if let Err(e) = serve(state, port, https).await {
            tracing::warn!("web console exited: {e}");
        }
    });
}

async fn serve(state: Shared, port: u16, https: bool) -> anyhow::Result<()> {
    let app = build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    bind_and_serve(app, addr, https).await
}

/// Build the web console's full route table with the auth/entry-gate middleware
/// and shared state applied. Routes above the gate layer are public (login);
/// everything else requires an authenticated session.
fn build_router(state: Shared) -> Router {
    Router::new()
        // Public (no auth): the login page + login endpoint.
        .route("/", get(index_page))
        .route("/ui/*path", get(ui_asset))
        .route("/api/login/challenge", get(login_challenge))
        .route("/api/login", post(login))
        // Authenticated API.
        .route("/api/logout", post(logout))
        .route("/api/ticket", post(mint_ticket))
        .route("/api/me", get(me))
        .route("/api/profile", post(put_profile))
        .route("/api/password", post(put_password))
        .route("/api/2fa/setup", post(twofa_setup))
        .route("/api/2fa/enable", post(twofa_enable))
        .route("/api/2fa/disable", post(twofa_disable))
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/update", post(users_update))
        .route("/api/users/delete", post(users_delete))
        .route("/api/info", get(panel_info))
        .route("/api/metrics", get(metrics))
        .route("/api/procs", get(procs))
        .route("/api/settings", get(get_settings).post(put_settings))
        .route("/api/logs", get(logs_list))
        .route("/api/logs/clear", post(logs_clear))
        .route("/api/branding", get(get_branding).post(put_branding))
        .route("/api/update/status", get(update_status))
        .route(
            "/api/update/config",
            get(update_config_get).post(update_config_put),
        )
        .route("/api/update/check", post(update_check))
        .route("/api/update/changelog", get(update_changelog))
        .route("/api/update/apply", post(update_apply))
        .route("/api/docker", post(docker_op))
        .route("/api/nginx", post(nginx_op))
        .route("/api/mysql", post(mysql_op))
        .route("/api/terminal", get(terminal_ws))
        .route("/api/container/terminal", get(container_terminal_ws))
        .route("/api/files/list", post(files_list))
        .route("/api/files/mkdir", post(files_mkdir))
        .route("/api/files/delete", post(files_delete))
        .route("/api/files/download", get(files_download))
        .route("/api/files/upload", post(files_upload))
        .route("/api/docker/download", get(docker_download))
        .route("/api/docker/image-upload", post(docker_image_upload))
        .route("/api/nginx/static-upload", post(nginx_static_upload))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            entry_gate,
        ))
        .with_state(state)
}

/// Bind and serve the app on `addr`, over self-signed HTTPS (rustls ring
/// provider — musl-static friendly) or plain HTTP. Runs until the process exits.
async fn bind_and_serve(app: Router, addr: SocketAddr, https: bool) -> anyhow::Result<()> {
    if https {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem) = ensure_panel_cert()?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
        tracing::info!(%addr, "web console listening (https)");
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "web console listening");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

/// Safe-entry gate: when a non-"/" entry path is configured, only requests that
/// (a) carry a valid session token, (b) carry the matching `dn7_entry` cookie,
/// or (c) hit the entry path itself are served; everything else gets a bare
/// 404. Visiting the entry path returns the login page and sets the cookie, so
/// the SPA's subsequent `/api` + `/ui` requests pass. Defends against scanners
/// that don't know the secret path (obscurity layer, not a TLS replacement).
async fn entry_gate(State(state): State<Shared>, req: Request, next: Next) -> Response {
    // Capture the client IP + sanitized request headers for the audit log, and
    // bind them as a per-request context so any audit record made while handling
    // this request can attach them (no per-handler plumbing).
    let client_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_default();
    let headers_str = sanitize_headers(req.headers());
    let ctx = audit::RequestCtx {
        ip: client_ip,
        headers: headers_str,
    };
    audit::scope(ctx, entry_gate_inner(state, req, next)).await
}

/// The actual gate logic (allow list + safe-entry path), run inside the audit
/// request-context scope established by `entry_gate`.
async fn entry_gate_inner(state: Shared, req: Request, next: Next) -> Response {
    // Authorized-IP allow list (when configured). Loopback is always allowed to
    // avoid a self-lockout from the local CLI / curl.
    let allow = state
        .settings
        .lock()
        .map(|s| s.allow_ips.clone())
        .unwrap_or_default();
    if !allow.is_empty() {
        let peer = req
            .extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());
        let ok = match peer {
            Some(ip) => ip_in_allowlist(&allow, ip),
            None => true, // can't determine peer (shouldn't happen) — fail open
        };
        if !ok {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }
    let entry = state
        .settings
        .lock()
        .map(|s| s.entry_path.clone())
        .unwrap_or_else(|_| "/".to_string());
    if entry == "/" || entry.is_empty() {
        return next.run(req).await;
    }
    let token = entry.trim_start_matches('/').to_string();
    let headers = req.headers();
    let authed = bearer(headers)
        .map(|t| state.auth.valid(&t))
        .unwrap_or(false);
    let cookie_ok = cookie_value(headers, "dn7_entry").as_deref() == Some(token.as_str());
    if authed || cookie_ok {
        return next.run(req).await;
    }
    if req.uri().path() == entry {
        let mut resp = index_page().await.into_response();
        if let Ok(v) =
            format!("dn7_entry={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000").parse()
        {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
        return resp;
    }
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

/// Read a named cookie value from the request headers.
fn cookie_value(headers: &header::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let pfx = format!("{name}=");
    raw.split(';')
        .map(|p| p.trim())
        .find_map(|p| p.strip_prefix(&pfx).map(|v| v.to_string()))
}

/// Serialize request headers to a "Name: value" block for the audit log,
/// redacting anything that could carry a credential (Authorization, Cookie,
/// and any header whose name hints at a token/secret/password/session/key).
fn sanitize_headers(h: &header::HeaderMap) -> String {
    let mut out = String::new();
    for (name, value) in h.iter() {
        let n = name.as_str();
        let nl = n.to_ascii_lowercase();
        let secret = nl == "authorization"
            || nl == "cookie"
            || nl == "proxy-authorization"
            || nl.contains("token")
            || nl.contains("secret")
            || nl.contains("password")
            || nl.contains("session")
            || nl.contains("api-key")
            || nl.contains("apikey");
        let v = if secret {
            "[redacted]".to_string()
        } else {
            value
                .to_str()
                .unwrap_or("[binary]")
                .chars()
                .take(256)
                .collect()
        };
        out.push_str(n);
        out.push_str(": ");
        out.push_str(&v);
        out.push('\n');
    }
    out
}

/// Redact secret-looking fields from a response value (recursively) before it
/// goes into the audit log, then serialize + truncate it.
fn redact_response(v: &Value) -> String {
    let mut v = v.clone();
    redact_json(&mut v);
    let s = serde_json::to_string(&v).unwrap_or_default();
    s.chars().take(4000).collect()
}

fn redact_json(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                let kl = k.to_ascii_lowercase();
                if kl.contains("password")
                    || kl.contains("passwd")
                    || kl.contains("pw_")
                    || kl == "pw"
                    || kl.contains("token")
                    || kl.contains("secret")
                    || kl.contains("salt")
                    || kl.contains("private")
                    || kl.ends_with("key")
                {
                    *val = Value::String("[redacted]".into());
                } else {
                    redact_json(val);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json(item);
            }
        }
        _ => {}
    }
}

/// Whether `ip` is permitted by the authorized-IP allow list. Loopback is
/// always allowed (avoids locking the local operator out). Entries are exact
/// IPs or CIDR blocks (validated on save).
fn ip_in_allowlist(allow: &[String], ip: std::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    for entry in allow {
        if let Some((a, p)) = entry.split_once('/') {
            if let (Ok(net), Ok(prefix)) = (a.parse::<std::net::IpAddr>(), p.parse::<u8>()) {
                if cidr_contains(net, prefix, ip) {
                    return true;
                }
            }
        } else if let Ok(a) = entry.parse::<std::net::IpAddr>() {
            if a == ip {
                return true;
            }
        }
    }
    false
}

/// Whether `ip` falls within the `net`/`prefix` CIDR block (v4 or v6).
fn cidr_contains(net: std::net::IpAddr, prefix: u8, ip: std::net::IpAddr) -> bool {
    match (net, ip) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// Load (or generate + persist) the panel's self-signed TLS cert/key as PEM.
fn ensure_panel_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let dir = crate::paths::data_dir();
    let crt = dir.join("panel-tls.crt");
    let key = dir.join("panel-tls.key");
    if let (Ok(c), Ok(k)) = (std::fs::read(&crt), std::fs::read(&key)) {
        if !c.is_empty() && !k.is_empty() {
            return Ok((c, k));
        }
    }
    let host = sysinfo::System::host_name().unwrap_or_default();
    let mut sans = vec!["localhost".to_string()];
    if !host.is_empty() && host != "localhost" {
        sans.push(host);
    }
    let params = rcgen::CertificateParams::new(sans)?;
    let kp = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&kp)?;
    let cpem = cert.pem();
    let kpem = kp.serialize_pem();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(&crt, &cpem)?;
    std::fs::write(&key, &kpem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
    }
    Ok((cpem.into_bytes(), kpem.into_bytes()))
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Extract a bearer token from the Authorization header.
fn bearer(headers: &header::HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// Require a valid session; returns `Some(response)` to short-circuit when
/// unauthorized, `None` when the request may proceed.
fn require_auth(state: &Shared, headers: &header::HeaderMap) -> Option<Response> {
    let token = bearer(headers).unwrap_or_default();
    if state.auth.valid(&token) {
        None
    } else {
        Some(api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"))
    }
}

/// A resolved, authenticated account: the super-admin (web.json) or a
/// system-backed panel user (users.json).
struct Account {
    username: String,
    is_admin: bool,
    is_super: bool,
    /// System user to drop privileges to for terminal/file ops. `None` for the
    /// super-admin (operates as the panel's own uid, i.e. root).
    system_user: Option<String>,
}

/// Resolve an account name to a super-admin or panel-user view.
fn resolve_account(state: &Shared, username: &str) -> Option<Account> {
    {
        let su = state.settings.lock().unwrap();
        if username == su.username {
            return Some(Account {
                username: su.username.clone(),
                is_admin: true,
                is_super: true,
                system_user: None,
            });
        }
    }
    super::users::find(username).map(|u| Account {
        is_admin: u.is_admin(),
        is_super: false,
        system_user: Some(u.username.clone()),
        username: u.username,
    })
}

/// Resolve the caller (from the bearer token) to an `Account`, or an error
/// response when unauthenticated / the account no longer exists.
#[allow(clippy::result_large_err)]
fn current_account(state: &Shared, headers: &header::HeaderMap) -> Result<Account, Response> {
    let token = bearer(headers).unwrap_or_default();
    match state.auth.identity(&token) {
        Some(user) => resolve_account(state, &user)
            .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized")),
        None => Err(api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized")),
    }
}

/// Require an authenticated **admin** (sudo) account for privileged endpoints.
#[allow(clippy::result_large_err)]
fn require_admin(state: &Shared, headers: &header::HeaderMap) -> Result<Account, Response> {
    let a = current_account(state, headers)?;
    if a.is_admin {
        Ok(a)
    } else {
        Err(api_err(StatusCode::FORBIDDEN, "auth.forbidden"))
    }
}

/// Require the **super-admin** (the bootstrap owner) for global settings.
#[allow(clippy::result_large_err)]
fn require_super(state: &Shared, headers: &header::HeaderMap) -> Result<Account, Response> {
    let a = current_account(state, headers)?;
    if a.is_super {
        Ok(a)
    } else {
        Err(api_err(StatusCode::FORBIDDEN, "auth.forbidden"))
    }
}

/// Build a stable, localizable error response: `{ ok:false, code, error }`.
/// `code` is a machine-stable identifier the client maps to a translated
/// message (`err.<code>`); `error` carries the same code as a neutral fallback
/// for non-localized consumers / logs.
fn api_err(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(json!({ "ok": false, "code": code, "error": code })),
    )
        .into_response()
}

/// Like `api_err`, but keep a human detail string (e.g. an underlying IO error)
/// in `error` while `code` still drives localization on the client.
fn api_err_detail(status: StatusCode, code: &str, detail: impl std::fmt::Display) -> Response {
    (
        status,
        Json(json!({ "ok": false, "code": code, "error": detail.to_string() })),
    )
        .into_response()
}

/// Build the JSON body for a capability-op failure. Fixed validation errors
/// from the docker/nginx/mysql modules carry a stable code as `ERR_CODE:<code>`
/// in their message; split it into a `code` field the client localizes
/// (`err.<code>`). Dynamic/operational errors pass through as plain text.
fn op_err_body(e: anyhow::Error) -> Value {
    let s = e.to_string();
    match s.strip_prefix("ERR_CODE:") {
        Some(code) => json!({ "ok": false, "code": code, "error": code }),
        None => json!({ "ok": false, "error": s }),
    }
}

// ---------------------------------------------------------------------------
// Handler submodules (see .kiro/steering/code-structure.md). Shared state
// (WebState/Account/Shared) and auth/error helpers stay in this parent so the
// descendant modules can read their private items via `use super::*`.
// ---------------------------------------------------------------------------
mod account_api;
mod audit_api;
mod branding_api;
mod files_api;
mod login;
mod settings_api;
mod update_api;
mod users_api;
mod ws;
use account_api::*;
use audit_api::*;
use branding_api::*;
use files_api::*;
use login::*;
use settings_api::*;
use update_api::*;
use users_api::*;
use ws::*;

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------

async fn metrics(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let m = state.collector.lock().await.collect();
    Json(json!({ "ok": true, "data": m })).into_response()
}

async fn procs(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let data = crate::procs::web_snapshot(20).await;
    Json(json!({ "ok": true, "data": data })).into_response()
}

/// Basic panel identity (version + hostname) for the console footer/topbar.
async fn panel_info(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Some(r) = require_auth(&state, &headers) {
        return r;
    }
    let hostname = sysinfo::System::host_name().unwrap_or_default();
    Json(json!({
        "ok": true,
        "data": {
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": hostname,
        }
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Capability dispatch (docker / nginx / mysql) — same JSON protocol as relays
// ---------------------------------------------------------------------------

async fn dispatch(
    state: &Shared,
    headers: &header::HeaderMap,
    chan: &str,
    body: Value,
    f: impl std::future::Future<Output = anyhow::Result<Value>>,
) -> Response {
    // Docker / Nginx / MySQL management are root-level capabilities — admin only.
    let acct = match require_admin(state, headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let op = body
        .get("op")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let res = f.await;
    // Record state-changing operations only (skip reads/polls to keep the log
    // meaningful and small).
    if !is_read_op(&op) {
        let target = body
            .get("inst")
            .or_else(|| body.get("name"))
            .or_else(|| body.get("domain"))
            .or_else(|| body.get("container"))
            .or_else(|| body.get("database"))
            .or_else(|| body.get("ref"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (detail, response) = match &res {
            Ok(v) => (String::new(), redact_response(v)),
            Err(e) => (e.to_string(), String::new()),
        };
        audit::record_op(
            &acct.username,
            &format!("{chan}.{op}"),
            &target,
            res.is_ok(),
            &detail,
            &response,
        );
    }
    match res {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}

/// Read-only / polling ops we don't write to the audit log.
fn is_read_op(op: &str) -> bool {
    matches!(
        op,
        "" | "info"
            | "list"
            | "list_ops"
            | "op_log"
            | "status"
            | "ps"
            | "stats"
            | "logs"
            | "log"
            | "inspect"
            | "get"
            | "detail"
            | "read"
            | "databases"
            | "tables"
            | "columns"
            | "table_rows"
            | "list_users"
            | "user_grants"
            | "credentials"
            | "images"
            | "networks"
            | "volumes"
            | "df"
            | "usage"
            | "ports"
            | "exists"
            | "preview"
            | "validate"
            | "test"
            | "check"
            | "changelog"
            | "dismiss_op"
            | "list_dirs"
            | "network_ips"
            | "container_stats"
            | "get_container_config"
            | "list_backups"
    )
}

async fn docker_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::docker::web_dispatch(&body);
    dispatch(&state, &headers, "docker", body.clone(), fut).await
}

async fn nginx_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::nginx::web_dispatch(&body);
    dispatch(&state, &headers, "nginx", body.clone(), fut).await
}

async fn mysql_op(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let fut = crate::mysql::web_dispatch(&body);
    dispatch(&state, &headers, "mysql", body.clone(), fut).await
}

// ---------------------------------------------------------------------------
// Static UI
// ---------------------------------------------------------------------------

async fn index_page() -> Html<String> {
    let b = branding::load();
    Html(branding::render_index(include_str!("ui/index.html"), &b))
}

/// Serve an embedded UI asset (css/js) under `/ui/...`. These are non-secret
/// front-end modules; no auth required (same posture as the index page).
async fn ui_asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    match UI_ASSETS.get_file(&path) {
        Some(f) => (
            [(header::CONTENT_TYPE, asset_content_type(&path))],
            f.contents().to_vec(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

fn asset_content_type(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "text/javascript; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}
