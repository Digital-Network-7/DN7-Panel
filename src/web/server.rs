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
    let app = Router::new()
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
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    if https {
        // Self-signed HTTPS via rustls (ring provider — musl-static friendly).
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
// Login / logout
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LoginReq {
    #[serde(default)]
    username: String,
    /// Challenge-response: the nonce from `/api/login/challenge` and the proof
    /// `sha256_hex(nonce ":" verifier)`, where `verifier = sha256_hex(salt ":"
    /// password)` (the value the server stores). The cleartext password never
    /// crosses the wire, and the server holds only the irreversible verifier.
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    proof: String,
    /// Optional TOTP code (required when the account has 2FA enabled).
    #[serde(default)]
    code: String,
}

/// GET /api/login/challenge — PUBLIC. Mint a one-time login nonce and return
/// the per-install password salt so the client can compute the verifier.
async fn login_challenge(
    State(state): State<Shared>,
    Query(q): Query<LoginChallengeQuery>,
) -> Response {
    let nonce = state.auth.issue_challenge();
    // Return the salt for the requested account so the client can compute the
    // verifier. Falls back to the super-admin salt (so probing a name doesn't
    // reveal whether it exists — a random-looking salt is always returned).
    let salt = {
        let su = state.settings.lock().unwrap();
        if q.username.is_empty() || q.username == su.username {
            su.pw_salt.clone()
        } else if let Some(u) = super::users::find(&q.username) {
            u.pw_salt
        } else {
            su.pw_salt.clone()
        }
    };
    Json(json!({ "nonce": nonce, "salt": salt })).into_response()
}

#[derive(serde::Deserialize)]
struct LoginChallengeQuery {
    #[serde(default)]
    username: String,
}

async fn login(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let source = peer.ip().to_string();
    if !state.auth.login_allowed(&source) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, "auth.rate_limited");
    }
    // Resolve the account: the super-admin (web.json) or a panel user.
    let (exp_hash, totp_secret, totp_enabled, must_setup) = {
        let su = state.settings.lock().unwrap();
        if req.username == su.username {
            (
                su.verifier().to_string(),
                su.totp_secret.clone(),
                su.totp_enabled,
                su.pw_default || su.username.eq_ignore_ascii_case("admin"),
            )
        } else if let Some(u) = super::users::find(&req.username) {
            (
                u.pw_hash.clone(),
                u.totp_secret.clone(),
                u.totp_enabled,
                false,
            )
        } else {
            (String::new(), String::new(), false, false)
        }
    };
    let pw_ok = !exp_hash.is_empty()
        && state.auth.consume_challenge(&req.nonce)
        && proof_matches(&req.nonce, &exp_hash, &req.proof);
    if !pw_ok {
        state.auth.record_failure(&source);
        audit::record_ip(
            &req.username,
            "auth.login",
            "",
            false,
            "bad_credentials",
            &source,
        );
        return api_err(StatusCode::UNAUTHORIZED, "auth.bad_credentials");
    }
    // Second factor (TOTP) when enabled for this account.
    if totp_enabled {
        if req.code.trim().is_empty() {
            // Password verified, but a code is required — tell the client to ask.
            return Json(json!({ "ok": false, "need_totp": true })).into_response();
        }
        if !super::totp::verify(&totp_secret, &req.code) {
            state.auth.record_failure(&source);
            audit::record_ip(&req.username, "auth.login", "", false, "bad_totp", &source);
            return api_err(StatusCode::UNAUTHORIZED, "auth.bad_totp");
        }
    }
    state.auth.clear_failures(&source);
    let token = state.auth.issue(&req.username);
    audit::record_ip(&req.username, "auth.login", "", true, "", &source);
    Json(json!({ "ok": true, "token": token, "must_setup": must_setup })).into_response()
}

async fn logout(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let who = current_account(&state, &headers)
        .map(|a| a.username)
        .unwrap_or_default();
    if let Some(t) = bearer(&headers) {
        state.auth.revoke(&t);
    }
    if !who.is_empty() {
        audit::record(&who, "auth.logout", "", true, "");
    }
    Json(json!({ "ok": true })).into_response()
}

/// POST /api/ticket — mint a one-time, 30-second ticket for a single WebSocket
/// upgrade or file download. Requires a valid bearer session; the ticket (not
/// the long-lived token) is what goes in the URL, so a leaked URL exposes only
/// a short-lived, single-use credential.
async fn mint_ticket(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    Json(json!({ "ok": true, "data": { "ticket": state.auth.issue_ticket(&acct.username) } }))
        .into_response()
}

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
// Settings
// ---------------------------------------------------------------------------

async fn get_settings(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let s = state.settings.lock().unwrap().clone();
    // The password is intentionally NOT returned: a session should never be able
    // to read back the reusable console password. The form sends a new password
    // only when the operator chooses to change it.
    Json(json!({
        "ok": true,
        "data": { "port": s.port, "username": s.username, "pw_default": s.pw_default,
                  "entry_path": s.entry_path, "https": s.https,
                  "session_timeout": s.session_timeout, "allow_ips": s.allow_ips,
                  "must_setup": s.pw_default || s.username.eq_ignore_ascii_case("admin") }
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct SettingsReq {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    username: Option<String>,
    /// Password change: client-computed `salt` + `sha256_hex(salt ":" password)`
    /// so the plaintext never crosses the wire. Both must be present to change.
    #[serde(default)]
    pw_salt: Option<String>,
    #[serde(default)]
    pw_hash: Option<String>,
    /// `sha256_hex(current_salt ":" new_password)` — lets the server verify the
    /// new password differs from the current (default) one without ever seeing
    /// the plaintext. Required when changing the password off the default.
    #[serde(default)]
    pw_check: Option<String>,
    /// Safe-entry path ("/" disables it). Applied live (no restart).
    #[serde(default)]
    entry_path: Option<String>,
    /// Serve over HTTPS (self-signed). Changing requires a restart.
    #[serde(default)]
    https: Option<bool>,
    /// Session inactivity timeout in minutes. Applied live.
    #[serde(default)]
    session_timeout: Option<u32>,
    /// Authorized client IPs / CIDRs (one per entry). Empty = allow any.
    #[serde(default)]
    allow_ips: Option<Vec<String>>,
}

async fn put_settings(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let mut needs_restart = false;
    let saved = {
        let mut s = state.settings.lock().unwrap();
        let was_default = s.pw_default;
        let cur_hash = s.pw_hash.clone();
        if let Some(p) = req.port {
            if !(1..=65535).contains(&p) {
                return api_err(StatusCode::BAD_REQUEST, "settings.port_range");
            }
            if p != s.port {
                s.port = p;
                needs_restart = true;
            }
        }
        // Password change: accept a client-computed salt + hash (plaintext never
        // crosses the wire). Both must be present and well-formed hex.
        if req.pw_salt.is_some() || req.pw_hash.is_some() {
            let salt = req.pw_salt.unwrap_or_default();
            let hash = req.pw_hash.unwrap_or_default();
            let salt_ok = salt.len() == 32 && salt.bytes().all(|b| b.is_ascii_hexdigit());
            let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
            if !salt_ok || !hash_ok {
                return api_err(StatusCode::BAD_REQUEST, "settings.pw_format");
            }
            // While still on the auto-generated default, require proof that the
            // new password actually differs from it: pw_check = sha256(current
            // salt ":" new password) must NOT equal the stored default hash.
            if was_default {
                let chk = req.pw_check.clone().unwrap_or_default().to_lowercase();
                if chk.is_empty() || chk == cur_hash {
                    return api_err(StatusCode::BAD_REQUEST, "settings.pw_is_default");
                }
            }
            s.set_password_hashed(&salt, &hash.to_lowercase());
        }
        if let Some(un) = req.username {
            let un = un.trim();
            if un.len() < 2
                || un.len() > 32
                || !un
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return api_err(StatusCode::BAD_REQUEST, "settings.username_format");
            }
            // "admin" is the default account name and is not allowed as a chosen
            // account (the operator must pick their own).
            if un.eq_ignore_ascii_case("admin") {
                return api_err(StatusCode::BAD_REQUEST, "settings.username_reserved");
            }
            s.username = un.to_string();
        }
        // Safe-entry path — applied live (the gate reads it per request).
        if let Some(ep) = &req.entry_path {
            match settings::normalize_entry(ep) {
                Some(norm) => s.entry_path = norm,
                None => return api_err(StatusCode::BAD_REQUEST, "settings.bad_entry"),
            }
        }
        // HTTPS toggle — needs a restart to rebind the listener.
        if let Some(h) = req.https {
            if h != s.https {
                s.https = h;
                needs_restart = true;
            }
        }
        // Session inactivity timeout (minutes) — applied live to the auth layer.
        if let Some(t) = req.session_timeout {
            if !(1..=43200).contains(&t) {
                return api_err(StatusCode::BAD_REQUEST, "settings.timeout_range");
            }
            s.session_timeout = t;
            state.auth.set_ttl_secs((t.max(1) as u64) * 60);
        }
        // Authorized IP allow list — validated; empty = allow any address.
        if let Some(ips) = &req.allow_ips {
            match settings::normalize_allow_ips(ips) {
                Some(list) => s.allow_ips = list,
                None => return api_err(StatusCode::BAD_REQUEST, "settings.bad_allow_ip"),
            }
        }
        s.clone()
    };
    if let Err(e) = settings::save(&saved) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(
        &actor_name(&state, &headers),
        "settings.update",
        "",
        true,
        "",
    );
    Json(json!({ "ok": true, "needs_restart": needs_restart })).into_response()
}

// ---------------------------------------------------------------------------
// Audit log (Owner only)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LogsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

/// GET /api/logs — the audit log, newest first. Super-admin (Owner) only.
async fn logs_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let entries = audit::read(q.limit.unwrap_or(500));
    Json(json!({ "ok": true, "data": { "entries": entries } })).into_response()
}

/// POST /api/logs/clear — erase the audit log. Owner only.
async fn logs_clear(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let actor = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(e) = audit::clear() {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&actor.username, "logs.clear", "", true, "");
    Json(json!({ "ok": true })).into_response()
}

/// Best-effort current account name for audit records (empty when unresolved).
fn actor_name(state: &Shared, headers: &header::HeaderMap) -> String {
    current_account(state, headers)
        .map(|a| a.username)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Account self-service: profile / password / 2FA (any authenticated user)
// ---------------------------------------------------------------------------

/// GET /api/me — the caller's account: identity, role, profile, 2FA + whether a
/// first-run credential setup is still pending (super-admin only).
async fn me(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let (full_name, nickname, avatar, totp_enabled, must_setup) = if a.is_super {
        let s = state.settings.lock().unwrap();
        (
            s.full_name.clone(),
            s.nickname.clone(),
            s.avatar.clone(),
            s.totp_enabled,
            s.pw_default || s.username.eq_ignore_ascii_case("admin"),
        )
    } else {
        match super::users::find(&a.username) {
            Some(u) => (u.full_name, u.nickname, u.avatar, u.totp_enabled, false),
            None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
        }
    };
    // Home directory to open the file manager at: the user's system home, or
    // the panel owner's home (root) for the super-admin.
    let home = match &a.system_user {
        Some(u) => super::users::getpwnam(u)
            .map(|(_, h)| h)
            .unwrap_or_else(|| "/".to_string()),
        None => std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "/root".to_string()),
    };
    Json(json!({ "ok": true, "data": {
        "username": a.username,
        "is_admin": a.is_admin,
        "is_super": a.is_super,
        "role": if a.is_admin { "admin" } else { "user" },
        "full_name": full_name,
        "nickname": nickname,
        "avatar": avatar,
        "totp_enabled": totp_enabled,
        "must_setup": must_setup,
        "home": home,
    }}))
    .into_response()
}

#[derive(serde::Deserialize)]
struct ProfileReq {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    /// base64 data URL (size-limited).
    #[serde(default)]
    avatar: Option<String>,
}

fn clip(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// POST /api/profile — update the caller's own full name / nickname / avatar.
async fn put_profile(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<ProfileReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(av) = &req.avatar {
        if av.len() > 700_000 {
            return api_err(StatusCode::BAD_REQUEST, "branding.logo_invalid");
        }
    }
    if a.is_super {
        let saved = {
            let mut s = state.settings.lock().unwrap();
            if let Some(f) = &req.full_name {
                s.full_name = clip(f, 64);
            }
            if let Some(n) = &req.nickname {
                s.nickname = clip(n, 40);
            }
            if let Some(av) = &req.avatar {
                s.avatar = av.clone();
            }
            s.clone()
        };
        if let Err(e) = settings::save(&saved) {
            return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
        }
    } else {
        let res = super::users::update(&a.username, |u| {
            if let Some(f) = &req.full_name {
                u.full_name = clip(f, 64);
            }
            if let Some(n) = &req.nickname {
                u.nickname = clip(n, 40);
            }
            if let Some(av) = &req.avatar {
                u.avatar = av.clone();
            }
        });
        if let Err(e) = res {
            return Json(op_err_body(e)).into_response();
        }
        if let Some(f) = &req.full_name {
            let _ = super::users::set_full_name(&a.username, &clip(f, 64)).await;
        }
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(serde::Deserialize)]
struct PasswordReq {
    #[serde(default)]
    pw_salt: String,
    #[serde(default)]
    pw_hash: String,
    /// `sha256_hex(current_salt ":" old_password)` — proves the caller knows
    /// their current password before it can be changed.
    #[serde(default)]
    old_verifier: String,
    /// Plaintext new password (system users only) — used to sync the OS
    /// password to the panel password. Omitted for the super-admin.
    #[serde(default)]
    password: String,
}

/// POST /api/password — change the caller's own panel password (requires the
/// current password to be verified first).
async fn put_password(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<PasswordReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let salt_ok = req.pw_salt.len() == 32 && req.pw_salt.bytes().all(|b| b.is_ascii_hexdigit());
    let hash_ok = req.pw_hash.len() == 64 && req.pw_hash.bytes().all(|b| b.is_ascii_hexdigit());
    if !salt_ok || !hash_ok {
        return api_err(StatusCode::BAD_REQUEST, "settings.pw_format");
    }
    let hash = req.pw_hash.to_lowercase();
    let cur_hash = if a.is_super {
        state.settings.lock().unwrap().pw_hash.clone()
    } else {
        super::users::find(&a.username)
            .map(|u| u.pw_hash)
            .unwrap_or_default()
    };
    // Verify the current password (its salted hash) before allowing a change.
    if cur_hash.is_empty() || req.old_verifier.to_lowercase() != cur_hash {
        return api_err(StatusCode::BAD_REQUEST, "settings.bad_old_password");
    }
    if a.is_super {
        let saved = {
            let mut s = state.settings.lock().unwrap();
            s.set_password_hashed(&req.pw_salt, &hash);
            s.clone()
        };
        if let Err(e) = settings::save(&saved) {
            return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
        }
    } else {
        let res = super::users::update(&a.username, |u| {
            u.pw_salt = req.pw_salt.clone();
            u.pw_hash = hash.clone();
        });
        if let Err(e) = res {
            return Json(op_err_body(e)).into_response();
        }
        // Sync the OS password to the new panel password.
        if !req.password.is_empty() {
            if let Some(u) = &a.system_user {
                let _ = super::users::set_system_password(u, &req.password).await;
            }
        }
    }
    audit::record(&a.username, "account.password", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

/// Read the caller's pending/active TOTP secret.
fn read_totp(state: &Shared, a: &Account) -> String {
    if a.is_super {
        state.settings.lock().unwrap().totp_secret.clone()
    } else {
        super::users::find(&a.username)
            .map(|u| u.totp_secret)
            .unwrap_or_default()
    }
}

/// Persist the caller's TOTP secret + enabled flag.
fn write_totp(state: &Shared, a: &Account, secret: &str, enabled: bool) -> anyhow::Result<()> {
    if a.is_super {
        let mut s = state.settings.lock().unwrap();
        s.totp_secret = secret.to_string();
        s.totp_enabled = enabled;
        let saved = s.clone();
        drop(s);
        settings::save(&saved)
    } else {
        super::users::update(&a.username, |u| {
            u.totp_secret = secret.to_string();
            u.totp_enabled = enabled;
        })
    }
}

/// POST /api/2fa/setup — generate a fresh (pending) TOTP secret + QR. 2FA is not
/// enabled until the user verifies a live code via /api/2fa/enable.
async fn twofa_setup(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = super::totp::gen_secret();
    let issuer = branding::load().panel_name;
    let uri = super::totp::provisioning_uri(&issuer, &a.username, &secret);
    let qr = super::totp::qr_svg(&uri);
    if let Err(e) = write_totp(&state, &a, &secret, false) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    Json(json!({ "ok": true, "data": { "secret": secret, "uri": uri, "qr_svg": qr } }))
        .into_response()
}

#[derive(serde::Deserialize)]
struct CodeReq {
    #[serde(default)]
    code: String,
}

/// POST /api/2fa/enable — bind 2FA after verifying a live code.
async fn twofa_enable(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CodeReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = read_totp(&state, &a);
    if secret.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_totp");
    }
    if !super::totp::verify(&secret, &req.code) {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_totp");
    }
    if let Err(e) = write_totp(&state, &a, &secret, true) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&a.username, "account.2fa_enable", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

/// POST /api/2fa/disable — verify a current code, then turn 2FA off.
async fn twofa_disable(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CodeReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = read_totp(&state, &a);
    if !secret.is_empty() && !super::totp::verify(&secret, &req.code) {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_totp");
    }
    if let Err(e) = write_totp(&state, &a, "", false) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&a.username, "account.2fa_disable", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

// ---------------------------------------------------------------------------
// User management (admin only): panel users backed by system accounts
// ---------------------------------------------------------------------------

async fn users_list(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let mut list = Vec::new();
    {
        let s = state.settings.lock().unwrap();
        list.push(json!({
            "username": s.username, "role": "admin", "is_super": true,
            "full_name": s.full_name, "nickname": s.nickname, "uid": s.owner_uid, "totp_enabled": s.totp_enabled,
        }));
    }
    for u in super::users::load() {
        list.push(json!({
            "username": u.username, "role": u.role, "is_super": false,
            "full_name": u.full_name, "nickname": u.nickname, "uid": u.uid, "totp_enabled": u.totp_enabled,
        }));
    }
    Json(json!({ "ok": true, "data": { "users": list } })).into_response()
}

/// Privilege level: super-admin (owner) 2, admin (sudo) 1, plain user 0.
fn account_level(a: &Account) -> u8 {
    if a.is_super {
        2
    } else if a.is_admin {
        1
    } else {
        0
    }
}
fn role_level(role: &str) -> u8 {
    if role == "admin" {
        1
    } else {
        0
    }
}

#[derive(serde::Deserialize)]
struct CreateUserReq {
    #[serde(default)]
    username: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    pw_salt: String,
    #[serde(default)]
    pw_hash: String,
    /// Plaintext (local console) — used to set the matching OS password.
    #[serde(default)]
    password: String,
}

async fn users_create(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if !matches!(req.role.as_str(), "admin" | "user") {
        return Json(op_err_body(anyhow::anyhow!("ERR_CODE:users.bad_role"))).into_response();
    }
    // May only create an account strictly lower in privilege than oneself
    // (owner → admin/user; admin → user only).
    if role_level(&req.role) >= account_level(&actor) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // Can't collide with the super-admin's login name.
    if req.username == state.settings.lock().unwrap().username {
        return Json(op_err_body(anyhow::anyhow!("ERR_CODE:users.exists"))).into_response();
    }
    match super::users::create(
        &req.username,
        &req.role,
        req.full_name.trim(),
        &req.pw_salt,
        &req.pw_hash,
        &req.password,
    )
    .await
    {
        Ok(u) => {
            audit::record(&actor.username, "user.create", &u.username, true, &req.role);
            Json(json!({ "ok": true, "data": { "username": u.username } })).into_response()
        }
        Err(e) => {
            audit::record(
                &actor.username,
                "user.create",
                &req.username,
                false,
                &e.to_string(),
            );
            Json(op_err_body(e)).into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct UpdateUserReq {
    #[serde(default)]
    username: String,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    pw_salt: Option<String>,
    #[serde(default)]
    pw_hash: Option<String>,
    /// Plaintext (local console) — used to set the matching OS password.
    #[serde(default)]
    password: Option<String>,
}

/// POST /api/users/update — an owner/admin edits a **lower-privilege** panel
/// user's profile, role and/or password.
async fn users_update(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<UpdateUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let actor_lvl = account_level(&actor);
    let target = match super::users::find(&req.username) {
        Some(t) => t,
        None => {
            return Json(op_err_body(anyhow::anyhow!("ERR_CODE:users.not_found"))).into_response()
        }
    };
    // Only manage accounts strictly below your own privilege.
    if actor_lvl <= role_level(&target.role) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // Optional role change (also adjusts the sudo group). The new role must
    // also be strictly below the actor.
    if let Some(role) = &req.role {
        if !matches!(role.as_str(), "admin" | "user") {
            return Json(op_err_body(anyhow::anyhow!("ERR_CODE:users.bad_role"))).into_response();
        }
        if role_level(role) >= actor_lvl {
            return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
        }
        if *role != target.role {
            if let Err(e) = super::users::set_sudo(&req.username, role == "admin").await {
                return Json(op_err_body(e)).into_response();
            }
        }
    }
    // Optional password reset (admin-set; no old password needed).
    let pw = if req.pw_salt.is_some() || req.pw_hash.is_some() {
        let salt = req.pw_salt.clone().unwrap_or_default();
        let hash = req.pw_hash.clone().unwrap_or_default();
        let salt_ok = salt.len() == 32 && salt.bytes().all(|b| b.is_ascii_hexdigit());
        let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
        if !salt_ok || !hash_ok {
            return api_err(StatusCode::BAD_REQUEST, "settings.pw_format");
        }
        Some((salt, hash.to_lowercase()))
    } else {
        None
    };
    let res = super::users::update(&req.username, |u| {
        if let Some(f) = &req.full_name {
            u.full_name = f.trim().chars().take(64).collect();
        }
        if let Some(n) = &req.nickname {
            u.nickname = n.trim().chars().take(40).collect();
        }
        if let Some(r) = &req.role {
            u.role = r.clone();
        }
        if let Some((salt, hash)) = &pw {
            u.pw_salt = salt.clone();
            u.pw_hash = hash.clone();
        }
    });
    if let Err(e) = res {
        return Json(op_err_body(e)).into_response();
    }
    if let Some(f) = &req.full_name {
        let _ = super::users::set_full_name(&req.username, f.trim()).await;
    }
    // Sync the OS password to the new panel password (system user).
    if pw.is_some() {
        if let Some(p) = &req.password {
            if !p.is_empty() {
                let _ = super::users::set_system_password(&req.username, p).await;
            }
        }
    }
    audit::record(&actor.username, "user.update", &req.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

#[derive(serde::Deserialize)]
struct DelUserReq {
    #[serde(default)]
    username: String,
}

async fn users_delete(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<DelUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    // Only delete accounts strictly below your own privilege.
    if let Some(t) = super::users::find(&req.username) {
        if account_level(&actor) <= role_level(&t.role) {
            return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
        }
    }
    match super::users::delete(&req.username).await {
        Ok(_) => {
            audit::record(&actor.username, "user.delete", &req.username, true, "");
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            audit::record(
                &actor.username,
                "user.delete",
                &req.username,
                false,
                &e.to_string(),
            );
            Json(op_err_body(e)).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal (PTY over WebSocket)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct WsAuth {
    #[serde(default)]
    ticket: String,
}

async fn terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<WsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    // WebSocket upgrades can't carry an Authorization header from the browser,
    // so a one-time ticket (minted via POST /api/ticket) authorizes the upgrade.
    let user = match state.auth.consume_ticket(&q.ticket) {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Run the shell as the account's system user (non-super), else as root.
    let login_user = resolve_account(&state, &user).and_then(|a| a.system_user);
    ws.on_upgrade(move |socket| handle_terminal(socket, login_user))
}

async fn handle_terminal(socket: WebSocket, login_user: Option<String>) {
    if let Err(e) = crate::terminal::run_web_pty(socket, login_user).await {
        tracing::debug!("web terminal ended: {e}");
    }
}

/// WS query for a container terminal: one-time ticket + container ref.
#[derive(serde::Deserialize)]
struct ContainerWsAuth {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    container: String,
}

async fn container_terminal_ws(
    State(state): State<Shared>,
    Query(q): Query<ContainerWsAuth>,
    ws: WebSocketUpgrade,
) -> Response {
    // Container exec is a Docker capability — admin only. The ticket owner must
    // resolve to an admin account.
    let user = match state.auth.consume_ticket(&q.ticket) {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    match resolve_account(&state, &user) {
        Some(a) if a.is_admin => {}
        _ => return api_err(StatusCode::FORBIDDEN, "auth.forbidden"),
    }
    let container = q.container.clone();
    if container.is_empty() {
        return api_err(StatusCode::BAD_REQUEST, "terminal.missing_container");
    }
    ws.on_upgrade(move |socket| async move {
        if let Err(e) = crate::terminal::run_web_container_exec(socket, &container).await {
            tracing::debug!("web container terminal ended: {e}");
        }
    })
}

// ---------------------------------------------------------------------------
// File transfer (host + container) — plain HTTP request/response.
// ---------------------------------------------------------------------------

/// Body for list/mkdir/delete: a path, optionally scoped to a container.
#[derive(serde::Deserialize)]
struct FileOpReq {
    #[serde(default)]
    path: String,
    /// When set, the operation targets this container's filesystem.
    #[serde(default)]
    container: Option<String>,
}

fn ctn_ref(req: &FileOpReq) -> Option<&str> {
    req.container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Default per-file upload cap (lowered from 512 MiB). Streaming keeps memory
/// bounded regardless, but a smaller cap limits temp-disk blowups too.
const UPLOAD_CAP: u64 = 256 * 1024 * 1024;

/// Global cap on concurrent file transfers (uploads + downloads), so a few
/// parallel transfers can't exhaust resources. A transfer holds a permit for
/// its whole duration (downloads carry it inside the response stream).
fn transfer_sem() -> std::sync::Arc<tokio::sync::Semaphore> {
    static S: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(6)))
        .clone()
}

/// Stream a request body to a host temp file, enforcing `cap` (bounded memory).
/// Returns the temp path, or an error response (and removes the partial temp).
async fn stream_body_to_temp(
    body: axum::body::Body,
    cap: u64,
) -> Result<std::path::PathBuf, Response> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let tmp = crate::file::temp_upload_path();
    let mut f = match tokio::fs::File::create(&tmp).await {
        Ok(f) => f,
        Err(e) => {
            return Err(api_err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "common.save_failed",
                e,
            ))
        }
    };
    let mut total: u64 = 0;
    let mut stream = body.into_data_stream();
    let fail = |tmp: &std::path::PathBuf, resp: Response| {
        let t = tmp.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&t).await;
        });
        resp
    };
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => {
                return Err(fail(
                    &tmp,
                    api_err(StatusCode::BAD_REQUEST, "common.save_failed"),
                ))
            }
        };
        total += chunk.len() as u64;
        if total > cap {
            return Err(fail(
                &tmp,
                api_err(StatusCode::PAYLOAD_TOO_LARGE, "files.too_large"),
            ));
        }
        if f.write_all(&chunk).await.is_err() {
            return Err(fail(
                &tmp,
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed"),
            ));
        }
    }
    if f.flush().await.is_err() {
        return Err(fail(
            &tmp,
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed"),
        ));
    }
    Ok(tmp)
}

async fn files_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let res = match ctn_ref(&req) {
        Some(c) => {
            if !acct.is_admin {
                return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
            }
            crate::file::web_ctn_list(c, &req.path).await
        }
        None => crate::file::web_host_list(&req.path, acct.system_user.as_deref()).await,
    };
    match res {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn files_mkdir(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let res = match ctn_ref(&req) {
        Some(c) => {
            if !acct.is_admin {
                return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
            }
            crate::file::web_ctn_mkdir(c, &req.path).await
        }
        None => crate::file::web_host_mkdir(&req.path, acct.system_user.as_deref()).await,
    };
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

async fn files_delete(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let res = match ctn_ref(&req) {
        Some(c) => {
            if !acct.is_admin {
                return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
            }
            crate::file::web_ctn_delete(c, &req.path).await
        }
        None => crate::file::web_host_delete(&req.path, acct.system_user.as_deref()).await,
    };
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

/// Download query: a one-time ticket (browser can't set Authorization on a
/// direct link), path, optional container.
#[derive(serde::Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
}

async fn files_download(State(state): State<Shared>, Query(q): Query<DownloadQuery>) -> Response {
    use futures::StreamExt;
    let user = match state.auth.consume_ticket(&q.ticket) {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    let acct = match resolve_account(&state, &user) {
        Some(a) => a,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Hold a transfer permit for the whole download (moved into the stream).
    let permit = transfer_sem().acquire_owned().await.ok();
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let res = match ctn {
        Some(c) => {
            if !acct.is_admin {
                return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
            }
            crate::file::web_ctn_read_stream(c, &q.path).await
        }
        None => crate::file::web_host_read_stream(&q.path, acct.system_user.as_deref()).await,
    };
    match res {
        Ok((name, stream)) => {
            // Keep the permit alive for the lifetime of the response stream.
            let guarded = stream.map(move |item| {
                let _hold = &permit;
                item
            });
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                axum::body::Body::from_stream(guarded),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Docker download query: a one-time ticket plus what to fetch — a container
/// backup (kind=backup, name + backup file) or an image export (kind=image,
/// ref). Admin-only; mirrors files_download's ticket model.
#[derive(serde::Deserialize)]
struct DockerDownloadQuery {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    backup: String,
    #[serde(default, rename = "ref")]
    reference: String,
}

async fn docker_download(
    State(state): State<Shared>,
    Query(q): Query<DockerDownloadQuery>,
) -> Response {
    use futures::StreamExt;
    let user = match state.auth.consume_ticket(&q.ticket) {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    let acct = match resolve_account(&state, &user) {
        Some(a) => a,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Docker management is admin-only.
    if !acct.is_admin {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    let permit = transfer_sem().acquire_owned().await.ok();
    let res = match q.kind.as_str() {
        "backup" => crate::docker::backup_read_stream(&q.name, &q.backup).await,
        "image" => crate::docker::image_export_stream(&q.reference).await,
        _ => Err(anyhow::anyhow!("invalid download kind")),
    };
    match res {
        Ok((name, stream)) => {
            let guarded = stream.map(move |item| {
                let _hold = &permit;
                item
            });
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                axum::body::Body::from_stream(guarded),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /api/docker/image-upload — load a local image archive (docker load).
/// Streams the request body (a `docker save` tar, optionally gzipped) into the
/// daemon's image-load API. Admin only.
async fn docker_image_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    body: axum::body::Body,
) -> Response {
    use futures::StreamExt;
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    let stream = body.into_data_stream().map(|r| r.unwrap_or_default());
    match crate::docker::import_image_upload(stream).await {
        Ok(v) => Json(json!({ "ok": true, "data": v })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}

/// Strip characters that could break the Content-Disposition header / path.
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '"' || c == '\\' || c == '\n' || c == '\r' {
                '_'
            } else {
                c
            }
        })
        .take(255)
        .collect()
}

/// Upload: multipart-free — the path/container come as query params and the raw
/// file bytes are the request body (kept simple; the UI sends one file at a
/// time). Caps the body at 512 MiB to bound memory.
#[derive(serde::Deserialize)]
struct UploadQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
}

async fn files_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<UploadQuery>,
    body: axum::body::Body,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if ctn.is_some() && !acct.is_admin {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    // Stream the body to a temp file (bounded memory), then write it into place.
    let tmp = match stream_body_to_temp(body, UPLOAD_CAP).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let res = match ctn {
        Some(c) => crate::file::web_ctn_write_file(c, &q.path, &tmp).await,
        None => crate::file::web_host_write_file(&q.path, &tmp, acct.system_user.as_deref()).await,
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    match res {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

/// Static-site upload: extract an uploaded ZIP, or write a single file, into a
/// managed static webroot. Query params:
///   root  — the static site's webroot subdirectory name (validated panel-side)
///   mode  — "zip" (body is a .zip to extract) | "file" (body is one file)
///   rel   — for mode=file: the file's relative path within the webroot
///   clear — "1" to wipe the webroot first (fresh upload)
/// Body is the raw bytes (capped at 512 MiB), mirroring files_upload.
#[derive(serde::Deserialize)]
struct StaticUploadQuery {
    root: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    rel: Option<String>,
    #[serde(default)]
    clear: Option<String>,
}

async fn nginx_static_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<StaticUploadQuery>,
    body: axum::body::Body,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    let tmp = match stream_body_to_temp(body, UPLOAD_CAP).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let mode = q.mode.as_deref().unwrap_or("zip");
    let clear = q.clear.as_deref() == Some("1");
    let res = crate::nginx::web_static_upload(&q.root, mode, q.rel.as_deref(), clear, &tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match res {
        Ok(n) => Json(json!({ "ok": true, "files": n })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
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

// ---------------------------------------------------------------------------
// Branding (panel name / logo / accent / default theme) — public GET so the
// login page can render branded; authenticated POST to update.
// ---------------------------------------------------------------------------

async fn get_branding() -> Response {
    let b = branding::load();
    Json(json!({ "ok": true, "data": b })).into_response()
}

#[derive(serde::Deserialize)]
struct BrandingReq {
    #[serde(default)]
    panel_name: Option<String>,
    #[serde(default)]
    logo: Option<String>,
    #[serde(default)]
    accent: Option<String>,
    #[serde(default)]
    theme_default: Option<String>,
}

async fn put_branding(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<BrandingReq>,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let b = match branding::validate(req.panel_name, req.logo, req.accent, req.theme_default) {
        Ok(b) => b,
        Err(e) => return api_err(StatusCode::BAD_REQUEST, &e),
    };
    if let Err(e) = branding::save(&b) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(
        &actor_name(&state, &headers),
        "branding.update",
        "",
        true,
        "",
    );
    Json(json!({ "ok": true, "data": b })).into_response()
}

// ---------------------------------------------------------------------------
// Self-update (GitHub + dn7.cn)
// ---------------------------------------------------------------------------

/// GET /api/update/status — live phase/progress + current version (polled by
/// the UI during a download). Auth required.
async fn update_status(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    Json(json!({
        "ok": true,
        "data": {
            "phase": crate::update::phase_str(),
            "progress": crate::update::progress(),
            "done_bytes": crate::update::done_bytes(),
            "total_bytes": crate::update::total_bytes(),
            "in_progress": crate::update::in_progress(),
            "current": env!("CARGO_PKG_VERSION"),
        }
    }))
    .into_response()
}

async fn update_config_get(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let st = crate::update::UpdateState::load();
    Json(json!({ "ok": true, "data": st })).into_response()
}

#[derive(serde::Deserialize)]
struct UpdateConfigReq {
    #[serde(default)]
    auto: Option<bool>,
    /// "github" (preview channel) | "dn7" (default mirror)
    #[serde(default)]
    source_pref: Option<String>,
}

async fn update_config_put(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<UpdateConfigReq>,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let mut st = crate::update::UpdateState::load();
    if let Some(a) = req.auto {
        st.auto = a;
    }
    if let Some(p) = req.source_pref {
        // Legacy "auto" maps to the default mirror; otherwise github/dn7 only.
        let p = if p == "auto" { "dn7".to_string() } else { p };
        if !matches!(p.as_str(), "github" | "dn7") {
            return api_err(StatusCode::BAD_REQUEST, "update.source_invalid");
        }
        st.source_pref = p;
    }
    if let Err(e) = st.save() {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    Json(json!({ "ok": true, "data": st })).into_response()
}

/// POST /api/update/check — probe both sources + report whether a newer build
/// is available. Auth required.
async fn update_check(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let res = crate::update::check(&state.cfg).await;
    Json(json!({ "ok": true, "data": res })).into_response()
}

/// GET /api/update/changelog — release notes for every version newer than the
/// running one (newest first), from whichever source is reachable. Auth req.
async fn update_changelog(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let res = crate::update::changelog(&state.cfg).await;
    Json(json!({ "ok": true, "data": res })).into_response()
}

/// POST /api/update/apply — start a self-update in the background (download →
/// verify → atomic swap → exit for restart). Returns immediately; the UI polls
/// /api/update/status. Auth required.
async fn update_apply(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    if crate::update::in_progress() {
        return Json(
            json!({ "ok": true, "data": { "started": false, "reason": "already in progress" } }),
        )
        .into_response();
    }
    let cfg = state.cfg.clone();
    tokio::spawn(async move {
        crate::update::run_self_update(&cfg).await;
    });
    audit::record(&actor_name(&state, &headers), "update.apply", "", true, "");
    Json(json!({ "ok": true, "data": { "started": true } })).into_response()
}
