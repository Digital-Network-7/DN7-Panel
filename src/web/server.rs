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
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

/// Attach defensive security headers to every response. A Content-Security-
/// Policy locks `default-src`/`connect-src`/`img-src` to same-origin, which
/// blocks an injected script from exfiltrating the session token to an external
/// origin (the main XSS risk for a token-in-JS app); `script-src`/`style-src`
/// keep `'unsafe-inline'` because the bundled UI uses inline handlers/styles (a
/// nonce-based strict policy is a future improvement). HSTS is sent only over
/// HTTPS (browsers ignore it over HTTP, and sending it could strand an
/// HTTP-only deployment).
async fn security_headers(State(state): State<Shared>, req: Request, next: Next) -> Response {
    let https = state.settings.lock().map(|s| s.https).unwrap_or(false);
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; \
        style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
        object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
    let mut set = |name: header::HeaderName, val: &str| {
        if let Ok(v) = header::HeaderValue::from_str(val) {
            h.insert(name, v);
        }
    };
    set(header::CONTENT_SECURITY_POLICY, CSP);
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(header::REFERRER_POLICY, "same-origin");
    if https {
        set(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        );
    }
    resp
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
mod assets;
mod audit_api;
mod branding_api;
mod capability;
mod files_api;
mod gate;
mod login;
mod settings_api;
mod update_api;
mod users_api;
mod ws;
use account_api::*;
use assets::*;
use audit_api::*;
use branding_api::*;
use capability::*;
use files_api::*;
use gate::*;
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
