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
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use super::branding;
use super::settings::{self, WebSettings};
use crate::infra::support::audit;
use crate::infra::auth::AuthState;
use crate::infra::metrics::Collector;
use crate::platform::config::PanelConfig;
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

pub(crate) type Shared = Arc<WebState>;

impl WebState {
    /// Poison-safe guard over the console settings — the single typed accessor
    /// handlers use instead of reaching into the `Mutex` directly (facade so
    /// `WebState` doesn't leak its lock/representation across the web layer).
    fn settings_guard(&self) -> std::sync::MutexGuard<'_, WebSettings> {
        self.settings.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A cloned settings snapshot (caller holds no lock).
    fn settings_snapshot(&self) -> WebSettings {
        self.settings_guard().clone()
    }
}

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
    // Periodically prune expired sessions/challenges/tickets/rate-limit entries
    // so memory doesn't depend solely on the prune-on-insert paths.
    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            sweeper.auth.sweep();
        }
    });
    tokio::spawn(async move {
        if let Err(e) = serve(state, port, https).await {
            tracing::warn!("web console exited: {e}");
        }
    });
}

async fn serve(state: Shared, port: u16, https: bool) -> anyhow::Result<()> {
    let app = crate::web::routes::build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    bind_and_serve(app, addr, https).await
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
    let dir = crate::platform::paths::data_dir();
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

/// A resolved, authenticated account — the request's **principal**. Built once
/// per request by `resolve_account` from the bearer token, it carries the
/// identity facts handlers/services need (role, system user, 2FA state) so they
/// never re-derive "who is this / what may they do" from settings/users.
pub(crate) struct Account {
    username: String,
    is_admin: bool,
    is_super: bool,
    /// System user to drop privileges to for terminal/file ops. `None` for the
    /// super-admin (operates as the panel's own uid, i.e. root).
    system_user: Option<String>,
    /// Whether this account has TOTP two-factor enabled.
    totp_enabled: bool,
}

impl Account {
    /// The account's role label ("admin" for sudo/owner, else "user").
    fn role(&self) -> &'static str {
        if self.is_admin {
            "admin"
        } else {
            "user"
        }
    }

    /// The domain `Principal` for this account (use-case actor).
    fn to_principal(&self) -> crate::domain::identity::Principal {
        crate::domain::identity::Principal {
            username: self.username.clone(),
            is_super: self.is_super,
            system_user: self.system_user.clone(),
        }
    }
}

/// Resolve an account name to a super-admin or panel-user view.
fn resolve_account(state: &Shared, username: &str) -> Option<Account> {
    {
        let su = state.settings_guard();
        if username == su.username {
            return Some(Account {
                username: su.username.clone(),
                is_admin: true,
                is_super: true,
                system_user: None,
                totp_enabled: su.totp_enabled,
            });
        }
    }
    crate::app::users::find(username).map(|u| Account {
        is_admin: u.is_admin(),
        is_super: false,
        system_user: Some(u.username.clone()),
        totp_enabled: u.totp_enabled,
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
mod accounts;
mod policy;
use accounts::*;
use policy::*;

// Handler bodies live in `controllers` (≈ Laravel app/Http/Controllers); the
// gate + security-header layers in `middleware`. The route table that binds
// them is `crate::web::routes`.
pub(crate) mod controllers;
pub(crate) mod middleware;
pub(crate) use middleware::*;

/// Best-effort current account name for audit records (empty when unresolved).
pub(crate) fn actor_name(state: &Shared, headers: &header::HeaderMap) -> String {
    current_account(state, headers)
        .map(|a| a.username)
        .unwrap_or_default()
}
