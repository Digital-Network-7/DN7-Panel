//! Web-console HTTP kernel: shared state (WebState/Account), session/identity
//! guards, server bootstrap (spawn/serve/TLS), and the per-request actor lookup.
use super::*;

/// Web-console UI assets (css + js modules), embedded at compile time so the
/// binary stays self-contained. `index.html` is served separately (templated
/// with branding); everything else is served verbatim from here under `/ui/`.
///
/// NOTE: `include_dir!` snapshots the tree at compile time and isn't tracked for
/// content changes, so after editing any file under `src/web/ui/` touch this file
/// (e.g. bump the marker below) to force a re-embed.
///   ui-embed-rev: 7  (console-access editor + security entry path; X-DN7-Entry header)
pub(crate) static UI_ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/web/ui");

/// Shared web-console state.
pub struct WebState {
    pub(crate) auth: AuthState,
    pub(crate) settings: std::sync::Mutex<WebSettings>,
    /// Reused metrics collector (CPU% needs a persistent handle across reads).
    pub(crate) collector: Mutex<Collector>,
    /// Runtime config (used by the self-update endpoints).
    pub(crate) cfg: PanelConfig,
    /// Root-only control token for the local `dn7` CLI: presented over a DIRECT
    /// loopback connection (no `X-Forwarded-For`) it authenticates as the
    /// super-admin owner, so the CLI drives the same API the web console uses
    /// without a login. The token file is 0600 (only root can read it).
    pub(crate) cli_token: String,
}

pub(crate) type Shared = Arc<WebState>;

impl WebState {
    /// Poison-safe guard over the console settings — the single typed accessor
    /// handlers use instead of reaching into the `Mutex` directly (facade so
    /// `WebState` doesn't leak its lock/representation across the web layer).
    pub(crate) fn settings_guard(&self) -> std::sync::MutexGuard<'_, WebSettings> {
        self.settings.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A cloned settings snapshot (caller holds no lock).
    pub(crate) fn settings_snapshot(&self) -> WebSettings {
        self.settings_guard().clone()
    }
}

/// Start the web console in a background task. Returns immediately; the server
/// runs for the process lifetime.
pub fn spawn(cfg: PanelConfig) {
    let (s, _fresh) = settings::load_or_init(cfg.web_port);
    let ttl_secs = (s.session_timeout.max(1) as u64) * 60;
    let auth = AuthState::with_store();
    auth.set_ttl_secs(ttl_secs);
    let cli_token = load_or_make_cli_token(&cfg.data_dir);
    let state: Shared = Arc::new(WebState {
        auth,
        settings: std::sync::Mutex::new(s),
        collector: Mutex::new(Collector::new()),
        cfg,
        cli_token,
    });
    // Periodically prune expired sessions/challenges/tickets/rate-limit entries
    // so memory doesn't depend solely on the prune-on-insert paths.
    let sweeper = state.clone();
    crate::infra::metrics::history_start(); // begin the dashboard time-series sampler
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            tick.tick().await;
            sweeper.auth.sweep();
        }
    });
    tokio::spawn(async move {
        if let Err(e) = serve(state).await {
            tracing::warn!("web console exited: {e}");
        }
    });
}

/// Serve the console on loopback, plain HTTP. The console is now an internal
/// service: the edge owns :80/:443 and reverse-proxies the operator's external
/// address to here (terminating TLS at the edge), so the console never binds a
/// public interface and never terminates its own TLS. The real client IP is
/// recovered from the edge's `X-Forwarded-For` (trusted because the peer is
/// loopback — see `security::real_ip`).
pub(crate) async fn serve(state: Shared) -> anyhow::Result<()> {
    let app = crate::web::routes::build_router(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], dn7_edge::CONSOLE_LOOPBACK_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "web console listening (loopback; fronted by the edge)");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Extract a bearer token from the Authorization header.
pub(crate) fn bearer(headers: &header::HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// The authenticated username for this request, or `None`. The root-only CLI
/// control token — presented over a DIRECT loopback connection (no proxy
/// headers) — resolves to the super-admin owner; otherwise the normal bearer
/// session token is resolved.
pub(crate) fn authed_user(state: &Shared, headers: &header::HeaderMap) -> Option<String> {
    let token = bearer(headers).unwrap_or_default();
    if token.is_empty() {
        return None;
    }
    if !state.cli_token.is_empty()
        && ct_eq(token.as_bytes(), state.cli_token.as_bytes())
        && is_direct_loopback(headers)
    {
        // The CLI control token authenticates as the super-admin owner.
        let su = state.settings_guard();
        if su.initialized && !su.username.is_empty() {
            return Some(su.username.clone());
        }
        return None;
    }
    state.auth.identity(&token)
}

/// A direct loopback connection (the local CLI talking straight to the console),
/// not an edge-forwarded external request. The edge stamps a dedicated
/// `X-DN7-Forwarded` marker (overwriting any client copy) on EVERY request it
/// proxies, and also sets `X-Forwarded-For` / `X-Real-IP`; the absence of all
/// three means a genuinely direct hit. The CLI control token is only honoured
/// here, so a leaked token can't be replayed through the public edge — and the
/// positive marker means a future change that drops `X-Forwarded-For` on some
/// edge path still can't be mistaken for a direct hit.
fn is_direct_loopback(headers: &header::HeaderMap) -> bool {
    headers.get("x-dn7-forwarded").is_none()
        && headers.get("x-forwarded-for").is_none()
        && headers.get("x-real-ip").is_none()
}

/// Constant-time byte-slice equality (length-aware) for the control token and the
/// init-token gate (middleware::gate).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate (once) or load the root-only CLI control token (`<data>/cli.token`,
/// 0600). The local `dn7` CLI reads it to drive the API as super-admin, so the
/// whole boundary rests on the file being root-only: an existing token is reused
/// ONLY if it is still tight (no group/other bits) — a loose-perm file (e.g.
/// restored from a backup under a wide umask) is distrusted and re-minted. The
/// write goes through `write_private` (O_EXCL temp + 0600 + atomic rename), which
/// re-establishes the mode on every overwrite and can't follow a planted symlink.
fn load_or_make_cli_token(data_dir: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = data_dir.join("cli.token");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let token = s.trim().to_string();
        let tight = std::fs::metadata(&path)
            .map(|m| m.permissions().mode() & 0o077 == 0)
            .unwrap_or(false);
        if !token.is_empty() && tight {
            return token;
        }
        if !token.is_empty() {
            tracing::warn!("cli.token had loose permissions; re-minting a fresh token");
        }
    }
    let token = dn7_cred::random_token();
    if let Err(e) = crate::platform::paths::write_private(&path, token.as_bytes()) {
        tracing::warn!("could not persist cli.token: {e}");
    }
    token
}

/// Require a valid session; returns `Some(response)` to short-circuit when
/// unauthorized, `None` when the request may proceed.
pub(crate) fn require_auth(state: &Shared, headers: &header::HeaderMap) -> Option<Response> {
    if authed_user(state, headers).is_some() {
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
    pub(crate) username: String,
    pub(crate) is_admin: bool,
    pub(crate) is_super: bool,
    /// System user to drop privileges to for terminal/file ops. `None` for the
    /// super-admin (operates as the panel's own uid, i.e. root).
    pub(crate) system_user: Option<String>,
    /// Whether this account has TOTP two-factor enabled.
    pub(crate) totp_enabled: bool,
}

impl Account {
    /// The account's role label ("admin" for sudo/owner, else "user").
    pub(crate) fn role(&self) -> &'static str {
        if self.is_admin {
            "admin"
        } else {
            "user"
        }
    }

    /// The domain `Principal` for this account (use-case actor).
    pub(crate) fn to_principal(&self) -> crate::core::identity::Principal {
        crate::core::identity::Principal {
            username: self.username.clone(),
            is_super: self.is_super,
            system_user: self.system_user.clone(),
        }
    }
}

/// Resolve an account name to a super-admin or panel-user view.
pub(crate) fn resolve_account(state: &Shared, username: &str) -> Option<Account> {
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
pub(crate) fn current_account(
    state: &Shared,
    headers: &header::HeaderMap,
) -> Result<Account, Response> {
    match authed_user(state, headers) {
        Some(user) => resolve_account(state, &user)
            .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized")),
        None => Err(api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized")),
    }
}

/// Require an authenticated **admin** (sudo) account for privileged endpoints.
#[allow(clippy::result_large_err)]
pub(crate) fn require_admin(
    state: &Shared,
    headers: &header::HeaderMap,
) -> Result<Account, Response> {
    let a = current_account(state, headers)?;
    if a.is_admin {
        Ok(a)
    } else {
        Err(api_err(StatusCode::FORBIDDEN, "auth.forbidden"))
    }
}

/// Require the **super-admin** (the bootstrap owner) for global settings.
#[allow(clippy::result_large_err)]
pub(crate) fn require_super(
    state: &Shared,
    headers: &header::HeaderMap,
) -> Result<Account, Response> {
    let a = current_account(state, headers)?;
    if a.is_super {
        Ok(a)
    } else {
        Err(api_err(StatusCode::FORBIDDEN, "auth.forbidden"))
    }
}

/// Best-effort current account name for audit records (empty when unresolved).
pub(crate) fn actor_name(state: &Shared, headers: &header::HeaderMap) -> String {
    current_account(state, headers)
        .map(|a| a.username)
        .unwrap_or_default()
}

/// The step-up token a high-risk request carries to prove a fresh re-auth,
/// read from the `X-DN7-Stepup` header (or, for WebSocket upgrades that can't
/// set headers, supplied by the caller from a query param).
pub(crate) fn stepup_token(headers: &header::HeaderMap) -> String {
    headers
        .get("x-dn7-stepup")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Require a fresh step-up (re-auth) grant for `account` **in addition** to the
/// session, for the highest-blast-radius operations (self-update, panel-access
/// changes, privileged-container exec). The token is single-use and bound to
/// the account, so a stolen session alone can't trigger these. Returns
/// `Some(response)` to short-circuit when the grant is missing/expired/foreign.
pub(crate) fn require_stepup(
    state: &Shared,
    headers: &header::HeaderMap,
    account: &str,
) -> Option<Response> {
    if state.auth.consume_stepup(&stepup_token(headers), account) {
        None
    } else {
        Some(api_err(StatusCode::FORBIDDEN, "auth.stepup_required"))
    }
}

#[cfg(test)]
mod control_token_gate_tests {
    use super::{ct_eq, is_direct_loopback};
    use axum::http::header::HeaderMap;

    #[test]
    fn direct_loopback_only_with_no_proxy_markers() {
        assert!(
            is_direct_loopback(&HeaderMap::new()),
            "a bare hit is direct"
        );
        // ANY of the edge's forwarding signals means NOT direct → CLI token rejected.
        for marker in ["x-dn7-forwarded", "x-forwarded-for", "x-real-ip"] {
            let mut h = HeaderMap::new();
            h.insert(marker, "1".parse().unwrap());
            assert!(
                !is_direct_loopback(&h),
                "{marker} present must read as edge-forwarded"
            );
        }
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }
}
