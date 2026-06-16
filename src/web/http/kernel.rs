//! Web-console HTTP kernel: shared state (WebState/Account), session/identity
//! guards, server bootstrap (spawn/serve/TLS), and the per-request actor lookup.
use super::*;

/// Web-console UI assets (css + js modules), embedded at compile time so the
/// binary stays self-contained. `index.html` is served separately (templated
/// with branding); everything else is served verbatim from here under `/ui/`.
pub(crate) static UI_ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/web/ui");

/// Shared web-console state.
pub struct WebState {
    pub(crate) auth: AuthState,
    pub(crate) settings: std::sync::Mutex<WebSettings>,
    /// Reused metrics collector (CPU% needs a persistent handle across reads).
    pub(crate) collector: Mutex<Collector>,
    /// Runtime config (used by the self-update endpoints).
    pub(crate) cfg: PanelConfig,
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

/// Start the web console in a background task (no-op when disabled). Returns
/// immediately; the server runs for the process lifetime.
pub fn spawn(cfg: PanelConfig) {
    let (s, _fresh) = settings::load_or_init(cfg.web_port);
    let port = s.port;
    let https = s.https;
    let public = s.public_access;
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
        if let Err(e) = serve(state, port, https, public).await {
            tracing::warn!("web console exited: {e}");
        }
    });
}

pub(crate) async fn serve(
    state: Shared,
    port: u16,
    https: bool,
    public: bool,
) -> anyhow::Result<()> {
    let app = crate::web::routes::build_router(state);
    // Public access binds all interfaces; otherwise loopback only, so the
    // console is reachable only via an nginx reverse proxy / SSH tunnel.
    let host = if public { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
    let addr = SocketAddr::from((host, port));
    bind_and_serve(app, addr, https).await
}

/// Bind and serve the app on `addr`, over self-signed HTTPS (rustls ring
/// provider — musl-static friendly) or plain HTTP. Runs until the process exits.
pub(crate) async fn bind_and_serve(
    app: Router,
    addr: SocketAddr,
    https: bool,
) -> anyhow::Result<()> {
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
pub(crate) fn ensure_panel_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
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
pub(crate) fn bearer(headers: &header::HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ")
        .or_else(|| v.strip_prefix("bearer "))
        .map(|s| s.trim().to_string())
}

/// Require a valid session; returns `Some(response)` to short-circuit when
/// unauthorized, `None` when the request may proceed.
pub(crate) fn require_auth(state: &Shared, headers: &header::HeaderMap) -> Option<Response> {
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
    let token = bearer(headers).unwrap_or_default();
    match state.auth.identity(&token) {
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
