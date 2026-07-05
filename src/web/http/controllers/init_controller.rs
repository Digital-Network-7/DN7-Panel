//! First-run **UI** init wizard endpoints (pre-auth). Reachable ONLY while the
//! panel is UNINITIALIZED and armed with an init token (the operator chose the
//! "UI custom" deploy mode), and only behind the init-token gate (see
//! `middleware::gate`). Two steps:
//!   1. the full config — access address + HTTPS mode + language/timezone +
//!      website HTTP/HTTPS ports + console port — which issues the console cert
//!      and reloads the edge;
//!   2. the admin account + password — which flips `initialized`, clears the init
//!      token, and stops these endpoints (+ the token gate) from serving.
use super::super::*;
use serde::Deserialize;

/// GET `/api/init/status` — whether setup is already complete (the SPA shows the
/// wizard while `initialized` is false, else the login screen).
pub(crate) async fn init_status(State(state): State<Shared>) -> Response {
    Json(json!({ "ok": true, "initialized": locked_initialized(&state) })).into_response()
}

#[derive(Deserialize)]
pub(crate) struct Step1Req {
    external_address: String,
    https_mode: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    timezone: String,
    #[serde(default)]
    website_http_port: u16,
    #[serde(default)]
    website_https_port: u16,
    #[serde(default)]
    console_port: u16,
}

/// POST `/api/init/step1` — set the full access config and issue the console cert
/// (self-signed or Let's Encrypt). For LE the issuance is awaited; the live edge
/// answers the ACME challenge on the port already serving this wizard, so the
/// wizard only advances on a real, verified cert. The edge is deliberately NOT
/// reloaded here. The listen ports are bound once at process start, so the chosen
/// ports and TLS take effect only at the step-2 restart. Reloading now would just
/// flip the live console route into SSL-redirect mode while no TLS listener is
/// bound, breaking the very wizard the operator is using.
pub(crate) async fn init_step1(State(state): State<Shared>, Json(req): Json<Step1Req>) -> Response {
    if locked_initialized(&state) {
        return init_err("已初始化 / already initialized");
    }
    let addr = req.external_address.trim().to_string();
    let mode = req.https_mode.trim();
    // Charset-gate the address: it becomes the edge host key AND is echoed back in
    // the UI, so reject anything that isn't a bare host/IP literal (no spaces, no
    // `<>"/` — blocks host-key injection and stored-XSS if it's ever reflected raw).
    if addr.is_empty() || addr.len() > 253 || !crate::core::website::valid_host_token(&addr) {
        return init_err("请填写有效的访问地址 / invalid address");
    }
    if !matches!(mode, "none" | "selfsigned" | "le") {
        return init_err("无效的 HTTPS 模式 / invalid HTTPS mode");
    }
    // Let's Encrypt needs a real domain — it can't validate a bare IP.
    if mode == "le" && addr.parse::<std::net::IpAddr>().is_ok() {
        return init_err("Let's Encrypt 需要域名 / Let's Encrypt needs a domain, not an IP");
    }
    // Ports (default the well-known ones when 0/unset). The two website ports must
    // differ; a console port matching a website port merges (the 0 sentinel).
    let http_port = if req.website_http_port == 0 {
        80
    } else {
        req.website_http_port
    };
    let https_port = if req.website_https_port == 0 {
        443
    } else {
        req.website_https_port
    };
    if http_port == https_port {
        return init_err(
            "网站 HTTP 与 HTTPS 端口不能相同 / website HTTP and HTTPS ports must differ",
        );
    }
    let console_port =
        if req.console_port == 0 || req.console_port == http_port || req.console_port == https_port
        {
            0
        } else {
            req.console_port
        };
    // Issue the cert FIRST (LE awaits + self-checks); only persist once it's on
    // disk, so a failed issuance leaves the chosen mode unset (the wizard retries).
    if let Err(e) = crate::infra::website::console_apply_tls(mode, &addr).await {
        return init_err(&format!("证书签发失败 / cert issuance failed: {e:#}"));
    }
    {
        let mut s = lock_settings(&state);
        s.external_address = addr;
        s.https_mode = mode.to_string();
        if matches!(req.language.as_str(), "zh-CN" | "zh-TW" | "en" | "ja") {
            s.language = req.language.clone();
        }
        if !req.timezone.trim().is_empty() && req.timezone.len() <= 64 {
            s.timezone = req.timezone.trim().to_string();
        }
        s.website_http_port = http_port;
        s.website_https_port = https_port;
        s.console_port = console_port;
        if let Err(e) = settings::save(&s) {
            return init_err(&format!("保存设置失败 / save failed: {e}"));
        }
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub(crate) struct Step2Req {
    username: String,
    pw_salt: String,
    pw_hash: String,
    pw_kdf: String,
}

/// POST `/api/init/step2` — set the admin account + password, mark the panel
/// initialized, clear the init token, then restart the panel so the chosen ports
/// and TLS bind and the console route drops its catch-all init fallback. The
/// restart is deferred (the supervisor respawns on exit), so this response reaches
/// the browser first; the wizard then points the operator at the final login URL.
pub(crate) async fn init_step2(State(state): State<Shared>, Json(req): Json<Step2Req>) -> Response {
    if locked_initialized(&state) {
        return init_err("已初始化 / already initialized");
    }
    // Step 1 must have completed first — it sets the external address (+ cert).
    if lock_settings(&state).external_address.trim().is_empty() {
        return init_err("请先完成第一步 / complete step 1 first");
    }
    let un = req.username.trim().to_string();
    if !crate::app::users::valid_username(&un) {
        return init_err("用户名格式不正确 / invalid username");
    }
    // The cleartext never reaches us — the client sends salt + verifier (sha256
    // hex) under a KDF scheme; we store Argon2id(verifier) at rest. Validate the
    // KDF string too (parity with every other credential path), so a tampered body
    // can't persist a too-weak client stretch like `s256:1`.
    if !crate::app::users::valid_pw_format(&req.pw_salt, &req.pw_hash)
        || !crate::app::users::valid_pw_kdf(&req.pw_kdf)
    {
        return init_err("密码格式不正确 / invalid password format");
    }
    let stored = match crate::infra::auth::hash_verifier(&req.pw_hash.to_lowercase()) {
        Some(h) => h,
        None => return init_err("密码哈希失败 / password hashing failed"),
    };
    {
        let mut s = lock_settings(&state);
        s.username = un;
        s.set_password_hashed(&req.pw_salt, &stored, &req.pw_kdf);
        s.initialized = true;
        s.init_token = String::new();
        if let Err(e) = settings::save(&s) {
            return init_err(&format!("保存设置失败 / save failed: {e}"));
        }
    }
    // Restart so a fresh process binds the configured ports + console TLS (the
    // listen ports are set-once at start) and serves the console at its named
    // address with the init fallback gone. Deferred exit → this response flushes.
    crate::platform::panel::request_restart();
    Json(json!({ "ok": true })).into_response()
}

/// Lock the shared settings, recovering a poisoned guard (the settings are only
/// mutated under this lock and aren't left half-written by a panic elsewhere).
fn lock_settings(state: &Shared) -> std::sync::MutexGuard<'_, WebSettings> {
    state
        .settings
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn locked_initialized(state: &Shared) -> bool {
    lock_settings(state).initialized
}

fn init_err(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "msg": msg })),
    )
        .into_response()
}
