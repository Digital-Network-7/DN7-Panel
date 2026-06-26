//! First-run init wizard endpoints (pre-auth). These are reachable only while
//! the panel is UNINITIALIZED and behind the init-token gate (see `middleware`).
//! Two steps:
//!   1. external access address + HTTPS mode (issues the console cert),
//!   2. the admin account + password — which flips `initialized` and clears the
//!      init token, after which the wizard + these endpoints stop being served.
use super::super::*;
use serde::Deserialize;

/// GET `/api/init/status` — what the wizard needs to render. The address default
/// is decided client-side (`location.hostname`), so this only reports whether
/// setup is already complete (the SPA shows login instead of the wizard then).
pub(crate) async fn init_status(State(state): State<Shared>) -> Response {
    Json(json!({ "ok": true, "initialized": locked_initialized(&state) })).into_response()
}

#[derive(Deserialize)]
pub(crate) struct Step1Req {
    external_address: String,
    https_mode: String,
}

/// POST `/api/init/step1` — set the external access address + HTTPS mode, issue
/// the console cert (self-signed or Let's Encrypt), and reload the edge. For LE
/// the issuance is awaited, so the wizard only advances on a real, verified cert.
pub(crate) async fn init_step1(State(state): State<Shared>, Json(req): Json<Step1Req>) -> Response {
    if locked_initialized(&state) {
        return init_err("已初始化");
    }
    let addr = req.external_address.trim().to_string();
    let mode = req.https_mode.trim();
    if addr.is_empty() || addr.len() > 253 {
        return init_err("请填写有效的访问地址");
    }
    if !matches!(mode, "none" | "selfsigned" | "le") {
        return init_err("无效的 HTTPS 模式");
    }
    // Let's Encrypt needs a real domain — it can't validate a bare IP.
    if mode == "le" && addr.parse::<std::net::IpAddr>().is_ok() {
        return init_err("Let's Encrypt 需要域名，请改用域名或选择自签名/不启用");
    }
    // Issue the cert FIRST (LE awaits + self-checks); only persist once it's on
    // disk, so a failed issuance leaves the chosen mode unset (the wizard retries).
    if let Err(e) = crate::infra::website::console_apply_tls(mode, &addr).await {
        return init_err(&format!("证书签发失败：{e:#}"));
    }
    {
        let mut s = lock_settings(&state);
        s.external_address = addr;
        s.https_mode = mode.to_string();
        if let Err(e) = settings::save(&s) {
            return init_err(&format!("保存设置失败：{e}"));
        }
    }
    if let Err(e) = crate::infra::website::edge_reload().await {
        return init_err(&format!("edge 重载失败：{e:#}"));
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
/// initialized, and clear the init token. After this the init gate stops
/// requiring the token and the console route drops its catch-all fallback.
pub(crate) async fn init_step2(State(state): State<Shared>, Json(req): Json<Step2Req>) -> Response {
    if locked_initialized(&state) {
        return init_err("已初始化");
    }
    let un = req.username.trim().to_string();
    if !crate::app::users::valid_username(&un) {
        return init_err("用户名格式不正确（小写字母/数字/_/-，1-32 位，且不能为 root）");
    }
    // The cleartext never reaches us — the client sends salt + verifier (sha256
    // hex) under a KDF scheme; we store Argon2id(verifier) at rest.
    if !crate::app::users::valid_pw_format(&req.pw_salt, &req.pw_hash) {
        return init_err("密码格式不正确");
    }
    let stored = match crate::infra::auth::hash_verifier(&req.pw_hash.to_lowercase()) {
        Some(h) => h,
        None => return init_err("密码哈希失败"),
    };
    {
        let mut s = lock_settings(&state);
        s.username = un;
        s.set_password_hashed(&req.pw_salt, &stored, &req.pw_kdf);
        s.initialized = true;
        s.init_token = String::new();
        if let Err(e) = settings::save(&s) {
            return init_err(&format!("保存设置失败：{e}"));
        }
    }
    if let Err(e) = crate::infra::website::edge_reload().await {
        return init_err(&format!("edge 重载失败：{e:#}"));
    }
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
