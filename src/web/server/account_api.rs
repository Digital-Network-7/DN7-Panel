//! Account self-service: profile / password / 2FA (split from web/server.rs).
use super::*;

// ---------------------------------------------------------------------------
// Account self-service: profile / password / 2FA (any authenticated user)
// ---------------------------------------------------------------------------

/// GET /api/me — the caller's account: identity, role, profile, 2FA + whether a
/// first-run credential setup is still pending (super-admin only).
pub(crate) async fn me(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
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
        match crate::web::users::find(&a.username) {
            Some(u) => (u.full_name, u.nickname, u.avatar, u.totp_enabled, false),
            None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
        }
    };
    // Home directory to open the file manager at: the user's system home, or
    // the panel owner's home (root) for the super-admin.
    let home = match &a.system_user {
        Some(u) => crate::web::users::getpwnam(u)
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
pub(crate) struct ProfileReq {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    /// base64 data URL (size-limited).
    #[serde(default)]
    avatar: Option<String>,
}

pub(crate) fn clip(s: &str, max: usize) -> String {
    s.trim().chars().take(max).collect()
}

/// POST /api/profile — update the caller's own full name / nickname / avatar.
pub(crate) async fn put_profile(
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
        let res = crate::web::users::update(&a.username, |u| {
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
            let _ = crate::web::users::set_full_name(&a.username, &clip(f, 64)).await;
        }
    }
    Json(json!({ "ok": true })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct PasswordReq {
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
pub(crate) async fn put_password(
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
        crate::web::users::find(&a.username)
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
        let res = crate::web::users::update(&a.username, |u| {
            u.pw_salt = req.pw_salt.clone();
            u.pw_hash = hash.clone();
        });
        if let Err(e) = res {
            return Json(op_err_body(e)).into_response();
        }
        // Sync the OS password to the new panel password.
        if !req.password.is_empty() {
            if let Some(u) = &a.system_user {
                let _ = crate::web::users::set_system_password(u, &req.password).await;
            }
        }
    }
    audit::record(&a.username, "account.password", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

/// Read the caller's pending/active TOTP secret.
pub(crate) fn read_totp(state: &Shared, a: &Account) -> String {
    if a.is_super {
        state.settings.lock().unwrap().totp_secret.clone()
    } else {
        crate::web::users::find(&a.username)
            .map(|u| u.totp_secret)
            .unwrap_or_default()
    }
}

/// Persist the caller's TOTP secret + enabled flag.
pub(crate) fn write_totp(
    state: &Shared,
    a: &Account,
    secret: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    if a.is_super {
        let mut s = state.settings.lock().unwrap();
        s.totp_secret = secret.to_string();
        s.totp_enabled = enabled;
        let saved = s.clone();
        drop(s);
        settings::save(&saved)
    } else {
        crate::web::users::update(&a.username, |u| {
            u.totp_secret = secret.to_string();
            u.totp_enabled = enabled;
        })
    }
}

/// POST /api/2fa/setup — generate a fresh (pending) TOTP secret + QR. 2FA is not
/// enabled until the user verifies a live code via /api/2fa/enable.
pub(crate) async fn twofa_setup(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = crate::web::totp::gen_secret();
    let issuer = branding::load().panel_name;
    let uri = crate::web::totp::provisioning_uri(&issuer, &a.username, &secret);
    let qr = crate::web::totp::qr_svg(&uri);
    if let Err(e) = write_totp(&state, &a, &secret, false) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    Json(json!({ "ok": true, "data": { "secret": secret, "uri": uri, "qr_svg": qr } }))
        .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct CodeReq {
    #[serde(default)]
    code: String,
}

/// POST /api/2fa/enable — bind 2FA after verifying a live code.
pub(crate) async fn twofa_enable(
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
    if !crate::web::totp::verify(&secret, &req.code) {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_totp");
    }
    if let Err(e) = write_totp(&state, &a, &secret, true) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&a.username, "account.2fa_enable", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

/// POST /api/2fa/disable — verify a current code, then turn 2FA off.
pub(crate) async fn twofa_disable(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CodeReq>,
) -> Response {
    let a = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let secret = read_totp(&state, &a);
    if !secret.is_empty() && !crate::web::totp::verify(&secret, &req.code) {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_totp");
    }
    if let Err(e) = write_totp(&state, &a, "", false) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    audit::record(&a.username, "account.2fa_disable", &a.username, true, "");
    Json(json!({ "ok": true })).into_response()
}
