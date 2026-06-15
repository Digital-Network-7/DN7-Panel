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
    Json(json!({ "ok": true, "data": me_view(&state, &a) })).into_response()
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
            let _ = crate::web::system_account::set_full_name(&a.username, &clip(f, 64)).await;
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
    if !crate::web::users::valid_pw_format(&req.pw_salt, &req.pw_hash) {
        return api_err(StatusCode::BAD_REQUEST, "settings.pw_format");
    }
    if let Err(r) = verify_current_password(&state, &a, &req.old_verifier) {
        return r;
    }
    if let Err(r) = save_new_password(&state, &a, &req.pw_salt, &req.pw_hash, &req.password).await {
        return r;
    }
    // Invalidate any other (possibly leaked) sessions/tickets for this account,
    // keeping the caller's current session, then audit.
    after_credential_change(&state, &a.username, bearer(&headers).as_deref(), "account.password");
    Json(json!({ "ok": true })).into_response()
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
    after_credential_change(
        &state,
        &a.username,
        bearer(&headers).as_deref(),
        "account.2fa_enable",
    );
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
    after_credential_change(
        &state,
        &a.username,
        bearer(&headers).as_deref(),
        "account.2fa_disable",
    );
    Json(json!({ "ok": true })).into_response()
}
