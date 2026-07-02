//! User management API (admin only) (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// User management (admin only): panel users backed by system accounts
// ---------------------------------------------------------------------------

pub(crate) async fn users_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let mut list = Vec::new();
    {
        let s = state.settings_guard();
        list.push(json!({
            "username": s.username, "role": "admin", "is_super": true,
            "full_name": s.full_name, "nickname": s.nickname, "uid": s.owner_uid, "totp_enabled": s.totp_enabled,
        }));
    }
    for u in crate::app::users::load() {
        list.push(json!({
            "username": u.username, "role": u.role, "is_super": false,
            "full_name": u.full_name, "nickname": u.nickname, "uid": u.uid, "totp_enabled": u.totp_enabled,
        }));
    }
    Json(json!({ "ok": true, "data": { "users": list } })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateUserReq {
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
    /// KDF scheme used to compute `pw_hash` (e.g. "s256:30000"); empty = legacy.
    #[serde(default)]
    pw_kdf: String,
    /// Plaintext (local console) — used to set the matching OS password.
    #[serde(default)]
    password: String,
}

pub(crate) async fn users_create(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if !matches!(req.role.as_str(), "admin" | "user") {
        return map_core_err(crate::core::Error::RoleInvalid);
    }
    // May only create an account strictly lower in privilege than oneself
    // (owner → admin/user; admin → user only).
    if !accounts::can_manage(account_level(&actor), role_level(&req.role)) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // Can't collide with the super-admin's login name.
    if req.username
        == state
            .settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .username
    {
        return map_core_err(crate::core::Error::UserExists);
    }
    match crate::app::users::create(&crate::app::users::NewUser {
        username: &req.username,
        role: &req.role,
        full_name: req.full_name.trim(),
        pw_salt: &req.pw_salt,
        pw_hash: &req.pw_hash,
        pw_kdf: &req.pw_kdf,
        password: &req.password,
    })
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
                &format!("{e:?}"),
            );
            map_core_err(e)
        }
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct UpdateUserReq {
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
    /// KDF scheme used to compute `pw_hash` (e.g. "s256:30000"); empty = legacy.
    #[serde(default)]
    pw_kdf: Option<String>,
    /// Plaintext (local console) — used to set the matching OS password.
    #[serde(default)]
    password: Option<String>,
}

/// POST /api/users/update — an owner/admin edits a **lower-privilege** panel
/// user's profile, role and/or password.
pub(crate) async fn users_update(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<UpdateUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let actor_lvl = account_level(&actor);
    let target = match crate::app::users::find(&req.username) {
        Some(t) => t,
        None => return map_core_err(crate::core::Error::UserNotFound),
    };
    // Only manage accounts strictly below your own privilege.
    if !accounts::can_manage(actor_lvl, role_level(&target.role)) {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    // Validate an optional role change (the new role must be strictly below the
    // actor). The OS sudo-group change is applied AFTER the persist below.
    if let Err(r) = validate_role_change(&req, actor_lvl) {
        return r;
    }
    // Optional password reset (admin-set; no old password needed).
    let pw = match parse_pw_update(&req) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let res = crate::app::users::update(&req.username, |u| {
        if let Some(f) = &req.full_name {
            u.full_name = f.trim().chars().take(64).collect();
        }
        if let Some(n) = &req.nickname {
            u.nickname = n.trim().chars().take(40).collect();
        }
        if let Some(r) = &req.role {
            u.role = r.clone();
        }
        if let Some((salt, hash, kdf)) = &pw {
            u.pw_salt = salt.clone();
            u.pw_hash = hash.clone();
            u.pw_kdf = kdf.clone();
        }
    });
    if let Err(e) = res {
        return map_core_err(e);
    }
    // Apply the OS sudo-group change AFTER persisting the panel role (the store
    // is the source of truth) — a persist failure must not leave the OS sudo
    // group and the stored role divergent.
    if let Some(role) = &req.role {
        if *role != target.role {
            if let Err(e) = crate::infra::system::set_sudo(&req.username, role == "admin").await {
                return Json(op_err_body(e)).into_response();
            }
        }
    }
    if let Some(f) = &req.full_name {
        let _ = crate::infra::system::set_full_name(&req.username, f.trim()).await;
    }
    // Sync the OS password to the new panel password (system user).
    if pw.is_some() {
        // An admin password reset must immediately cut off the target's existing
        // sessions/tickets (a takeover survives a reset otherwise). The panel
        // verifier is already persisted, so revoke BEFORE the OS sync — that way
        // a failed OS sync (early-return below) still can't leave a live session.
        state.auth.revoke_user(&req.username, None);
        if let Some(p) = &req.password {
            if !p.is_empty() {
                // Surface a failed OS password sync instead of swallowing it: the
                // panel verifier is already persisted, so a silent failure would
                // leave the OS account on the OLD password and report success.
                if let Err(e) = crate::infra::system::set_system_password(&req.username, p).await {
                    return Json(op_err_body(e)).into_response();
                }
            }
        }
    }
    audit::record(&actor.username, "user.update", &req.username, true, "");
    Json(json!({ "ok": true })).into_response()
}

/// Validate an optional role change: the role is well-formed and strictly below
/// the actor's level. Pure check — the OS sudo-group side effect is applied by
/// the caller after the panel role is persisted.
#[allow(clippy::result_large_err)]
fn validate_role_change(req: &UpdateUserReq, actor_lvl: u8) -> Result<(), Response> {
    let Some(role) = &req.role else { return Ok(()) };
    if !matches!(role.as_str(), "admin" | "user") {
        return Err(map_core_err(crate::core::Error::RoleInvalid));
    }
    if !accounts::can_manage(actor_lvl, role_level(role)) {
        return Err(api_err(StatusCode::FORBIDDEN, "auth.forbidden"));
    }
    Ok(())
}

/// Parse + validate an optional admin password reset (client-computed salt +
/// hash). Returns `Some((salt, hash_lowercased))`, `None` when absent, or the
/// error `Response`.
#[allow(clippy::result_large_err)]
fn parse_pw_update(req: &UpdateUserReq) -> Result<Option<(String, String, String)>, Response> {
    if req.pw_salt.is_none() && req.pw_hash.is_none() {
        return Ok(None);
    }
    let salt = req.pw_salt.clone().unwrap_or_default();
    let hash = req.pw_hash.clone().unwrap_or_default();
    if !crate::app::users::valid_pw_format(&salt, &hash) {
        return Err(map_core_err(crate::core::Error::PasswordMalformed));
    }
    // The plaintext is synced to the OS password via `chpasswd`; reject control
    // chars that could forge an extra record (see identity::valid_os_secret).
    if let Some(p) = &req.password {
        if !crate::app::users::valid_os_secret(p) {
            return Err(map_core_err(crate::core::Error::PasswordMalformed));
        }
    }
    let kdf = req.pw_kdf.clone().unwrap_or_default();
    if !crate::app::users::valid_pw_kdf(&kdf) {
        return Err(map_core_err(crate::core::Error::PasswordMalformed));
    }
    // Store Argon2id(verifier), not the raw verifier, so a leaked file can't be
    // replayed as a login.
    let stored = crate::infra::auth::hash_verifier(&hash.to_lowercase())
        .ok_or_else(|| map_core_err(crate::core::Error::Persist("密码哈希失败".into())))?;
    Ok(Some((salt, stored, kdf)))
}

#[derive(serde::Deserialize)]
pub(crate) struct DelUserReq {
    #[serde(default)]
    username: String,
}

pub(crate) async fn users_delete(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<DelUserReq>,
) -> Response {
    let actor = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    // Only delete accounts strictly below your own privilege.
    if let Some(t) = crate::app::users::find(&req.username) {
        if !accounts::can_manage(account_level(&actor), role_level(&t.role)) {
            return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
        }
    }
    match crate::app::users::delete(&req.username).await {
        Ok(_) => {
            state.auth.revoke_user(&req.username, None);
            audit::record(&actor.username, "user.delete", &req.username, true, "");
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            audit::record(
                &actor.username,
                "user.delete",
                &req.username,
                false,
                &format!("{e:?}"),
            );
            map_core_err(e)
        }
    }
}
