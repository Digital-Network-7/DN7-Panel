//! Settings API handlers (split from web/server.rs).
use super::*;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub(crate) async fn get_settings(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
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
pub(crate) struct SettingsReq {
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

pub(crate) async fn put_settings(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let (saved, needs_restart, new_ttl) = {
        let mut s = state.settings.lock().unwrap();
        match apply_settings_update(&mut s, req) {
            Ok((nr, ttl)) => (s.clone(), nr, ttl),
            Err(resp) => return resp,
        }
    };
    // Session TTL is applied live to the auth layer (kept out of the settings
    // lock). Only when the request actually carried a new timeout.
    if let Some(secs) = new_ttl {
        state.auth.set_ttl_secs(secs);
    }
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

/// Apply a validated settings update onto `s` in place. Returns
/// `(needs_restart, new_session_ttl_secs)` — the TTL is `Some` only when the
/// request changed the session timeout (the caller applies it to the auth
/// layer). On any invalid field, returns the error `Response` to send.
// The `Err` is an axum `Response` (intentionally large); boxing it would only
// add noise to every early-return site in this internal helper.
#[allow(clippy::result_large_err)]
fn apply_settings_update(
    s: &mut WebSettings,
    req: SettingsReq,
) -> Result<(bool, Option<u64>), Response> {
    let mut needs_restart = false;
    let mut new_ttl = None;
    if let Some(p) = req.port {
        if !(1..=65535).contains(&p) {
            return Err(api_err(StatusCode::BAD_REQUEST, "settings.port_range"));
        }
        if p != s.port {
            s.port = p;
            needs_restart = true;
        }
    }
    apply_password_change(s, &req)?;
    if let Some(un) = req.username {
        let un = un.trim();
        if un.len() < 2
            || un.len() > 32
            || !un
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(api_err(StatusCode::BAD_REQUEST, "settings.username_format"));
        }
        // "admin" is the default account name and is not allowed as a chosen
        // account (the operator must pick their own).
        if un.eq_ignore_ascii_case("admin") {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "settings.username_reserved",
            ));
        }
        s.username = un.to_string();
    }
    // Safe-entry path — applied live (the gate reads it per request).
    if let Some(ep) = &req.entry_path {
        match settings::normalize_entry(ep) {
            Some(norm) => s.entry_path = norm,
            None => return Err(api_err(StatusCode::BAD_REQUEST, "settings.bad_entry")),
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
            return Err(api_err(StatusCode::BAD_REQUEST, "settings.timeout_range"));
        }
        s.session_timeout = t;
        new_ttl = Some((t.max(1) as u64) * 60);
    }
    // Authorized IP allow list — validated; empty = allow any address.
    if let Some(ips) = &req.allow_ips {
        match settings::normalize_allow_ips(ips) {
            Some(list) => s.allow_ips = list,
            None => return Err(api_err(StatusCode::BAD_REQUEST, "settings.bad_allow_ip")),
        }
    }
    Ok((needs_restart, new_ttl))
}

/// Apply a password change: a client-computed salt + hash (plaintext never
/// crosses the wire). While still on the auto-generated default, require proof
/// the new password actually differs from it. No-op when neither field is set.
#[allow(clippy::result_large_err)]
fn apply_password_change(s: &mut WebSettings, req: &SettingsReq) -> Result<(), Response> {
    if req.pw_salt.is_none() && req.pw_hash.is_none() {
        return Ok(());
    }
    let was_default = s.pw_default;
    let cur_hash = s.pw_hash.clone();
    let salt = req.pw_salt.clone().unwrap_or_default();
    let hash = req.pw_hash.clone().unwrap_or_default();
    let salt_ok = salt.len() == 32 && salt.bytes().all(|b| b.is_ascii_hexdigit());
    let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
    if !salt_ok || !hash_ok {
        return Err(api_err(StatusCode::BAD_REQUEST, "settings.pw_format"));
    }
    // pw_check = sha256(current salt ":" new password) must NOT equal the stored
    // default hash, proving the new password differs from the default.
    if was_default {
        let chk = req.pw_check.clone().unwrap_or_default().to_lowercase();
        if chk.is_empty() || chk == cur_hash {
            return Err(api_err(StatusCode::BAD_REQUEST, "settings.pw_is_default"));
        }
    }
    s.set_password_hashed(&salt, &hash.to_lowercase());
    Ok(())
}
