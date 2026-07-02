//! Settings API handlers (split from web/server.rs).
use super::super::*;

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
    let s = state.settings_snapshot();
    // The password is intentionally NOT returned: a session should never be able
    // to read back the reusable console password. The form sends a new password
    // only when the operator chooses to change it.
    Json(json!({
        "ok": true,
        "data": { "username": s.username, "pw_default": s.pw_default,
                  "session_timeout": s.session_timeout, "allow_ips": s.allow_ips,
                  "trusted_proxies": s.trusted_proxies,
                  "must_setup": s.pw_default || s.username.eq_ignore_ascii_case("admin") }
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct SettingsReq {
    #[serde(default)]
    username: Option<String>,
    /// Password change: client-computed `salt` + `sha256_hex(salt ":" password)`
    /// so the plaintext never crosses the wire. Both must be present to change.
    #[serde(default)]
    pw_salt: Option<String>,
    #[serde(default)]
    pw_hash: Option<String>,
    /// KDF scheme used to compute `pw_hash` (e.g. "s256:30000"); stored so login
    /// recomputes the same verifier. Empty = legacy single hash.
    #[serde(default)]
    pw_kdf: Option<String>,
    /// `derive(current_salt, new_password, current_kdf)` — lets the server verify
    /// the new password differs from the current (default) one without ever
    /// seeing the plaintext. Required when changing the password off the default.
    #[serde(default)]
    pw_check: Option<String>,
    /// Session inactivity timeout in minutes. Applied live.
    #[serde(default)]
    session_timeout: Option<u32>,
    /// Authorized client IPs / CIDRs (one per entry). Empty = allow any.
    #[serde(default)]
    allow_ips: Option<Vec<String>>,
    /// Trusted front-proxy IPs / CIDRs. Empty = trust only the direct peer.
    #[serde(default)]
    trusted_proxies: Option<Vec<String>>,
}

pub(crate) async fn put_settings(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<SettingsReq>,
) -> Response {
    // Console settings include the panel's network exposure (public-access
    // bind, port, HTTPS, entry path, authorized IPs) and the owner credentials
    // — super only, plus a fresh step-up re-auth so a stolen session can't
    // quietly widen access or change the password.
    let acct = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(r) = require_stepup(&state, &headers, &acct.username) {
        return r;
    }
    let actor = acct.username;
    let (saved, outcome) = {
        let mut s = state.settings_guard();
        match apply_settings_update(&mut s, req) {
            Ok(o) => (s.clone(), o),
            Err(resp) => return resp,
        }
    };
    // Session TTL is applied live to the auth layer (kept out of the settings
    // lock). Only when the request actually carried a new timeout.
    if let Some(secs) = outcome.new_ttl {
        state.auth.set_ttl_secs(secs);
    }
    if let Err(e) = settings::save(&saved) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    // A password change must invalidate the account's other (possibly leaked)
    // sessions/tickets — the same policy the account password flow applies —
    // keeping the caller's current session alive.
    if outcome.password_changed {
        state.auth.revoke_user(&actor, bearer(&headers).as_deref());
    }
    audit::record(&actor, "settings.update", "", true, "");
    Json(json!({ "ok": true, "needs_restart": outcome.needs_restart })).into_response()
}

/// What the caller must still do after a settings update is applied in place.
struct SettingsOutcome {
    /// A field that needs a listener rebind (port / https) changed.
    needs_restart: bool,
    /// New session-timeout in seconds, when the request changed it.
    new_ttl: Option<u64>,
    /// The console password was (re)set in this request.
    password_changed: bool,
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
) -> Result<SettingsOutcome, Response> {
    // The console binds a fixed loopback port behind the edge now, and HTTPS /
    // public exposure are owned by the edge + the init wizard — so a settings
    // change no longer rebinds a listener: nothing here needs a restart.
    let needs_restart = false;
    let mut new_ttl = None;
    let password_changed = apply_password_change(s, &req)?;
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
    // Trusted front-proxy list — same IP/CIDR validation; empty = trust none.
    if let Some(px) = &req.trusted_proxies {
        match settings::normalize_allow_ips(px) {
            Some(list) => s.trusted_proxies = list,
            None => return Err(api_err(StatusCode::BAD_REQUEST, "settings.bad_allow_ip")),
        }
    }
    Ok(SettingsOutcome {
        needs_restart,
        new_ttl,
        password_changed,
    })
}

/// Apply a password change: a client-computed salt + hash (plaintext never
/// crosses the wire). While still on the auto-generated default, require proof
/// the new password actually differs from it. Returns whether the password was
/// changed; no-op (false) when neither field is set.
#[allow(clippy::result_large_err)]
fn apply_password_change(s: &mut WebSettings, req: &SettingsReq) -> Result<bool, Response> {
    if req.pw_salt.is_none() && req.pw_hash.is_none() {
        return Ok(false);
    }
    let was_default = s.pw_default;
    let cur_hash = s.pw_hash.clone();
    let salt = req.pw_salt.clone().unwrap_or_default();
    let hash = req.pw_hash.clone().unwrap_or_default();
    if !crate::app::users::valid_pw_format(&salt, &hash) {
        return Err(map_core_err(crate::core::Error::PasswordMalformed));
    }
    // pw_check is the new password's verifier under the CURRENT salt+KDF; the new
    // password must differ from the default, i.e. it must NOT validate against the
    // stored default credential (works whether that's a legacy raw verifier or an
    // Argon2id hash).
    if was_default {
        let chk = req.pw_check.clone().unwrap_or_default();
        if chk.is_empty() || crate::infra::auth::verify_verifier(&cur_hash, &chk).ok {
            return Err(map_core_err(crate::core::Error::PasswordIsDefault));
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
    s.set_password_hashed(&salt, &stored, &kdf);
    Ok(true)
}
