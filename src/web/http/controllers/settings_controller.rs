//! Settings API handlers (split from web/server.rs).
use super::super::*;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub(crate) async fn get_settings(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: header::HeaderMap,
) -> Response {
    if let Err(r) = require_super(&state, &headers) {
        return r;
    }
    let s = state.settings_snapshot();
    // The requester's IP exactly as the panel attributes it (direct peer, or the
    // forwarded client behind a trusted proxy) — the Authorized-IPs editor shows
    // it so an operator can tell whether a new allow list still covers themselves
    // before saving a lockout.
    let client_ip = client_ip(peer.ip(), &headers, &SecurityPolicy::new(&s)).to_string();
    // The password is intentionally NOT returned: a session should never be able
    // to read back the reusable console password. The form sends a new password
    // only when the operator chooses to change it.
    Json(json!({
        "ok": true,
        "data": { "username": s.username, "pw_default": s.pw_default,
                  "session_timeout": s.session_timeout, "allow_ips": s.allow_ips,
                  "trusted_proxies": s.trusted_proxies, "client_ip": client_ip,
                  "entry_path": s.entry_path,
                  // Console access config (edited in the Access section, applied by
                  // a restart) — surfaced so the form can show the current values.
                  "external_address": s.external_address, "https_mode": s.https_mode,
                  "website_http_port": s.website_http_port, "website_https_port": s.website_https_port,
                  "console_port": s.console_port,
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
    /// Security entry path (obscurity front door). Applied LIVE (the gate reads it
    /// each request). Empty = disable; a bare segment of letters/digits/`-`/`_`.
    #[serde(default)]
    entry_path: Option<String>,
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

#[derive(serde::Deserialize)]
pub(crate) struct ConsoleAccessReq {
    external_address: String,
    https_mode: String,
    #[serde(default)]
    website_http_port: u16,
    #[serde(default)]
    website_https_port: u16,
    #[serde(default)]
    console_port: u16,
}

/// POST /api/console/access — change the console's external address + HTTPS mode +
/// serving ports, then RESTART the panel so the new listeners/TLS bind (they're
/// set-once at process start). Super-admin + a fresh step-up (host-level
/// exposure). Returns the new login URL so the UI can point the operator at it.
pub(crate) async fn put_console_access(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<ConsoleAccessReq>,
) -> Response {
    let acct = match require_super(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(r) = require_stepup(&state, &headers, &acct.username) {
        return r;
    }
    let addr = req.external_address.trim().to_string();
    let mode = req.https_mode.trim();
    if addr.is_empty() || addr.len() > 253 || !crate::core::website::valid_host_token(&addr) {
        return api_err(StatusCode::BAD_REQUEST, "settings.bad_address");
    }
    if !matches!(mode, "none" | "selfsigned" | "le") {
        return api_err(StatusCode::BAD_REQUEST, "settings.bad_https_mode");
    }
    if mode == "le" && addr.parse::<std::net::IpAddr>().is_ok() {
        return api_err(StatusCode::BAD_REQUEST, "settings.le_needs_domain");
    }
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
        return api_err(StatusCode::BAD_REQUEST, "settings.ports_same");
    }
    let console_port =
        if req.console_port == 0 || req.console_port == http_port || req.console_port == https_port
        {
            0
        } else {
            req.console_port
        };
    // Issue the cert first (selfsigned/none apply immediately; LE awaits). Only
    // persist once it's on disk, so a failed issuance leaves the mode unchanged.
    if let Err(e) = crate::infra::website::console_apply_tls(mode, &addr).await {
        return api_err_detail(StatusCode::BAD_REQUEST, "settings.cert_failed", e);
    }
    let saved = {
        let mut s = state.settings_guard();
        s.external_address = addr.clone();
        s.https_mode = mode.to_string();
        s.website_http_port = http_port;
        s.website_https_port = https_port;
        s.console_port = console_port;
        s.clone()
    };
    if let Err(e) = settings::save(&saved) {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed", e);
    }
    if let Err(e) = crate::infra::website::edge_reload().await {
        return api_err_detail(StatusCode::INTERNAL_SERVER_ERROR, "settings.edge_failed", e);
    }
    audit::record(&acct.username, "settings.console_access", &addr, true, "");
    // Restart so the chosen ports + console TLS bind (set-once at start). Deferred
    // exit → this response flushes; the UI shows the new URL then waits for revive.
    crate::platform::panel::request_restart();
    let scheme = if mode == "none" { "http" } else { "https" };
    let port = if console_port != 0 {
        console_port
    } else if mode == "none" {
        http_port
    } else {
        https_port
    };
    let dflt: u16 = if scheme == "https" { 443 } else { 80 };
    let host = if addr.contains(':') && !addr.starts_with('[') {
        format!("[{addr}]")
    } else {
        addr
    };
    let authority = if port == dflt {
        host
    } else {
        format!("{host}:{port}")
    };
    let path = if saved.entry_path.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", saved.entry_path)
    };
    Json(json!({ "ok": true, "data": { "url": format!("{scheme}://{authority}{path}"), "restarting": true } }))
        .into_response()
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
    // Security entry path — applied LIVE (the gate reads settings each request, so
    // no restart). Empty disables the gate; otherwise a validated bare segment.
    if let Some(ep) = &req.entry_path {
        match settings::normalize_entry_path(ep) {
            Some(p) => s.entry_path = p,
            None => return Err(api_err(StatusCode::BAD_REQUEST, "settings.bad_entry_path")),
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
