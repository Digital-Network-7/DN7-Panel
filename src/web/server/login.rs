//! Login / logout handlers (split from web/server.rs).
use super::*;

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct LoginReq {
    #[serde(default)]
    username: String,
    /// Challenge-response: the nonce from `/api/login/challenge` and the proof
    /// `sha256_hex(nonce ":" verifier)`, where `verifier = sha256_hex(salt ":"
    /// password)` (the value the server stores). The cleartext password never
    /// crosses the wire, and the server holds only the irreversible verifier.
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    proof: String,
    /// Optional TOTP code (required when the account has 2FA enabled).
    #[serde(default)]
    code: String,
}

/// GET /api/login/challenge — PUBLIC. Mint a one-time login nonce and return
/// the per-install password salt so the client can compute the verifier.
pub(crate) async fn login_challenge(
    State(state): State<Shared>,
    Query(q): Query<LoginChallengeQuery>,
) -> Response {
    let nonce = state.auth.issue_challenge();
    // Return the salt for the requested account so the client can compute the
    // verifier. Falls back to the super-admin salt (so probing a name doesn't
    // reveal whether it exists — a random-looking salt is always returned).
    let salt = {
        let su = state.settings.lock().unwrap();
        if q.username.is_empty() || q.username == su.username {
            su.pw_salt.clone()
        } else if let Some(u) = crate::web::users::find(&q.username) {
            u.pw_salt
        } else {
            su.pw_salt.clone()
        }
    };
    Json(json!({ "nonce": nonce, "salt": salt })).into_response()
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginChallengeQuery {
    #[serde(default)]
    username: String,
}

pub(crate) async fn login(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let source = peer.ip().to_string();
    if !state.auth.login_allowed(&source) {
        return api_err(StatusCode::TOO_MANY_REQUESTS, "auth.rate_limited");
    }
    // Resolve the account: the super-admin (web.json) or a panel user.
    let (exp_hash, totp_secret, totp_enabled, must_setup) = {
        let su = state.settings.lock().unwrap();
        if req.username == su.username {
            (
                su.verifier().to_string(),
                su.totp_secret.clone(),
                su.totp_enabled,
                su.pw_default || su.username.eq_ignore_ascii_case("admin"),
            )
        } else if let Some(u) = crate::web::users::find(&req.username) {
            (
                u.pw_hash.clone(),
                u.totp_secret.clone(),
                u.totp_enabled,
                false,
            )
        } else {
            (String::new(), String::new(), false, false)
        }
    };
    let pw_ok = !exp_hash.is_empty()
        && state.auth.consume_challenge(&req.nonce)
        && proof_matches(&req.nonce, &exp_hash, &req.proof);
    if !pw_ok {
        state.auth.record_failure(&source);
        audit::record_ip(
            &req.username,
            "auth.login",
            "",
            false,
            "bad_credentials",
            &source,
        );
        return api_err(StatusCode::UNAUTHORIZED, "auth.bad_credentials");
    }
    // Second factor (TOTP) when enabled for this account.
    if totp_enabled {
        if req.code.trim().is_empty() {
            // Password verified, but a code is required — tell the client to ask.
            return Json(json!({ "ok": false, "need_totp": true })).into_response();
        }
        if !crate::web::totp::verify(&totp_secret, &req.code) {
            state.auth.record_failure(&source);
            audit::record_ip(&req.username, "auth.login", "", false, "bad_totp", &source);
            return api_err(StatusCode::UNAUTHORIZED, "auth.bad_totp");
        }
    }
    state.auth.clear_failures(&source);
    let token = state.auth.issue(&req.username);
    audit::record_ip(&req.username, "auth.login", "", true, "", &source);
    Json(json!({ "ok": true, "token": token, "must_setup": must_setup })).into_response()
}

pub(crate) async fn logout(State(state): State<Shared>, headers: header::HeaderMap) -> Response {
    let who = current_account(&state, &headers)
        .map(|a| a.username)
        .unwrap_or_default();
    if let Some(t) = bearer(&headers) {
        state.auth.revoke(&t);
    }
    if !who.is_empty() {
        audit::record(&who, "auth.logout", "", true, "");
    }
    Json(json!({ "ok": true })).into_response()
}

/// POST /api/ticket — mint a one-time, 30-second ticket for a single WebSocket
/// upgrade or file download. Requires a valid bearer session; the ticket (not
/// the long-lived token) is what goes in the URL, so a leaked URL exposes only
/// a short-lived, single-use credential.
pub(crate) async fn mint_ticket(
    State(state): State<Shared>,
    headers: header::HeaderMap,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    Json(json!({ "ok": true, "data": { "ticket": state.auth.issue_ticket(&acct.username) } }))
        .into_response()
}
