//! Login / logout handlers (split from web/server.rs).
use super::super::*;

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
    // verifier. Unknown accounts get a stable per-username decoy salt (below)
    // so probing a name never reveals whether it exists.
    // The client needs the salt AND the KDF scheme to recompute the same verifier
    // the password was stored under, so we return both.
    let (salt, kdf) = {
        let su = state.settings_guard();
        if q.username.is_empty() || q.username == su.username {
            (su.pw_salt.clone(), su.pw_kdf.clone())
        } else if let Some(u) = crate::app::users::find(&q.username) {
            (u.pw_salt, u.pw_kdf)
        } else {
            // Unknown account: return a deterministic, per-username pseudo-salt
            // derived from the install salt, and mirror the install account's KDF
            // — so a probe can't tell an existing account (its real salt/KDF) from
            // a missing one (this stable decoy), nor whether it's been migrated.
            (decoy_salt(&su.pw_salt, &q.username), su.pw_kdf.clone())
        }
    };
    Json(json!({ "nonce": nonce, "salt": salt, "kdf": kdf })).into_response()
}

/// A stable, per-username decoy salt for non-existent accounts, derived from
/// the per-install salt. It looks exactly like a real 32-hex per-user salt and
/// is identical across requests, so it reveals nothing about whether the
/// account exists.
fn decoy_salt(install_salt: &str, username: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(install_salt.as_bytes());
    h.update(b":decoy:");
    h.update(username.to_ascii_lowercase().as_bytes());
    let digest = h.finalize();
    let mut s = String::with_capacity(32);
    for b in &digest[..16] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginChallengeQuery {
    #[serde(default)]
    username: String,
}

pub(crate) async fn login(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: header::HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    let source = {
        let s = state.settings_guard();
        client_ip(peer.ip(), &headers, &SecurityPolicy::new(&s)).to_string()
    };
    let acct = resolve_login_account(&state, &req.username);
    let creds = crate::app::auth::LoginCreds {
        exp_hash: acct.exp_hash,
        totp_secret: acct.totp_secret,
        totp_enabled: acct.totp_enabled,
        must_setup: acct.must_setup,
    };
    use crate::app::auth::{LoginAttempt, LoginOutcome};
    match crate::app::auth::verify_login(
        &state.auth,
        &creds,
        &LoginAttempt {
            username: &req.username,
            source: &source,
            nonce: &req.nonce,
            proof: &req.proof,
            code: &req.code,
        },
    ) {
        LoginOutcome::RateLimited => api_err(StatusCode::TOO_MANY_REQUESTS, "auth.rate_limited"),
        LoginOutcome::BadCredentials => {
            audit::record_ip(
                &req.username,
                "auth.login",
                "",
                false,
                "bad_credentials",
                &source,
            );
            api_err(StatusCode::UNAUTHORIZED, "auth.bad_credentials")
        }
        LoginOutcome::NeedTotp => {
            // Password verified, but a code is required — tell the client to ask.
            Json(json!({ "ok": false, "need_totp": true })).into_response()
        }
        LoginOutcome::BadTotp => {
            audit::record_ip(&req.username, "auth.login", "", false, "bad_totp", &source);
            api_err(StatusCode::UNAUTHORIZED, "auth.bad_totp")
        }
        LoginOutcome::Ok { token, must_setup } => {
            audit::record_ip(&req.username, "auth.login", "", true, "", &source);
            Json(json!({ "ok": true, "token": token, "must_setup": must_setup })).into_response()
        }
    }
}

/// The login-relevant facts for an account (super-admin or panel user).
struct LoginAccount {
    /// Stored password verifier (hash); empty when the account doesn't exist.
    exp_hash: String,
    totp_secret: String,
    totp_enabled: bool,
    /// True when the client should be forced through first-time setup (still on
    /// the default password / the reserved `admin` name).
    must_setup: bool,
}

/// Resolve the login account: the super-admin (web.json) or a panel user. A
/// missing account yields an empty `exp_hash` so the password check fails
/// uniformly (no account-enumeration signal).
fn resolve_login_account(state: &Shared, username: &str) -> LoginAccount {
    let su = state.settings_guard();
    if username == su.username {
        return LoginAccount {
            exp_hash: su.verifier().to_string(),
            totp_secret: su.totp_secret.clone(),
            totp_enabled: su.totp_enabled,
            must_setup: su.pw_default || su.username.eq_ignore_ascii_case("admin"),
        };
    }
    drop(su);
    match crate::app::users::find(username) {
        Some(u) => LoginAccount {
            exp_hash: u.pw_hash,
            totp_secret: u.totp_secret,
            totp_enabled: u.totp_enabled,
            must_setup: false,
        },
        None => LoginAccount {
            exp_hash: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            must_setup: false,
        },
    }
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

/// Query for `POST /api/ticket`: the purpose the ticket is scoped to.
#[derive(serde::Deserialize)]
pub(crate) struct TicketReq {
    #[serde(default)]
    purpose: String,
}

/// POST /api/ticket?purpose=terminal|download — mint a one-time, 30-second ticket
/// for a single WebSocket upgrade or file download, SCOPED to a purpose so a
/// leaked ticket can't be reused across features (a download ticket can't open a
/// terminal). Requires a valid bearer session; the ticket (not the long-lived
/// token) travels in the URL.
pub(crate) async fn mint_ticket(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<TicketReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    // Only the known purposes are mintable.
    if q.purpose != "terminal" && q.purpose != "download" {
        return api_err(StatusCode::BAD_REQUEST, "auth.bad_request");
    }
    Json(json!({ "ok": true, "data": { "ticket": state.auth.issue_ticket(&acct.username, &q.purpose) } }))
        .into_response()
}

// ---------------------------------------------------------------------------
// Step-up re-authentication (high-risk operations)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct StepUpReq {
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    proof: String,
    #[serde(default)]
    code: String,
}

/// POST /api/stepup — re-authenticate the **current** account (challenge-
/// response password proof + TOTP when enabled) and, on success, mint a short-
/// lived single-use step-up token. The high-risk endpoints (self-update,
/// settings change, privileged-container exec) require this token via
/// `require_stepup` on top of the normal session, so a stolen/abandoned session
/// alone can't trigger an irreversible action. Reuses the login proof flow: the
/// client fetches a challenge for its own account, then posts
/// `sha256(nonce ":" verifier)`.
pub(crate) async fn stepup(
    State(state): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: header::HeaderMap,
    Json(req): Json<StepUpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let source = {
        let s = state.settings_guard();
        client_ip(peer.ip(), &headers, &SecurityPolicy::new(&s)).to_string()
    };
    let la = resolve_login_account(&state, &acct.username);
    let creds = crate::app::auth::ReauthCreds {
        exp_hash: la.exp_hash,
        totp_secret: la.totp_secret,
        totp_enabled: la.totp_enabled,
    };
    use crate::app::auth::{verify_reauth, ReauthOutcome};
    match verify_reauth(
        &state.auth,
        &creds,
        &source,
        &req.nonce,
        &req.proof,
        &req.code,
    ) {
        ReauthOutcome::RateLimited => api_err(StatusCode::TOO_MANY_REQUESTS, "auth.rate_limited"),
        ReauthOutcome::BadCredentials => api_err(StatusCode::UNAUTHORIZED, "auth.bad_credentials"),
        ReauthOutcome::NeedTotp => Json(json!({ "ok": false, "need_totp": true })).into_response(),
        ReauthOutcome::BadTotp => api_err(StatusCode::UNAUTHORIZED, "auth.bad_totp"),
        ReauthOutcome::Ok => {
            let token = state.auth.issue_stepup(&acct.username);
            Json(json!({ "ok": true, "data": { "token": token } })).into_response()
        }
    }
}
