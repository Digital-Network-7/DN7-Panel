//! ACME HTTP-01 challenge serving — the in-process replacement for the
//! `location = /.well-known/acme-challenge/<token> { return 200 "<keyauth>"; }`
//! the panel used to inject into the :80 server block during Let's Encrypt
//! issuance.
//!
//! The existing ACME client (`infra::website::certs`, instant-acme) computes the
//! token→keyAuthorization pair; during issuance it registers the pair here
//! ([`insert`]) and the router answers the validation request from this map
//! ([`serve`]), then [`remove`]s it. This is strictly simpler than the old
//! config-injection path and needs no reload.
//!
//! [M5] wires `insert`/`remove` into the issuance flow; the store + `serve` are
//! implemented here as foundation so the router can call them.

use std::collections::HashMap;
use std::sync::Mutex;

use super::response::{self, Resp};

/// token → keyAuthorization for in-flight HTTP-01 challenges.
fn tokens() -> &'static Mutex<HashMap<String, String>> {
    static T: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a challenge response for the issuance window.
pub(crate) fn insert(token: &str, key_authorization: &str) {
    tokens()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(token.to_string(), key_authorization.to_string());
}

/// Drop a challenge once issuance finishes (success or failure).
pub(crate) fn remove(token: &str) {
    tokens()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(token);
}

/// Answer an `/.well-known/acme-challenge/<token>` request, if we have it.
/// Returns `None` when the token is unknown (the router then routes normally,
/// e.g. 404), `Some(200 text/plain keyAuthorization)` when it matches.
pub(crate) fn serve(token: &str) -> Option<Resp> {
    let keyauth = tokens()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(token)
        .cloned()?;
    Some(response::text(http::StatusCode::OK, keyauth))
}
