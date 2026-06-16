//! Authentication use-cases — the single place the login policy is orchestrated.
//!
//! The web boundary only resolves an account's stored credentials, calls
//! [`verify_login`], and maps the [`LoginOutcome`] to an HTTP response + audit
//! line. Per-source rate limiting, single-use challenge consumption, the
//! constant-time proof check, the optional TOTP second factor, and session
//! minting all live here (over the `infra::auth` stores + `infra::totp`), so the
//! policy isn't split across delivery (`login`/`gate`) and infra.

use crate::infra::auth::{proof_matches, AuthState};

/// An account's login facts, resolved by the web boundary from the console
/// settings (super-admin) or the user store (panel users). `exp_hash` is the
/// stored challenge-response verifier; empty means the account doesn't exist
/// (the proof check then fails uniformly — no account-enumeration signal).
pub(crate) struct LoginCreds {
    pub(crate) exp_hash: String,
    pub(crate) totp_secret: String,
    pub(crate) totp_enabled: bool,
    pub(crate) must_setup: bool,
}

/// The result of a login attempt. The web layer maps each variant to a response
/// (and, where appropriate, an audit record).
pub(crate) enum LoginOutcome {
    /// Password (and TOTP, if enabled) verified; a fresh session was minted.
    Ok { token: String, must_setup: bool },
    /// Password verified, but the account has 2FA and no code was supplied.
    NeedTotp,
    /// Wrong password / unknown account / replayed-or-expired challenge.
    BadCredentials,
    /// Password ok but the TOTP code was wrong.
    BadTotp,
    /// The source exceeded the login-failure cap within the window.
    RateLimited,
}

/// One login attempt's request inputs. `username` binds the minted session;
/// `source` keys the rate limiter; `nonce`/`proof`/`code` carry the challenge
/// response. Bundled to keep [`verify_login`] within the param limit.
pub(crate) struct LoginAttempt<'a> {
    pub(crate) username: &'a str,
    pub(crate) source: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) proof: &'a str,
    pub(crate) code: &'a str,
}

/// Orchestrate one login attempt. Side effects (record/clear failures, consume
/// the challenge, mint the session) are confined here so the policy is in one
/// place.
pub(crate) fn verify_login(
    auth: &AuthState,
    creds: &LoginCreds,
    attempt: &LoginAttempt,
) -> LoginOutcome {
    if !auth.login_allowed(attempt.source) {
        return LoginOutcome::RateLimited;
    }
    // Account must exist, the challenge must be valid+unused, and the proof must
    // match — evaluated in that order so a single-use nonce is only consumed for
    // a real account.
    let pw_ok = !creds.exp_hash.is_empty()
        && auth.consume_challenge(attempt.nonce)
        && proof_matches(attempt.nonce, &creds.exp_hash, attempt.proof);
    if !pw_ok {
        auth.record_failure(attempt.source);
        return LoginOutcome::BadCredentials;
    }
    if creds.totp_enabled {
        if attempt.code.trim().is_empty() {
            return LoginOutcome::NeedTotp;
        }
        // Single-use TOTP: rejects a replay of the same code within its validity
        // window (an observed code can't be reused to log in again).
        if !auth.verify_totp_single_use(&creds.totp_secret, attempt.code) {
            auth.record_failure(attempt.source);
            return LoginOutcome::BadTotp;
        }
    }
    auth.clear_failures(attempt.source);
    let token = auth.issue(attempt.username);
    LoginOutcome::Ok {
        token,
        must_setup: creds.must_setup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof_for(nonce: &str, verifier: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(nonce.as_bytes());
        h.update(b":");
        h.update(verifier.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn creds(enabled: bool) -> LoginCreds {
        LoginCreds {
            exp_hash: "deadbeefverifier".to_string(),
            totp_secret: String::new(),
            totp_enabled: enabled,
            must_setup: false,
        }
    }

    /// Terse builder for a `LoginAttempt` in tests.
    fn att<'a>(
        username: &'a str,
        source: &'a str,
        nonce: &'a str,
        proof: &'a str,
        code: &'a str,
    ) -> LoginAttempt<'a> {
        LoginAttempt {
            username,
            source,
            nonce,
            proof,
            code,
        }
    }

    #[test]
    fn good_password_no_totp_issues_session() {
        let auth = AuthState::new();
        let n = auth.issue_challenge();
        let p = proof_for(&n, "deadbeefverifier");
        match verify_login(&auth, &creds(false), &att("alice", "1.1.1.1", &n, &p, "")) {
            LoginOutcome::Ok { token, .. } => assert!(auth.valid(&token)),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn wrong_proof_is_bad_credentials() {
        let auth = AuthState::new();
        let n = auth.issue_challenge();
        assert!(matches!(
            verify_login(
                &auth,
                &creds(false),
                &att("alice", "1.1.1.1", &n, "bogus", "")
            ),
            LoginOutcome::BadCredentials
        ));
    }

    #[test]
    fn unknown_account_is_bad_credentials() {
        let auth = AuthState::new();
        let n = auth.issue_challenge();
        let absent = LoginCreds {
            exp_hash: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            must_setup: false,
        };
        let p = proof_for(&n, "");
        assert!(matches!(
            verify_login(&auth, &absent, &att("ghost", "1.1.1.1", &n, &p, "")),
            LoginOutcome::BadCredentials
        ));
    }

    #[test]
    fn totp_enabled_without_code_asks_for_it() {
        let auth = AuthState::new();
        let n = auth.issue_challenge();
        let p = proof_for(&n, "deadbeefverifier");
        assert!(matches!(
            verify_login(&auth, &creds(true), &att("alice", "1.1.1.1", &n, &p, "")),
            LoginOutcome::NeedTotp
        ));
    }

    #[test]
    fn totp_code_is_single_use_across_logins() {
        use crate::infra::support::totp;
        let auth = AuthState::new();
        let secret = totp::gen_secret();
        // A live code for the current step.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = now / 30;
        // Derive the code the same way totp does, via a successful verify probe:
        // brute a 6-digit code is impractical, so instead assert single-use by
        // running two logins with the same code string and checking the second
        // is rejected. We obtain a valid code by trying the registry's own guard.
        // Build a known code: re-create it from the secret using a tiny HOTP.
        let code = live_code(&secret, step);

        let mk = |code: &str| {
            let n = auth.issue_challenge();
            let p = proof_for(&n, "deadbeefverifier");
            let creds = LoginCreds {
                exp_hash: "deadbeefverifier".to_string(),
                totp_secret: secret.clone(),
                totp_enabled: true,
                must_setup: false,
            };
            // att borrows; clone code into owned strings first.
            let nonce = n;
            let proof = p;
            let attempt = LoginAttempt {
                username: "alice",
                source: "1.1.1.1",
                nonce: &nonce,
                proof: &proof,
                code,
            };
            matches!(
                verify_login(&auth, &creds, &attempt),
                LoginOutcome::Ok { .. }
            )
        };

        assert!(mk(&code), "first use of a fresh code logs in");
        assert!(!mk(&code), "replay of the same code is rejected");
    }

    /// Minimal HOTP to derive the expected TOTP code for a step (test helper).
    fn live_code(secret_b32: &str, step: u64) -> String {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        // base32 decode (RFC 4648, no padding).
        const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u32;
        let mut nbits = 0u32;
        let mut bytes = Vec::new();
        for c in secret_b32
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
        {
            let v = B32
                .iter()
                .position(|&b| b == c.to_ascii_uppercase() as u8)
                .unwrap() as u32;
            bits = (bits << 5) | v;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                bytes.push((bits >> nbits) as u8);
            }
        }
        let mut mac = Hmac::<Sha1>::new_from_slice(&bytes).unwrap();
        mac.update(&step.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        let off = (tag[19] & 0x0f) as usize;
        let bin = ((tag[off] as u32 & 0x7f) << 24)
            | ((tag[off + 1] as u32) << 16)
            | ((tag[off + 2] as u32) << 8)
            | (tag[off + 3] as u32);
        format!("{:06}", bin % 1_000_000)
    }
}
