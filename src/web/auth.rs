//! Web-console auth: bearer session tokens + login rate limiting.
//!
//! A successful login (correct password) mints a random token kept in memory
//! with an expiry. Requests carry it as `Authorization: Bearer <token>` (or a
//! `token` query param for WebSocket upgrades, which can't set headers from the
//! browser). Failed logins are rate-limited per source to slow brute force.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Session lifetime. Plaintext transport already limits the value of a long
/// session, so keep it modest; the console refreshes on activity client-side.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// Login failure window + cap (per source key).
const FAIL_WINDOW: Duration = Duration::from_secs(300);
const FAIL_MAX: usize = 10;

/// Login challenge (nonce) lifetime. Short — it's used immediately.
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, Instant>>, // token -> created
    fails: Mutex<HashMap<String, Vec<Instant>>>, // source -> failure times
    challenges: Mutex<HashMap<String, Instant>>, // login nonce -> issued (single use)
}

impl AuthState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `source` is currently allowed to attempt a login.
    pub fn login_allowed(&self, source: &str) -> bool {
        let mut m = self.fails.lock().unwrap();
        let now = Instant::now();
        let entry = m.entry(source.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) <= FAIL_WINDOW);
        entry.len() < FAIL_MAX
    }

    pub fn record_failure(&self, source: &str) {
        let mut m = self.fails.lock().unwrap();
        let now = Instant::now();
        let entry = m.entry(source.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) <= FAIL_WINDOW);
        entry.push(now);
    }

    pub fn clear_failures(&self, source: &str) {
        self.fails.lock().unwrap().remove(source);
    }

    /// Mint a new session token.
    pub fn issue(&self) -> String {
        let token = random_token();
        let mut m = self.sessions.lock().unwrap();
        let now = Instant::now();
        // Opportunistically prune expired sessions.
        m.retain(|_, created| now.duration_since(*created) <= SESSION_TTL);
        m.insert(token.clone(), now);
        token
    }

    /// Validate a bearer token (unexpired).
    pub fn valid(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let m = self.sessions.lock().unwrap();
        match m.get(token) {
            Some(created) => Instant::now().duration_since(*created) <= SESSION_TTL,
            None => false,
        }
    }

    /// Invalidate a session (logout).
    pub fn revoke(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    /// Mint a one-time login challenge nonce (hex). The client proves knowledge
    /// of the password by returning `sha256(nonce:password)` so the cleartext
    /// password never crosses the (plaintext-HTTP) wire.
    pub fn issue_challenge(&self) -> String {
        let nonce = random_token();
        let mut m = self.challenges.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, t| now.duration_since(*t) <= CHALLENGE_TTL);
        m.insert(nonce.clone(), now);
        nonce
    }

    /// Consume a challenge nonce: valid only if present + unexpired, and it's
    /// removed so it can't be replayed.
    pub fn consume_challenge(&self, nonce: &str) -> bool {
        if nonce.is_empty() {
            return false;
        }
        let mut m = self.challenges.lock().unwrap();
        match m.remove(nonce) {
            Some(t) => Instant::now().duration_since(t) <= CHALLENGE_TTL,
            None => false,
        }
    }
}

fn random_token() -> String {
    use rand::Rng;
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..48).map(|_| HEX[rng.gen_range(0..16)] as char).collect()
}

/// Constant-time-ish password comparison (avoids early-exit timing leak).
pub fn password_matches(expected: &str, given: &str) -> bool {
    let a = expected.as_bytes();
    let b = given.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Verify a challenge-response login proof: the client sends
/// `sha256_hex(nonce + ":" + password)`. We recompute it from the known
/// password and compare (constant-time). This keeps the cleartext password off
/// the (plaintext-HTTP) wire; the nonce is single-use so a captured proof can't
/// be replayed.
pub fn proof_matches(nonce: &str, password: &str, proof: &str) -> bool {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(nonce.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    let expected = hex_lower(&h.finalize());
    password_matches(&expected, &proof.trim().to_lowercase())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_compare() {
        assert!(password_matches("hunter2", "hunter2"));
        assert!(!password_matches("hunter2", "hunter3"));
        assert!(!password_matches("hunter2", "hunter22"));
        assert!(!password_matches("", "x"));
    }

    #[test]
    fn proof_roundtrip() {
        use sha2::{Digest, Sha256};
        let nonce = "abc123";
        let pw = "hunter2";
        let mut h = Sha256::new();
        h.update(nonce.as_bytes());
        h.update(b":");
        h.update(pw.as_bytes());
        let proof = super::hex_lower(&h.finalize());
        assert!(proof_matches(nonce, pw, &proof));
        // Uppercase proof still matches (we lowercase before compare).
        assert!(proof_matches(nonce, pw, &proof.to_uppercase()));
        assert!(!proof_matches(nonce, "wrong", &proof));
        assert!(!proof_matches("othernonce", pw, &proof));
    }

    #[test]
    fn challenge_single_use() {
        let a = AuthState::new();
        let n = a.issue_challenge();
        assert!(a.consume_challenge(&n));
        assert!(!a.consume_challenge(&n)); // replay rejected
        assert!(!a.consume_challenge("never-issued"));
    }

    #[test]
    fn issue_and_validate_session() {
        let a = AuthState::new();
        let t = a.issue();
        assert!(a.valid(&t));
        assert!(!a.valid("bogus"));
        assert!(!a.valid(""));
        a.revoke(&t);
        assert!(!a.valid(&t));
    }

    #[test]
    fn login_rate_limit() {
        let a = AuthState::new();
        let src = "1.2.3.4";
        for _ in 0..FAIL_MAX {
            assert!(a.login_allowed(src));
            a.record_failure(src);
        }
        assert!(!a.login_allowed(src)); // capped
        a.clear_failures(src);
        assert!(a.login_allowed(src)); // reset on success
    }
}
