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

#[derive(Default)]
pub struct AuthState {
    sessions: Mutex<HashMap<String, Instant>>, // token -> created
    fails: Mutex<HashMap<String, Vec<Instant>>>, // source -> failure times
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
