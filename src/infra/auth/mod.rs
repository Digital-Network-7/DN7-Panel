//! Web-console auth: bearer session tokens + login rate limiting.
//!
//! A successful login (correct password) mints a random token kept in memory
//! with an expiry. Requests carry it as `Authorization: Bearer <token>` (or a
//! `token` query param for WebSocket upgrades, which can't set headers from the
//! browser). Failed logins are rate-limited per source to slow brute force.
//!
//! [`AuthState`] is a thin façade over four focused, self-contained stores —
//! each in its own submodule (`session`/`challenge`/`ticket`/`rate`), owning its
//! own lock and lifecycle. [`AuthState::sweep`] prunes expired entries across
//! all of them from one place (called periodically by the server), so lifecycle
//! isn't scattered across ad-hoc prune-on-insert paths. Shared helpers (token
//! RNG/hashing, the challenge-response proof, session persistence) live here.

use std::collections::HashMap;
use std::time::Duration;

mod challenge;
mod rate;
mod session;
mod ticket;

use challenge::ChallengeStore;
use rate::RateLimiter;
use session::SessionStore;
use ticket::TicketStore;

/// Session lifetime. Plaintext transport already limits the value of a long
/// session, so keep it modest; the console refreshes on activity client-side.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// Login failure window + cap (per source key).
const FAIL_WINDOW: Duration = Duration::from_secs(300);
const FAIL_MAX: usize = 10;

/// Login challenge (nonce) lifetime. Short — it's used immediately.
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// One-time ticket lifetime. Used to authorize a single WebSocket upgrade or
/// file download where the bearer token can't ride in an Authorization header
/// and would otherwise leak into the URL (history, proxy logs, screenshots).
const TICKET_TTL: Duration = Duration::from_secs(30);

/// Hard caps on outstanding challenges/tickets. The challenge endpoint is
/// public (pre-auth), so without a ceiling a flood could exhaust memory; at the
/// cap the oldest entries are evicted to make room.
const MAX_CHALLENGES: usize = 4096;
const MAX_TICKETS: usize = 4096;

/// Web-console auth façade: bearer sessions, login challenges, one-time tickets
/// and a per-source login rate limiter, each behind its own focused store.
#[derive(Default)]
pub struct AuthState {
    sessions: SessionStore,
    challenges: ChallengeStore,
    tickets: TicketStore,
    rate: RateLimiter,
}

impl AuthState {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with on-disk session persistence, loading any still-valid
    /// sessions left by a previous run so a restart doesn't force re-login.
    pub fn with_store() -> Self {
        Self {
            sessions: SessionStore::with_store(),
            ..Self::default()
        }
    }

    /// Set the session inactivity timeout (seconds). 0 falls back to the default.
    pub fn set_ttl_secs(&self, secs: u64) {
        self.sessions.set_ttl_secs(secs);
    }

    /// Mint a new session token bound to `user`.
    pub fn issue(&self, user: &str) -> String {
        self.sessions.issue(user)
    }

    /// Validate a bearer token (sliding expiry).
    pub fn valid(&self, token: &str) -> bool {
        self.sessions.identity(token).is_some()
    }

    /// Resolve a bearer token to its account name, sliding the expiry window.
    pub fn identity(&self, token: &str) -> Option<String> {
        self.sessions.identity(token)
    }

    /// Invalidate a single session (logout).
    pub fn revoke(&self, token: &str) {
        self.sessions.revoke(token);
    }

    /// Revoke every session and pending ticket belonging to `user`, optionally
    /// keeping one session token alive (the caller's current session). Called
    /// after a password or 2FA change so a previously-leaked token is
    /// invalidated immediately instead of surviving until its TTL expires.
    pub fn revoke_user(&self, user: &str, keep: Option<&str>) {
        self.sessions.revoke_user(user, keep);
        self.tickets.revoke_user(user);
    }

    /// Whether `source` is currently allowed to attempt a login.
    pub fn login_allowed(&self, source: &str) -> bool {
        self.rate.allowed(source)
    }

    pub fn record_failure(&self, source: &str) {
        self.rate.record(source);
    }

    pub fn clear_failures(&self, source: &str) {
        self.rate.clear(source);
    }

    /// Mint a one-time login challenge nonce (hex). The client proves knowledge
    /// of the password by returning `sha256(nonce:password)` so the cleartext
    /// password never crosses the (plaintext-HTTP) wire.
    pub fn issue_challenge(&self) -> String {
        self.challenges.issue()
    }

    /// Consume a challenge nonce: valid only if present + unexpired, and it's
    /// removed so it can't be replayed.
    pub fn consume_challenge(&self, nonce: &str) -> bool {
        self.challenges.consume(nonce)
    }

    /// Mint a one-time ticket (hex) bound to `user`, authorizing a single
    /// WebSocket upgrade or download. The ticket — not the long-lived session
    /// token — travels in the URL, so a leaked URL exposes only a 30-second,
    /// single-use credential.
    pub fn issue_ticket(&self, user: &str) -> String {
        self.tickets.issue(user)
    }

    /// Consume a one-time ticket: returns the owning account name if present +
    /// unexpired, then removes it so it can't be replayed.
    pub fn consume_ticket(&self, ticket: &str) -> Option<String> {
        self.tickets.consume(ticket)
    }

    /// Prune expired entries across every store. Idempotent and cheap; the
    /// server calls this on a timer so memory doesn't rely solely on the
    /// prune-on-insert paths.
    pub fn sweep(&self) {
        self.sessions.sweep();
        self.challenges.sweep();
        self.tickets.sweep();
        self.rate.sweep();
    }
}

// ---------------------------------------------------------------------------
// Shared session record + persistence (used by the `session` submodule)
// ---------------------------------------------------------------------------

/// A persisted session: the owning account + last-access (unix secs, sliding).
/// The map/file key is `sha256(token)` (see `token_key`), never the raw token.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SessionRec {
    #[serde(default)]
    user: String,
    last: u64,
}

fn sessions_path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("sessions.json")
}

/// Load persisted sessions (sha256(token) -> session record). None on any error.
fn load_sessions() -> Option<HashMap<String, SessionRec>> {
    let s = std::fs::read_to_string(sessions_path()).ok()?;
    serde_json::from_str(&s).ok()
}

/// Persist the session map. The keys are token hashes (never raw tokens), but
/// they're still sensitive, so the file is written 0600 atomically.
fn write_sessions(map: &HashMap<String, SessionRec>) -> std::io::Result<()> {
    let path = sessions_path();
    let data = serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string());
    crate::platform::paths::write_private(&path, data.as_bytes())
}

// ---------------------------------------------------------------------------
// Shared token + proof helpers
// ---------------------------------------------------------------------------

fn random_token() -> String {
    use rand::Rng;
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..48).map(|_| HEX[rng.gen_range(0..16)] as char).collect()
}

/// The at-rest key for a session token: `sha256_hex(token)`. The raw token is
/// only ever held by the client; the in-memory map and the persisted
/// `sessions.json` store the hash, so a leaked session file can't be replayed
/// (an attacker would need to invert SHA-256 to recover a usable bearer token).
fn token_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex_lower(&h.finalize())
}

/// Current wall-clock time in unix seconds (0 on the impossible clock error).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    fn ticket_single_use() {
        let a = AuthState::new();
        let t = a.issue_ticket("alice");
        assert_eq!(a.consume_ticket(&t).as_deref(), Some("alice"));
        assert!(a.consume_ticket(&t).is_none()); // replay rejected
        assert!(a.consume_ticket("never-issued").is_none());
        assert!(a.consume_ticket("").is_none());
    }

    #[test]
    fn issue_and_validate_session() {
        let a = AuthState::new();
        let t = a.issue("alice");
        assert!(a.valid(&t));
        assert_eq!(a.identity(&t).as_deref(), Some("alice"));
        assert!(!a.valid("bogus"));
        assert!(!a.valid(""));
        a.revoke(&t);
        assert!(!a.valid(&t));
    }

    #[test]
    fn revoke_user_clears_other_sessions() {
        let a = AuthState::new();
        let keep = a.issue("alice");
        let other = a.issue("alice");
        let bob = a.issue("bob");
        a.revoke_user("alice", Some(&keep));
        assert!(a.valid(&keep)); // current session kept
        assert!(!a.valid(&other)); // other alice session revoked
        assert!(a.valid(&bob)); // unrelated account untouched
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
