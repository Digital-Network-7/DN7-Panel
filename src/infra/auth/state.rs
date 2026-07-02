use super::*;
use std::collections::HashMap;
use std::time::Duration;

/// Session lifetime. Plaintext transport already limits the value of a long
/// session, so keep it modest; the console refreshes on activity client-side.
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// Absolute session lifetime, independent of activity. A session is hard-expired
/// once it's older than this even if continuously used, so a leaked bearer token
/// can't be kept alive indefinitely by polling. The sliding [`SESSION_TTL`]
/// still applies on top (idle sessions expire sooner).
pub(crate) const SESSION_ABS_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Login failure window + cap (per source key).
pub(crate) const FAIL_WINDOW: Duration = Duration::from_secs(300);
pub(crate) const FAIL_MAX: usize = 10;

/// Login challenge (nonce) lifetime. Short — it's used immediately.
pub(crate) const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// One-time ticket lifetime. Used to authorize a single WebSocket upgrade or
/// file download where the bearer token can't ride in an Authorization header
/// and would otherwise leak into the URL (history, proxy logs, screenshots).
pub(crate) const TICKET_TTL: Duration = Duration::from_secs(30);

/// Step-up (re-auth) token lifetime. Short — it's minted right before the
/// high-risk action it authorizes and consumed immediately after.
pub(crate) const STEPUP_TTL: Duration = Duration::from_secs(120);

/// Hard caps on outstanding challenges/tickets. The challenge endpoint is
/// public (pre-auth), so without a ceiling a flood could exhaust memory; at the
/// cap the oldest entries are evicted to make room.
pub(crate) const MAX_CHALLENGES: usize = 4096;
pub(crate) const MAX_TICKETS: usize = 4096;

/// Hard cap on outstanding step-up tokens (authenticated callers only, so a
/// lower ceiling than the public challenge/ticket stores is plenty).
pub(crate) const MAX_STEPUPS: usize = 1024;

/// Web-console auth façade: bearer sessions, login challenges, one-time tickets
/// and a per-source login rate limiter, each behind its own focused store.
#[derive(Default)]
pub struct AuthState {
    sessions: SessionStore,
    challenges: ChallengeStore,
    tickets: TicketStore,
    rate: RateLimiter,
    totp: TotpGuard,
    stepups: StepUpStore,
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

    /// Validate a bearer token (sliding expiry). Test-only now that the web layer
    /// authenticates via `kernel::authed_user` (which also accepts the CLI token).
    #[cfg(test)]
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
        self.stepups.revoke_user(user);
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

    /// Per-ACCOUNT login throttle (in addition to per-source), so a distributed
    /// attacker rotating source IPs to stay under the per-IP cap still hits an
    /// aggregate limit on the account they're targeting. The key is namespaced
    /// (`u:`) so it can't collide with a source-IP key, and callers only record
    /// failures for accounts that actually exist — username enumeration can't
    /// grow the map. (Locking a *known* account under a sustained flood is the
    /// accepted tradeoff; it auto-clears after FAIL_WINDOW and never blocks a
    /// different account or a successful login.)
    pub fn account_login_allowed(&self, user: &str) -> bool {
        self.rate.allowed(&format!("u:{user}"))
    }

    pub fn record_account_failure(&self, user: &str) {
        self.rate.record(&format!("u:{user}"));
    }

    pub fn clear_account_failures(&self, user: &str) {
        self.rate.clear(&format!("u:{user}"));
    }

    /// Mint a one-time login challenge nonce (hex). The client answers with a
    /// static password verifier (`deriveVerifier(salt, password, kdf)`) — never
    /// the cleartext password — alongside this nonce; the nonce is single-use so
    /// the exact request can't be replayed. NOTE: the verifier is NOT bound to
    /// the nonce, so a captured verifier can still be replayed with a fresh nonce
    /// over a plaintext / untrusted-TLS channel; closing that residual needs a
    /// PAKE — see `docs/design/pake-auth-proposal.md`.
    pub fn issue_challenge(&self) -> String {
        self.challenges.issue()
    }

    /// Consume a challenge nonce: valid only if present + unexpired, and it's
    /// removed so it can't be replayed.
    pub fn consume_challenge(&self, nonce: &str) -> bool {
        self.challenges.consume(nonce)
    }

    /// Verify a TOTP `code` against `secret` **and** enforce single use: a code
    /// is accepted only once within its ±1-step validity window. A replay of the
    /// same (or an earlier) code for the same secret is rejected even though it
    /// would still satisfy the bare RFC 6238 check. Use this everywhere a code is
    /// accepted as a second factor (login, enable/disable 2FA).
    pub fn verify_totp_single_use(&self, secret: &str, code: &str) -> bool {
        match crate::infra::support::totp::matched_step(secret, code) {
            Some(step) => self.totp.consume(secret, step),
            None => false,
        }
    }

    /// Mint a one-time ticket (hex) bound to `user`, authorizing a single
    /// WebSocket upgrade or download. The ticket — not the long-lived session
    /// token — travels in the URL, so a leaked URL exposes only a 30-second,
    /// single-use credential.
    pub fn issue_ticket(&self, user: &str, purpose: &str) -> String {
        self.tickets.issue(user, purpose)
    }

    /// Consume a one-time ticket: returns the owning account name if it's present,
    /// unexpired, AND was issued for `purpose`, then removes it so it can't be
    /// replayed (including against a different purpose).
    pub fn consume_ticket(&self, ticket: &str, purpose: &str) -> Option<String> {
        self.tickets.consume(ticket, purpose)
    }

    /// Mint a single-use step-up token bound to `user`, issued after a fresh
    /// re-authentication and consumed by a high-risk endpoint (self-update /
    /// settings change / privileged-container exec).
    pub fn issue_stepup(&self, user: &str) -> String {
        self.stepups.issue(user)
    }

    /// Consume a step-up token: true only if present, unexpired, and bound to
    /// `user`. Removed on use (single-use).
    pub fn consume_stepup(&self, token: &str, user: &str) -> bool {
        self.stepups.consume(token, user)
    }

    /// Prune expired entries across every store. Idempotent and cheap; the
    /// server calls this on a timer so memory doesn't rely solely on the
    /// prune-on-insert paths.
    pub fn sweep(&self) {
        self.sessions.sweep();
        self.challenges.sweep();
        self.tickets.sweep();
        self.rate.sweep();
        self.stepups.sweep();
    }
}

// ---------------------------------------------------------------------------
// Shared session record + persistence (used by the `session` submodule)
// ---------------------------------------------------------------------------

/// A persisted session: the owning account, last-access (unix secs, sliding),
/// and issued-at (unix secs, fixed) for the absolute lifetime cap.
/// The map/file key is `sha256(token)` (see `token_key`), never the raw token.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionRec {
    #[serde(default)]
    pub(crate) user: String,
    pub(crate) last: u64,
    /// When the session was first minted. Sessions are hard-expired at
    /// `issued + SESSION_ABS_TTL` regardless of activity, so a leaked token
    /// can't be kept alive forever by polling. Defaults to 0 for records written
    /// by older builds (treated as "issued at epoch" → they age out promptly,
    /// which is the safe direction).
    #[serde(default)]
    pub(crate) issued: u64,
}

pub(crate) fn sessions_path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("sessions.json")
}

/// Load persisted sessions (sha256(token) -> session record). None on any error.
pub(crate) fn load_sessions() -> Option<HashMap<String, SessionRec>> {
    let s = std::fs::read_to_string(sessions_path()).ok()?;
    serde_json::from_str(&s).ok()
}

/// Persist the session map. The keys are token hashes (never raw tokens), but
/// they're still sensitive, so the file is written 0600 atomically.
pub(crate) fn write_sessions(map: &HashMap<String, SessionRec>) -> std::io::Result<()> {
    let path = sessions_path();
    let data = serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string());
    crate::platform::paths::write_private(&path, data.as_bytes())
}

// ---------------------------------------------------------------------------
// Shared token + proof helpers
// ---------------------------------------------------------------------------

pub(crate) fn random_token() -> String {
    use rand::Rng;
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..48).map(|_| HEX[rng.gen_range(0..16)] as char).collect()
}

/// The at-rest key for a session token: `sha256_hex(token)`. The raw token is
/// only ever held by the client; the in-memory map and the persisted
/// `sessions.json` store the hash, so a leaked session file can't be replayed
/// (an attacker would need to invert SHA-256 to recover a usable bearer token).
pub(crate) fn token_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex_lower(&h.finalize())
}

/// Current wall-clock time in unix seconds (0 on the impossible clock error).
pub(crate) fn now_secs() -> u64 {
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

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
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
        let t = a.issue_ticket("alice", "download");
        // Wrong purpose is rejected (and consumes nothing).
        assert!(a.consume_ticket(&t, "terminal").is_none());
        assert_eq!(a.consume_ticket(&t, "download").as_deref(), Some("alice"));
        assert!(a.consume_ticket(&t, "download").is_none()); // replay rejected
        assert!(a.consume_ticket("never-issued", "download").is_none());
        assert!(a.consume_ticket("", "download").is_none());
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
