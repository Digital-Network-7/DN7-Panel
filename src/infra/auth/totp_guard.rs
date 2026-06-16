//! TOTP single-use guard: remembers the last consumed time-step per account so
//! a code can't be replayed within its ±1-step validity window.
//!
//! RFC 6238 codes are valid for a ~90-second window (the current step ± one for
//! clock skew). Without tracking, an attacker who observes one valid code
//! (shoulder-surf, plaintext-HTTP MITM, a logged URL) can replay it to complete
//! a login or disable 2FA. This store records `sha256(secret) -> last accepted
//! step` and rejects any code whose matched step is `<=` the last one accepted
//! for that secret. Keyed by the secret's hash (never the raw secret) so a
//! memory dump can't yield the TOTP seed.

use std::collections::HashMap;
use std::sync::Mutex;

use super::now_secs;

/// Per-secret last-consumed TOTP step, with an `updated` wall-clock stamp used
/// only to prune entries that can no longer matter (their window has passed).
#[derive(Default)]
pub(super) struct TotpGuard {
    map: Mutex<HashMap<String, Entry>>, // sha256(secret) -> last accepted step
}

struct Entry {
    last_step: u64,
    updated: u64, // unix secs, for opportunistic pruning
}

/// Steps are 30s; an entry older than this many seconds can be forgotten (its
/// code window — current ± 1 step — is long gone). Generous to absorb skew.
const PRUNE_AFTER_SECS: u64 = 300;

impl TotpGuard {
    /// Try to consume `step` for `secret`. Returns true if the step is newer than
    /// the last one accepted for this secret (so the code is fresh); false if it
    /// is a replay (`step <= last`). On success the new step is recorded.
    pub(super) fn consume(&self, secret: &str, step: u64) -> bool {
        let key = super::token_key(secret); // sha256(secret), never the raw seed
        let now = now_secs();
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        // Opportunistically drop stale entries so the map can't grow unbounded
        // across many accounts/secrets over the process lifetime.
        m.retain(|_, e| now.saturating_sub(e.updated) <= PRUNE_AFTER_SECS);
        if let Some(e) = m.get_mut(&key) {
            if step <= e.last_step {
                return false; // replay within (or before) the recorded window
            }
            e.last_step = step;
            e.updated = now;
            return true;
        }
        m.insert(
            key,
            Entry {
                last_step: step,
                updated: now,
            },
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_ok_replay_rejected() {
        let g = TotpGuard::default();
        // First time a step is seen for a secret: accepted.
        assert!(g.consume("SECRET", 100));
        // Same step again (replay): rejected.
        assert!(!g.consume("SECRET", 100));
        // An older step (skew toward the past): rejected.
        assert!(!g.consume("SECRET", 99));
        // A newer step (next window): accepted.
        assert!(g.consume("SECRET", 101));
        // A different secret is tracked independently.
        assert!(g.consume("OTHER", 100));
    }
}
