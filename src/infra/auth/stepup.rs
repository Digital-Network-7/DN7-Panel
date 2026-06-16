//! Step-up (re-authentication) token store.
//!
//! A few operations are high-blast-radius enough that a live bearer session
//! shouldn't be sufficient on its own: self-update, panel-access/settings
//! changes, and exec into a privileged container. For these the caller must
//! re-prove their password (and TOTP, if enabled) right before acting; a
//! successful re-auth mints a short-lived, single-use **step-up token** the
//! high-risk endpoint then consumes. This narrows the window in which a stolen
//! session (or an unattended browser) can trigger an irreversible action.
//!
//! Mirrors the one-time `ticket` store: each token is bound to the issuing
//! account, expires quickly, and is consumed on use so it can't be replayed.
use super::{random_token, MAX_STEPUPS, STEPUP_TTL};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// A step-up grant: when it was minted + the account it authorizes.
struct StepUpRec {
    issued: Instant,
    user: String,
}

#[derive(Default)]
pub(super) struct StepUpStore {
    map: Mutex<HashMap<String, StepUpRec>>, // token -> grant
}

impl StepUpStore {
    pub(super) fn issue(&self, user: &str) -> String {
        let token = random_token();
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        m.retain(|_, r| now.duration_since(r.issued) <= STEPUP_TTL);
        while m.len() >= MAX_STEPUPS {
            let Some(oldest) = m
                .iter()
                .min_by_key(|(_, r)| r.issued)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            m.remove(&oldest);
        }
        m.insert(
            token.clone(),
            StepUpRec {
                issued: now,
                user: user.to_string(),
            },
        );
        token
    }

    /// Consume a step-up token: succeeds only if it's present, unexpired, **and**
    /// belongs to `user` (so one account's grant can't authorize another's
    /// action). Removed on success — or on expiry (cleanup) — but a wrong-user
    /// attempt leaves the grant intact so it can't be burned by another session.
    pub(super) fn consume(&self, token: &str, user: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        // Decide first (immutable borrow), then mutate — can't hold a `&` into
        // the map across `remove`.
        let outcome = match m.get(token) {
            Some(r) if r.user == user && now_fresh(r.issued) => Some(true), // valid → consume
            Some(r) if !now_fresh(r.issued) => Some(false),                 // expired → drop
            _ => None, // missing or foreign → leave intact
        };
        match outcome {
            Some(ok) => {
                m.remove(token);
                ok
            }
            None => false,
        }
    }

    pub(super) fn revoke_user(&self, user: &str) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, r| r.user != user);
    }

    pub(super) fn sweep(&self) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, r| now_fresh(r.issued));
    }
}

fn now_fresh(issued: Instant) -> bool {
    Instant::now().duration_since(issued) <= STEPUP_TTL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_and_user_bound() {
        let s = StepUpStore::default();
        let t = s.issue("alice");
        // Wrong user can't consume it.
        assert!(!s.consume(&t, "bob"));
        // Right user consumes it once.
        assert!(s.consume(&t, "alice"));
        // Replay rejected (already consumed).
        assert!(!s.consume(&t, "alice"));
        // Unknown / empty tokens rejected.
        assert!(!s.consume("never-issued", "alice"));
        assert!(!s.consume("", "alice"));
    }

    #[test]
    fn revoke_user_clears_grants() {
        let s = StepUpStore::default();
        let a = s.issue("alice");
        let b = s.issue("bob");
        s.revoke_user("alice");
        assert!(!s.consume(&a, "alice")); // alice's grant gone
        assert!(s.consume(&b, "bob")); // bob's untouched
    }
}
