//! Bearer-token session store (split from auth.rs). Sliding inactivity timeout
//! plus optional on-disk persistence. The map is keyed by the token hash from
//! `super::token_key` (never the raw token), so a leaked session file or memory
//! dump can't yield a usable bearer token.
use super::{now_secs, random_token, token_key, SessionRec, SESSION_ABS_TTL, SESSION_TTL};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Bearer-token session store with a sliding inactivity timeout and optional
/// on-disk persistence (so a restart — e.g. a self-update — doesn't log
/// everyone out).
#[derive(Default)]
pub(super) struct SessionStore {
    map: Mutex<HashMap<String, SessionRec>>, // sha256(token) -> {user, last access}
    /// Configurable inactivity timeout in seconds (0 = built-in SESSION_TTL).
    ttl_secs: AtomicU64,
    /// When true, the session map is persisted to disk.
    persist: bool,
    /// Serializes persistence. Without it, `save` clones the map under the map
    /// lock but writes OUTSIDE it, so a stale snapshot (cloned before a
    /// concurrent `revoke`) could land on disk last and resurrect a revoked
    /// session after a restart. Holding this across snapshot+write makes the
    /// last writer always snapshot the freshest map.
    write_lock: Mutex<()>,
}

impl SessionStore {
    pub(super) fn with_store() -> Self {
        let s = Self {
            persist: true,
            ..Self::default()
        };
        if let Some(map) = super::load_sessions() {
            let now = now_secs();
            let live: HashMap<String, SessionRec> = map
                .into_iter()
                .filter(|(_, r)| Self::record_live(r, now, SESSION_TTL.as_secs()))
                .collect();
            *s.map.lock().unwrap_or_else(|p| p.into_inner()) = live;
        }
        s
    }

    /// Whether a session record is still valid: within the sliding inactivity
    /// window AND under the absolute lifetime cap (the latter can't be extended
    /// by activity, so a leaked token can't live forever).
    fn record_live(r: &SessionRec, now: u64, ttl: u64) -> bool {
        now.saturating_sub(r.last) <= ttl
            && now.saturating_sub(r.issued) <= SESSION_ABS_TTL.as_secs()
    }

    pub(super) fn set_ttl_secs(&self, secs: u64) {
        self.ttl_secs.store(secs, Ordering::Relaxed);
    }

    /// The active inactivity timeout in seconds (configured value, or the
    /// built-in default when unset/zero).
    fn ttl_secs(&self) -> u64 {
        let v = self.ttl_secs.load(Ordering::Relaxed);
        if v == 0 {
            SESSION_TTL.as_secs()
        } else {
            v
        }
    }

    fn save(&self) {
        if !self.persist {
            return;
        }
        // Serialize saves: take the snapshot AND write while holding write_lock,
        // so two concurrent saves can't reorder (a stale snapshot can't be the
        // last write). The snapshot is taken under this lock, so whichever save
        // writes last also reflects the freshest map.
        let _w = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let snapshot = self.map.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let _ = super::write_sessions(&snapshot);
    }

    pub(super) fn issue(&self, user: &str) -> String {
        let token = random_token();
        let key = token_key(&token);
        let now = now_secs();
        {
            let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
            // Opportunistically prune expired sessions.
            m.retain(|_, r| Self::record_live(r, now, self.ttl_secs()));
            m.insert(
                key,
                SessionRec {
                    user: user.to_string(),
                    last: now,
                    issued: now,
                },
            );
        }
        self.save();
        token
    }

    /// Resolve a token to its account, sliding the expiry. `None` when missing
    /// or expired. An active access refreshes the timestamp so an active user
    /// is never logged out mid-session — but the absolute lifetime cap
    /// ([`SESSION_ABS_TTL`]) still applies and is never extended.
    pub(super) fn identity(&self, token: &str) -> Option<String> {
        if token.is_empty() {
            return None;
        }
        let key = token_key(token);
        let now = now_secs();
        let mut persist = false;
        let user = {
            let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
            match m.get(&key).cloned() {
                Some(rec) if Self::record_live(&rec, now, self.ttl_secs()) => {
                    // Debounce disk writes: persist only every few minutes.
                    if now.saturating_sub(rec.last) >= 300 {
                        persist = true;
                    }
                    m.insert(
                        key,
                        SessionRec {
                            user: rec.user.clone(),
                            last: now,
                            issued: rec.issued, // absolute cap anchor is preserved
                        },
                    );
                    Some(rec.user)
                }
                _ => None,
            }
        };
        if persist {
            self.save();
        }
        user
    }

    pub(super) fn revoke(&self, token: &str) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&token_key(token));
        self.save();
    }

    pub(super) fn revoke_user(&self, user: &str, keep: Option<&str>) {
        let keep_key = keep.map(token_key);
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|tok, rec| rec.user != user || keep_key.as_deref() == Some(tok.as_str()));
        self.save();
    }

    pub(super) fn sweep(&self) {
        let now = now_secs();
        let changed = {
            let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
            let before = m.len();
            m.retain(|_, r| Self::record_live(r, now, self.ttl_secs()));
            m.len() != before
        };
        if changed {
            self.save();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(last: u64, issued: u64) -> SessionRec {
        SessionRec {
            user: "alice".into(),
            last,
            issued,
        }
    }

    #[test]
    fn absolute_lifetime_caps_active_session() {
        let now = 1_000_000_000u64;
        let ttl = SESSION_TTL.as_secs();
        // Fresh and active → live.
        assert!(SessionStore::record_live(&rec(now, now), now, ttl));
        // Active (just touched) but issued beyond the absolute cap → expired,
        // even though the sliding window alone would keep it.
        let old_issue = now - SESSION_ABS_TTL.as_secs() - 1;
        assert!(!SessionStore::record_live(&rec(now, old_issue), now, ttl));
        // Idle past the sliding window → expired regardless of issued.
        assert!(!SessionStore::record_live(
            &rec(now - ttl - 1, now),
            now,
            ttl
        ));
        // Legacy record (issued=0) ages out via the absolute cap.
        assert!(!SessionStore::record_live(&rec(now, 0), now, ttl));
    }

    #[test]
    fn issue_then_identity_roundtrips_under_caps() {
        let s = SessionStore::default();
        let t = s.issue("bob");
        assert_eq!(s.identity(&t).as_deref(), Some("bob"));
    }
}
