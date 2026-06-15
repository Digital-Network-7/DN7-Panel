//! Single-use login-challenge nonce store (split from auth.rs).
use super::{random_token, CHALLENGE_TTL, MAX_CHALLENGES};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
pub(super) struct ChallengeStore {
    map: Mutex<HashMap<String, Instant>>, // nonce -> issued
}

impl ChallengeStore {
    pub(super) fn issue(&self) -> String {
        let nonce = random_token();
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        m.retain(|_, t| now.duration_since(*t) <= CHALLENGE_TTL);
        // Bound memory: if still at the cap after pruning expired nonces, evict
        // the oldest ones so a flood of the public endpoint can't grow the map
        // without limit.
        while m.len() >= MAX_CHALLENGES {
            let Some(oldest) = m.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) else {
                break;
            };
            m.remove(&oldest);
        }
        m.insert(nonce.clone(), now);
        nonce
    }

    pub(super) fn consume(&self, nonce: &str) -> bool {
        if nonce.is_empty() {
            return false;
        }
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        match m.remove(nonce) {
            Some(t) => Instant::now().duration_since(t) <= CHALLENGE_TTL,
            None => false,
        }
    }

    pub(super) fn sweep(&self) {
        let now = Instant::now();
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, t| now.duration_since(*t) <= CHALLENGE_TTL);
    }
}
