//! Per-source login rate limiter (split from auth.rs).
use super::{FAIL_MAX, FAIL_WINDOW};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
pub(super) struct RateLimiter {
    map: Mutex<HashMap<String, Vec<Instant>>>, // source -> failure times
}

impl RateLimiter {
    pub(super) fn allowed(&self, source: &str) -> bool {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let entry = m.entry(source.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) <= FAIL_WINDOW);
        entry.len() < FAIL_MAX
    }

    pub(super) fn record(&self, source: &str) {
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let entry = m.entry(source.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) <= FAIL_WINDOW);
        entry.push(now);
    }

    pub(super) fn clear(&self, source: &str) {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(source);
    }

    pub(super) fn sweep(&self) {
        let now = Instant::now();
        let mut m = self.map.lock().unwrap_or_else(|p| p.into_inner());
        m.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) <= FAIL_WINDOW);
            !v.is_empty()
        });
    }
}
