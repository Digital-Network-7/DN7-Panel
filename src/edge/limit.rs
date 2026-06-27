//! Per-IP request rate limiting + auto-ban for the edge (the "高级功能" knobs).
//!
//! State lives HERE (process-global), NOT on the Arc'd `RuntimeConfig` — that is
//! replaced wholesale on every reload, which would otherwise reset everyone's
//! counters mid-flight. Keyed by `(route, client IP)`; IPv6 collapses to its /64
//! so a single user can't trivially rotate addresses within their prefix.
//! Loopback is exempt (the caller skips it). Idle entries are swept to bound
//! memory.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::config::RateLimit;

/// The verdict for one checked request.
pub(crate) enum Verdict {
    Allow,
    RateLimited,
    Banned,
}

/// Per `(route, ip)` state: a request token bucket + a sliding violation counter
/// that feeds the auto-ban.
struct St {
    tokens: f64,
    last: Instant,
    violations: u32,
    vwindow: Instant,
    banned_until: Option<Instant>,
}

/// `(hash(route.id), canonical-ip)`. Hashing the id keeps the key `Copy` (no
/// per-request allocation); a hash collision would only merge two routes' limits
/// for one IP — harmless and astronomically rare.
type Key = (u64, [u8; 16]);

fn table() -> &'static Mutex<HashMap<Key, St>> {
    static T: OnceLock<Mutex<HashMap<Key, St>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(HashMap::new()))
}

fn route_hash(id: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut h);
    h.finish()
}

/// Canonicalize the key IP: IPv4 as-is, IPv6 → its /64 prefix (high 8 bytes).
fn key(id: &str, ip: IpAddr) -> Key {
    let mut ipk = [0u8; 16];
    match ip {
        IpAddr::V4(a) => ipk[12..].copy_from_slice(&a.octets()),
        IpAddr::V6(a) => ipk[..8].copy_from_slice(&a.octets()[..8]),
    }
    (route_hash(id), ipk)
}

/// Check + record one request from `ip` to route `id` under `rl`. Consumes a
/// rate-limit token when one is configured; a rate-limit miss is a violation
/// that may trip the auto-ban. O(1), one brief lock.
pub(crate) fn check(id: &str, ip: IpAddr, rl: &RateLimit) -> Verdict {
    // With no rate limit there's nothing to enforce and no way to accrue a ban
    // (violations only come from rate-limit misses), so skip the lock entirely.
    if rl.req_per_sec == 0 {
        return Verdict::Allow;
    }
    let now = Instant::now();
    let cap = (rl.req_per_sec + rl.burst) as f64;
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    let st = t.entry(key(id, ip)).or_insert_with(|| St {
        tokens: cap,
        last: now,
        violations: 0,
        vwindow: now,
        banned_until: None,
    });

    // An active ban drops everything until it expires.
    if let Some(until) = st.banned_until {
        if now < until {
            return Verdict::Banned;
        }
        // Expired: clear the ban and give a fresh bucket.
        st.banned_until = None;
        st.violations = 0;
        st.tokens = cap;
        st.last = now;
    }

    // Token bucket: refill by elapsed × rate (capped at the burst ceiling).
    st.tokens =
        (st.tokens + now.duration_since(st.last).as_secs_f64() * rl.req_per_sec as f64).min(cap);
    st.last = now;
    if st.tokens >= 1.0 {
        st.tokens -= 1.0;
        return Verdict::Allow;
    }
    // Over the limit → a violation, which may trip the auto-ban.
    if record_violation(st, now, rl) {
        Verdict::Banned
    } else {
        Verdict::RateLimited
    }
}

/// Record a violation in the sliding window; returns true if it tripped a ban.
fn record_violation(st: &mut St, now: Instant, rl: &RateLimit) -> bool {
    if rl.autoban_threshold == 0 {
        return false;
    }
    let window = Duration::from_secs(rl.autoban_window.max(1) as u64);
    if now.duration_since(st.vwindow) > window {
        st.violations = 1;
        st.vwindow = now;
    } else {
        st.violations += 1;
    }
    if st.violations >= rl.autoban_threshold {
        st.banned_until = Some(now + Duration::from_secs(rl.autoban_minutes.max(1) as u64 * 60));
        return true;
    }
    false
}

/// Spawn the idle-entry sweeper once (bounds memory: drop entries with no recent
/// activity and no active ban). Idempotent — safe to call from every `spawn()`.
pub(crate) fn start_sweeper() {
    static ONCE: OnceLock<()> = OnceLock::new();
    if ONCE.set(()).is_err() {
        return;
    }
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = Instant::now();
            table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, st| {
                    st.banned_until.is_some_and(|u| now < u)
                        || now.duration_since(st.last) < Duration::from_secs(300)
                });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(rps: u32, burst: u32, thresh: u32, window: u32, minutes: u32) -> RateLimit {
        RateLimit {
            req_per_sec: rps,
            burst,
            autoban_threshold: thresh,
            autoban_window: window,
            autoban_minutes: minutes,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_within_burst_then_limits() {
        // rps 1, burst 2 → capacity 3: first 3 immediate requests pass, 4th is
        // rate-limited (no time to refill).
        let r = rl(1, 2, 0, 0, 0);
        let id = "site-burst";
        let who = ip("203.0.113.10");
        let mut allowed = 0;
        for _ in 0..3 {
            if matches!(check(id, who, &r), Verdict::Allow) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3, "the full burst passes");
        assert!(matches!(check(id, who, &r), Verdict::RateLimited));
    }

    #[test]
    fn zero_rps_is_unlimited() {
        let r = rl(0, 0, 5, 10, 5);
        let who = ip("203.0.113.11");
        for _ in 0..50 {
            assert!(matches!(check("site-off", who, &r), Verdict::Allow));
        }
    }

    #[test]
    fn auto_ban_trips_after_threshold_violations() {
        // rps 1 burst 0 → capacity 1: 1 passes, then every extra is a violation.
        // threshold 3 → the 3rd violation bans; subsequent requests are Banned.
        let r = rl(1, 0, 3, 60, 10);
        let id = "site-ban";
        let who = ip("198.51.100.5");
        assert!(matches!(check(id, who, &r), Verdict::Allow));
        assert!(matches!(check(id, who, &r), Verdict::RateLimited)); // v1
        assert!(matches!(check(id, who, &r), Verdict::RateLimited)); // v2
        assert!(matches!(check(id, who, &r), Verdict::Banned)); // v3 trips the ban
        assert!(matches!(check(id, who, &r), Verdict::Banned)); // stays banned
    }

    #[test]
    fn ipv6_is_keyed_by_64_prefix() {
        // Two addresses in the same /64 share one bucket (capacity 1).
        let r = rl(1, 0, 0, 0, 0);
        let id = "site-v6";
        assert!(matches!(
            check(id, ip("2001:db8:1:2::1"), &r),
            Verdict::Allow
        ));
        assert!(matches!(
            check(id, ip("2001:db8:1:2::9999"), &r),
            Verdict::RateLimited
        ));
    }
}
