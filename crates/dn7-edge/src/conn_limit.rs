//! Per-IP CONCURRENT in-flight request limit for the edge (the "高级功能"
//! connection-limit knob) — the in-process equivalent of nginx's
//! `limit_conn`/`limit_conn_zone`.
//!
//! Unlike [`super::limit`] (a rate over TIME), this bounds how many requests a
//! single client IP may have in flight at ONCE. State lives HERE (process-global,
//! not on the Arc'd `RuntimeConfig`, which is replaced wholesale on every reload
//! and would otherwise reset the live counts mid-flight). Keyed by
//! `(hash(route.id), canonical IP)`, mirroring [`super::limit`]'s key; IPv6
//! collapses to its /64 so a client can't trivially rotate within their prefix.
//!
//! Admission is RAII: [`acquire`] bumps the count and hands back a [`ConnGuard`]
//! whose `Drop` decrements it. The router holds the guard for the whole request —
//! it is threaded into the response body (see [`super::router`]) so it lives until
//! the body is fully drained (request completion), then releases the slot. An
//! entry that falls to zero is removed, so the table self-bounds (no sweeper).
//! Loopback is exempt (the caller skips it), and a limit of 0 = unlimited.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use super::response::{boxed, ResBody};

/// `(hash(route.id), canonical-ip)` — the same key shape as [`super::limit`], so
/// the two "高级功能" trackers partition a client the same way. Hashing the id
/// keeps the key `Copy` (no per-request allocation); a hash collision would only
/// merge two routes' counts for one IP — harmless and astronomically rare.
type Key = (u64, [u8; 16]);

fn table() -> &'static Mutex<HashMap<Key, u32>> {
    static T: OnceLock<Mutex<HashMap<Key, u32>>> = OnceLock::new();
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

/// RAII slot in the per-IP concurrency count: holds one unit of the `(route, ip)`
/// count for its lifetime and releases it on `Drop` (request completion). The
/// router threads it into the response body so the slot stays held until the body
/// is fully drained, not just until the handler returns.
pub(crate) struct ConnGuard {
    key: Key,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = t.get_mut(&self.key) {
            *n -= 1;
            // Drop the entry once it hits zero so the table self-bounds — an idle
            // client leaves no residue (no separate sweeper needed).
            if *n == 0 {
                t.remove(&self.key);
            }
        }
    }
}

/// Try to admit one more concurrent request from `ip` to route `id`, allowing at
/// most `max` in flight at once. `Some(guard)` admits (the slot is held until the
/// guard drops); `None` means the limit is already reached — reject with 503. The
/// caller only invokes this when `max > 0` (0 = unlimited, checked before the
/// call), so a `None` here is unambiguously "at capacity". O(1), one brief lock.
pub(crate) fn acquire(id: &str, ip: IpAddr, max: u32) -> Option<ConnGuard> {
    let k = key(id, ip);
    let mut t = table().lock().unwrap_or_else(|e| e.into_inner());
    let n = t.entry(k).or_insert(0);
    if *n >= max {
        // At capacity. Don't leave a freshly-created zero entry behind (the
        // `Drop` cleanup only fires for slots we actually handed out).
        if *n == 0 {
            t.remove(&k);
        }
        return None;
    }
    *n += 1;
    Some(ConnGuard { key: k })
}

/// A response body that carries a [`ConnGuard`] alongside the real body, so the
/// per-IP concurrency slot stays held until the body is fully streamed to the
/// client (or the body is dropped). This is what makes the guard's lifetime match
/// *request completion* rather than merely the handler returning — a slow reader
/// keeps occupying its one slot, exactly as nginx's `limit_conn` does.
struct GuardedBody {
    inner: ResBody,
    // Held for its `Drop` side effect (releases the slot); never read.
    _guard: ConnGuard,
}

impl Body for GuardedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        // `GuardedBody` is `Unpin` (UnsyncBoxBody + a plain guard field).
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Wrap `body` so it keeps `guard`'s per-IP concurrency slot held until the body
/// is fully drained (or dropped). A pure pass-through otherwise.
pub(crate) fn guard_body(body: ResBody, guard: ConnGuard) -> ResBody {
    boxed(GuardedBody {
        inner: body,
        _guard: guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn admits_up_to_max_then_rejects_and_releases_on_drop() {
        // max 2 concurrent: two acquires succeed, the 3rd is rejected while both
        // guards are alive. Dropping one frees a slot; a fresh acquire succeeds.
        let id = "site-conn";
        let who = ip("203.0.113.20");

        let g1 = acquire(id, who, 2).expect("1st in-flight admitted");
        let g2 = acquire(id, who, 2).expect("2nd in-flight admitted");
        assert!(
            acquire(id, who, 2).is_none(),
            "the (N+1)th concurrent request is rejected while N are in flight"
        );

        // Releasing one (request completes) frees exactly one slot.
        drop(g1);
        let g3 = acquire(id, who, 2).expect("a freed slot admits the next request");
        assert!(
            acquire(id, who, 2).is_none(),
            "still capped at max after the replacement acquire"
        );

        // Once everything drops, the entry is removed (self-bounding table).
        drop(g2);
        drop(g3);
        assert!(
            !table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&key(id, who)),
            "the entry is pruned once its count returns to zero"
        );
    }

    #[test]
    fn distinct_ips_and_routes_do_not_share_a_slot() {
        // A max-1 limit is per (route, IP): a second IP, or the same IP on another
        // route, gets its own independent slot.
        let a = ip("198.51.100.30");
        let b = ip("198.51.100.31");
        let _g_a = acquire("r1", a, 1).expect("IP a admitted on r1");
        assert!(acquire("r1", a, 1).is_none(), "IP a is capped on r1");
        let _g_b = acquire("r1", b, 1).expect("a different IP has its own slot");
        let _g_a2 = acquire("r2", a, 1).expect("the same IP on another route is independent");
    }

    #[test]
    fn ipv6_is_keyed_by_64_prefix() {
        // Two addresses in the same /64 share one slot (parity with `limit`).
        let id = "site-conn-v6";
        let _g = acquire(id, ip("2001:db8:9:9::1"), 1).expect("first v6 admitted");
        assert!(
            acquire(id, ip("2001:db8:9:9::abcd"), 1).is_none(),
            "a sibling address in the same /64 shares the slot"
        );
    }
}
