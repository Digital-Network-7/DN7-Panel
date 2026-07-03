//! A tiny embedded DNS responder — one per bridge network, bound to the network's
//! gateway IP (`<gateway>:53/udp`) in the host netns. It answers A queries for the
//! CONTAINER NAMES on that network (from the IPAM leases + container state), so
//! containers resolve each other by name — Docker's `127.0.0.11` equivalent — and
//! forwards everything else to the host's upstream resolvers.
//!
//! Reachable because the gateway IP lives on the bridge, so every container on the
//! network can send DNS to it. One responder per gateway; `ensure_running` is
//! idempotent, so it's safe to call from bridge-create + the boot reconcile.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::net::ipam::{Ipam, NetworkConfig};

fn running() -> &'static Mutex<HashSet<Ipv4Addr>> {
    static S: OnceLock<Mutex<HashSet<Ipv4Addr>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Start the responder for `cfg`'s gateway if one isn't already running.
pub fn ensure_running(cfg: &NetworkConfig) {
    let gw = cfg.gateway;
    if !running()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(gw)
    {
        return; // already running for this gateway
    }
    let net = cfg.name.clone();
    std::thread::spawn(move || {
        if serve(gw, &net).is_err() {
            // bind failed (port taken / iface gone) — clear the marker so a later
            // ensure_running retries.
            running()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&gw);
        }
    });
}

/// Ensure a responder is running for every known network (boot reconcile).
pub fn ensure_all() {
    for cfg in crate::net::registry::all() {
        ensure_running(&cfg);
    }
}

fn serve(gw: Ipv4Addr, net: &str) -> std::io::Result<()> {
    let sock = UdpSocket::bind(SocketAddr::from((gw, 53)))?;
    let mut buf = [0u8; 512];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let reply = handle(&buf[..n], net);
        let _ = sock.send_to(&reply, from);
    }
}

/// An A answer if the QNAME is a single-label container name on `net`, else the
/// forwarded upstream response (or SERVFAIL if forwarding fails).
fn handle(query: &[u8], net: &str) -> Vec<u8> {
    if let Some((qname, qtype)) = parse_question(query) {
        if qtype == 1 {
            if let Some(ip) = resolve_container(net, &qname) {
                return build_a_response(query, ip);
            }
        }
    }
    forward_upstream(query).unwrap_or_else(|| servfail(query))
}

/// Resolve a single-label name to a container IP on `net` (its display name or
/// hostname, case-insensitive). Multi-label / FQDN names go upstream.
fn resolve_container(net: &str, qname: &str) -> Option<Ipv4Addr> {
    let name = qname.trim_end_matches('.');
    if name.is_empty() || name.contains('.') {
        return None;
    }
    for lease in Ipam::new().leases(net) {
        if let Ok(s) = crate::container::state::State::load(&lease.container_id) {
            let hit = s
                .meta
                .name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
                || s.meta
                    .hostname
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(name));
            if hit {
                return Some(lease.ip);
            }
        }
    }
    None
}

/// Extract the first question's lowercased QNAME + QTYPE. `None` on a malformed
/// packet or no question.
fn parse_question(q: &[u8]) -> Option<(String, u16)> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) < 1 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || i + len > q.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&q[i..i + len]));
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((name.to_lowercase(), qtype))
}

/// End offset of the question section (after QNAME + QTYPE + QCLASS).
fn question_end(q: &[u8]) -> Option<usize> {
    let mut i = 12;
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        i += len;
    }
    Some(i + 4)
}

/// Build a single-A-record response echoing the query's question.
fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let qend = question_end(query).unwrap_or(query.len()).min(query.len());
    let mut r = query[..qend].to_vec();
    r[2] |= 0x80; // QR = response
    r[3] = 0x80; // RA set, RCODE 0
    r[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    r[8..12].copy_from_slice(&[0, 0, 0, 0]); // NSCOUNT = ARCOUNT = 0
                                             // Answer: name pointer to the question (0xC00C), type A, class IN, TTL 30,
                                             // RDLENGTH 4, then the IPv4 octets.
    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4]);
    r.extend_from_slice(&ip.octets());
    r
}

/// Forward the raw query to a host upstream and relay the first response.
fn forward_upstream(query: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    for up in super::dns::host_upstreams() {
        let Ok(addr) = up.parse::<Ipv4Addr>() else {
            continue;
        };
        if sock.send_to(query, SocketAddr::from((addr, 53))).is_ok() {
            let mut buf = [0u8; 512];
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                return Some(buf[..n].to_vec());
            }
        }
    }
    None
}

/// A minimal SERVFAIL echoing the query id, when upstream can't be reached.
fn servfail(query: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 12];
    let head = query.len().min(12);
    r[..head].copy_from_slice(&query[..head]);
    r[2] |= 0x80; // QR
    r[3] = 0x82; // SERVFAIL
    r[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // keep QDCOUNT=1, no answers
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_for(name: &str) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        q
    }

    #[test]
    fn parses_and_builds() {
        let q = query_for("web");
        assert_eq!(parse_question(&q), Some(("web".to_string(), 1)));
        let r = build_a_response(&q, "172.18.0.5".parse().unwrap());
        // response bit set, one answer, and the ip is at the tail
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1);
        assert_eq!(&r[r.len() - 4..], &[172, 18, 0, 5]);
        // transaction id preserved
        assert_eq!(&r[0..2], &[0x12, 0x34]);
    }
}
