//! Bridge / veth / netns plumbing via **pure-Rust synchronous rtnetlink** (see
//! [`crate::net::nl`]) — the in-process replacement for shelling out to `ip`
//! (iproute2). Host-side links (bridge, veth, master, move) are configured on a
//! host-netns netlink socket; the container's `eth0`/`lo`/route are configured by
//! entering its netns (`with_netns`, by pid) — no transient named netns needed.

use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::net::ipam::NetworkConfig;
use crate::net::nl::{self, NlSock};

/// Create/ensure the host bridge with its gateway IP and bring it up. Idempotent.
pub fn ensure_bridge(cfg: &NetworkConfig) -> Result<()> {
    let mut sock = NlSock::open()?;
    sock.add_bridge(&cfg.bridge)?;
    let idx = nl::if_index(&cfg.bridge)?;
    sock.add_addr(idx, cfg.gateway, cfg.subnet.prefix_len())?;
    sock.set_up(idx)
}

/// Create a veth pair (`host` end stays on the host, `peer` is moved into the
/// container).
pub fn make_veth(host: &str, peer: &str) -> Result<()> {
    NlSock::open()?.add_veth(host, peer)
}

/// Attach the host veth end to the bridge and bring it up.
pub fn attach_to_bridge(host: &str, bridge: &str) -> Result<()> {
    let mut sock = NlSock::open()?;
    let h = nl::if_index(host)?;
    let b = nl::if_index(bridge)?;
    sock.set_master(h, b)?;
    sock.set_up(h)
}

/// Move the peer veth end into the container's netns (by pid).
pub fn move_peer(peer: &str, pid: i32) -> Result<()> {
    let mut sock = NlSock::open()?;
    let idx = nl::if_index(peer)?; // still in the host netns at this point
    sock.move_to_netns_pid(idx, pid)
}

/// Configure the moved peer inside the container netns: rename to `eth0`, set the
/// MAC + address, bring `eth0` and `lo` up, add a default route via the gateway.
#[allow(clippy::too_many_arguments)]
pub fn config_inside(
    pid: i32,
    peer: &str,
    ip_addr: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    mac: &str,
) -> Result<()> {
    let mac = parse_mac(mac)?;
    nl::with_netns(pid, |sock| {
        // The index is stable across rename, so resolve once and reuse it.
        let idx = nl::if_index(peer)?;
        sock.set_name(idx, "eth0")?;
        sock.set_mac(idx, &mac)?;
        sock.add_addr(idx, ip_addr, prefix)?;
        sock.set_up(idx)?;
        let lo = nl::if_index("lo")?;
        sock.set_up(lo)?;
        sock.add_default_route(gateway)
    })
}

/// Bring `lo` up inside the netns (None mode — isolation, but a working loopback).
pub fn lo_up(pid: i32) -> Result<()> {
    nl::with_netns(pid, |sock| {
        let lo = nl::if_index("lo")?;
        sock.set_up(lo)
    })
}

/// Remove the host veth end. Its container peer is auto-removed by the kernel
/// when the container netns dies, so an already-gone link is not an error.
pub fn teardown_veth(host: &str) -> Result<()> {
    let mut sock = NlSock::open()?;
    match nl::if_index(host) {
        Ok(idx) => sock.del_link(idx),
        Err(_) => Ok(()), // already gone
    }
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC into 6 bytes.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::Other(format!("bad mac: {s}")));
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|_| Error::Other(format!("bad mac: {s}")))?;
    }
    Ok(out)
}
