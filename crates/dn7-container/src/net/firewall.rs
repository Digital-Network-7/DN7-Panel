//! nftables rules via the in-process pure-Rust [`super::nft`] netlink encoder (no
//! `nft` binary, no C library, no GPL/bindgen `rustables`). All rules live in our
//! own dedicated `table inet dn7`, so we never touch the host's existing tables
//! and teardown is a single `delete table inet dn7`. Outbound masquerade +
//! forwarding for the subnet and per-container published-port DNAT, tagged with a
//! `dn7:<id>` rule comment (nft userdata) for clean removal.

use std::net::{IpAddr, Ipv4Addr};

use crate::error::{Error, Result};
use crate::net::config::{PortMap, Proto};
use crate::net::ipam::NetworkConfig;
use crate::net::nft::{self, exprs};

const TABLE: &str = "dn7";

/// The nat priorities (NF_IP_PRI_*), as nft uses for `srcnat`/`dstnat`.
const PRI_SRCNAT: i32 = 100;
const PRI_DSTNAT: i32 = -100;

/// IPv4 header offsets (network base): source/destination address, 4 bytes each.
const IP_SADDR_OFF: u32 = 12;
const IP_DADDR_OFF: u32 = 16;
/// TCP/UDP destination-port offset in the transport header (2 bytes).
const TH_DPORT_OFF: u32 = 2;

fn proto_num(p: Proto) -> u8 {
    match p {
        Proto::Tcp => 6,  // IPPROTO_TCP
        Proto::Udp => 17, // IPPROTO_UDP
    }
}

/// `meta nfproto ipv4` guard — the `ip ...` matches below read IPv4 payload,
/// only valid for v4 packets in an `inet` table.
fn nfproto_ipv4() -> Vec<Vec<u8>> {
    vec![
        exprs::meta_load(nft::NFT_META_NFPROTO, nft::NFT_REG_1),
        exprs::cmp(nft::NFT_REG_1, nft::NFT_CMP_EQ, &[nft::NFPROTO_IPV4 as u8]),
    ]
}

/// `ip {saddr,daddr} {==,!=} net/mask` (payload load + subnet mask + compare).
fn match_subnet(source: bool, eq: bool, net: Ipv4Addr, mask: Ipv4Addr) -> Vec<Vec<u8>> {
    let offset = if source { IP_SADDR_OFF } else { IP_DADDR_OFF };
    let op = if eq {
        nft::NFT_CMP_EQ
    } else {
        nft::NFT_CMP_NEQ
    };
    vec![
        exprs::payload_load(nft::NFT_PAYLOAD_NETWORK_HEADER, offset, 4, nft::NFT_REG_1),
        exprs::bitwise(nft::NFT_REG_1, nft::NFT_REG_1, 4, &mask.octets(), &[0u8; 4]),
        exprs::cmp(nft::NFT_REG_1, op, &net.octets()),
    ]
}

/// `ip daddr == addr` (with the nfproto guard).
fn daddr_eq(addr: Ipv4Addr) -> Vec<Vec<u8>> {
    let mut e = nfproto_ipv4();
    e.push(exprs::payload_load(
        nft::NFT_PAYLOAD_NETWORK_HEADER,
        IP_DADDR_OFF,
        4,
        nft::NFT_REG_1,
    ));
    e.push(exprs::cmp(nft::NFT_REG_1, nft::NFT_CMP_EQ, &addr.octets()));
    e
}

/// `<proto> dport == port` — l4proto guard then transport-header dport compare.
fn l4_dport(proto: Proto, port: u16) -> Vec<Vec<u8>> {
    vec![
        exprs::meta_load(nft::NFT_META_L4PROTO, nft::NFT_REG_1),
        exprs::cmp(nft::NFT_REG_1, nft::NFT_CMP_EQ, &[proto_num(proto)]),
        exprs::payload_load(
            nft::NFT_PAYLOAD_TRANSPORT_HEADER,
            TH_DPORT_OFF,
            2,
            nft::NFT_REG_1,
        ),
        exprs::cmp(nft::NFT_REG_1, nft::NFT_CMP_EQ, &port.to_be_bytes()),
    ]
}

/// DNAT the matched packet to `ip:port` (load both into registers, then `nat`).
fn dnat(ip: Ipv4Addr, port: u16) -> Vec<Vec<u8>> {
    vec![
        exprs::immediate_data(nft::NFT_REG_1, &ip.octets()),
        exprs::immediate_data(nft::NFT_REG_2, &port.to_be_bytes()),
        exprs::nat_dnat(nft::NFPROTO_IPV4, nft::NFT_REG_1, nft::NFT_REG_2),
    ]
}

/// `<iifname|oifname> == name accept`'s match half (meta iface-name load + cmp).
fn iface(key: u32, name: &str) -> Vec<Vec<u8>> {
    // The register holds the NUL-terminated name; comparing name+NUL is an exact
    // match (a longer name differs in the first name.len()+1 bytes).
    let mut val = name.as_bytes().to_vec();
    val.push(0);
    vec![
        exprs::meta_load(key, nft::NFT_REG_1),
        exprs::cmp(nft::NFT_REG_1, nft::NFT_CMP_EQ, &val),
    ]
}

/// libnftnl rule-comment userdata (TLV: type=COMMENT(0), len incl NUL,
/// NUL-terminated value). Used both to tag our rules and to match them on
/// teardown — `nft list ruleset` shows it as `comment "dn7:<id>"`.
fn comment_udata(id: &str) -> Vec<u8> {
    let s = format!("dn7:{id}");
    let mut v = vec![0u8, (s.len() + 1) as u8];
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

/// Extract the v4 host IP to scope a published port to, or `None` (wildcard) for
/// an unspecified or IPv6 host address (DNAT here is IPv4-only).
fn host_v4(host: IpAddr) -> Option<Ipv4Addr> {
    match host {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// Whether the nftables netlink subsystem is usable (kernel support + perms).
pub fn have_nft() -> bool {
    nft::have_nft()
}

/// Does `table inet dn7` already exist? (idempotency — base rules are static.)
fn base_present() -> bool {
    nft::table_present(TABLE)
}

/// Ensure the base table/chains/rules exist (postrouting masquerade, forward
/// accept, and empty prerouting/output dstnat chains for published ports), and
/// enable IPv4 forwarding. Idempotent: skips the build when our table is present
/// (so the per-container DNAT rules in prerouting/output are never disturbed).
pub fn ensure_base(cfg: &NetworkConfig) -> Result<()> {
    enable_ip_forward()?;
    // Let 127.0.0.0/8-sourced packets (a `curl localhost:port` DNAT'd to the
    // container) route out the bridge instead of being dropped as martian.
    let rl = format!("/proc/sys/net/ipv4/conf/{}/route_localnet", cfg.bridge);
    let _ = std::fs::write(&rl, "1");

    if base_present() {
        return Ok(());
    }

    let net = cfg.subnet.network();
    let mask = cfg.subnet.netmask();

    let mut b = nft::Batch::new();
    b.add_table(TABLE);
    b.add_chain(
        TABLE,
        "postrouting",
        nft::NF_INET_POST_ROUTING,
        PRI_SRCNAT,
        "nat",
        nft::NF_ACCEPT,
    );
    b.add_chain(
        TABLE,
        "forward",
        nft::NF_INET_FORWARD,
        0,
        "filter",
        nft::NF_ACCEPT,
    );
    b.add_chain(
        TABLE,
        "prerouting",
        nft::NF_INET_PRE_ROUTING,
        PRI_DSTNAT,
        "nat",
        nft::NF_ACCEPT,
    );
    b.add_chain(
        TABLE,
        "output",
        nft::NF_INET_LOCAL_OUT,
        PRI_DSTNAT,
        "nat",
        nft::NF_ACCEPT,
    );

    // Outbound masquerade: subnet -> non-subnet, and non-subnet -> subnet.
    let mut masq1 = nfproto_ipv4();
    masq1.extend(match_subnet(true, true, net, mask));
    masq1.extend(match_subnet(false, false, net, mask));
    masq1.push(exprs::masquerade());
    b.add_rule(TABLE, "postrouting", &masq1, None);

    let mut masq2 = nfproto_ipv4();
    masq2.extend(match_subnet(true, false, net, mask));
    masq2.extend(match_subnet(false, true, net, mask));
    masq2.push(exprs::masquerade());
    b.add_rule(TABLE, "postrouting", &masq2, None);

    // Forward accept for anything in/out the bridge.
    let mut fwd_in = iface(nft::NFT_META_IIFNAME, &cfg.bridge);
    fwd_in.push(exprs::immediate_verdict(nft::NF_ACCEPT));
    b.add_rule(TABLE, "forward", &fwd_in, None);

    let mut fwd_out = iface(nft::NFT_META_OIFNAME, &cfg.bridge);
    fwd_out.push(exprs::immediate_verdict(nft::NF_ACCEPT));
    b.add_rule(TABLE, "forward", &fwd_out, None);

    b.send()
}

/// Publish one port: DNAT `host[:ip]:hostport` → `container_ip:containerport` in
/// the prerouting chain (external traffic) and the output chain (host-local). Each
/// rule is tagged with a `dn7:<id>` comment for teardown.
pub fn publish_port(id: &str, p: &PortMap, container_ip: Ipv4Addr) -> Result<()> {
    let host = host_v4(p.host_ip);
    let udata = comment_udata(id);

    // External path: optionally scope to a specific host IP.
    let mut pre = Vec::new();
    if let Some(v4) = host {
        pre.extend(daddr_eq(v4));
    }
    pre.extend(l4_dport(p.proto, p.host_port));
    pre.extend(dnat(container_ip, p.container_port));

    // Host-local path: a specific host IP, else loopback (covers `curl
    // localhost:port` — we have no `fib daddr type local`).
    let mut out = Vec::new();
    if let Some(v4) = host {
        out.extend(daddr_eq(v4));
    } else {
        out.extend(nfproto_ipv4());
        out.extend(match_subnet(
            false,
            true,
            Ipv4Addr::new(127, 0, 0, 0),
            Ipv4Addr::new(255, 0, 0, 0),
        ));
    }
    out.extend(l4_dport(p.proto, p.host_port));
    out.extend(dnat(container_ip, p.container_port));

    let mut b = nft::Batch::new();
    b.add_rule(TABLE, "prerouting", &pre, Some(&udata));
    b.add_rule(TABLE, "output", &out, Some(&udata));
    b.send()
}

/// Remove every rule tagged `dn7:<id>` (the container's published-port DNAT).
/// Idempotent; tolerates a missing table.
pub fn teardown_container(id: &str) -> Result<()> {
    if !base_present() {
        return Ok(());
    }
    let want = comment_udata(id);
    let mut b = nft::Batch::new();
    let mut any = false;
    for chain in ["prerouting", "output"] {
        for (handle, udata) in nft::list_rules(TABLE, chain)? {
            if udata == want {
                b.del_rule(TABLE, chain, handle);
                any = true;
            }
        }
    }
    if any {
        b.send()?;
    }
    Ok(())
}

/// Remove the entire dn7 table (used by `net gc`). Tolerates an absent table.
pub fn nuke_table() -> Result<()> {
    if !base_present() {
        return Ok(());
    }
    let mut b = nft::Batch::new();
    b.del_table(TABLE);
    b.send()
}

fn enable_ip_forward() -> Result<()> {
    // Record-but-don't-reset: other software may rely on forwarding, so we never
    // turn it back off on teardown.
    let p = "/proc/sys/net/ipv4/ip_forward";
    std::fs::write(p, "1").map_err(Error::io(p))
}
