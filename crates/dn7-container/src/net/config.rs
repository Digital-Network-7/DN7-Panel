//! Networking identifiers, port maps, and deterministic name/MAC derivation.
//! All interface names and firewall comments are derived from `sha256(id)` — never
//! from the raw id — so a crafted container id can't inject into `ip`/`nft` args.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Validate a container id used to derive interface names / firewall comments:
/// `[a-z0-9][a-z0-9_.-]{0,63}`.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = (1..=64).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Other(format!(
            "invalid container id for networking: {id:?}"
        )))
    }
}

/// Host-side veth name for a container: `dn7v` + 8 hex of `sha256(id)` (12 bytes,
/// within Linux's 15-char interface-name limit).
pub fn veth_host_name(id: &str) -> String {
    format!("dn7v{}", &hex_sha(id)[..8])
}

/// The temporary peer-end name before it's renamed to `eth0` inside the netns.
pub fn veth_peer_name(id: &str) -> String {
    format!("dn7p{}", &hex_sha(id)[..8])
}

/// Host-side veth name for a container's SECONDARY attachment to `net` (docker
/// `network connect`) — keyed by `(id, net)` so it can't collide with the
/// primary veth or another attachment.
pub fn veth_host_name_for(id: &str, net: &str) -> String {
    format!("dn7v{}", &hex_sha(&format!("{id}\u{0}{net}"))[..8])
}

/// Peer-end name for a secondary attachment (renamed to `ethN` inside the netns).
pub fn veth_peer_name_for(id: &str, net: &str) -> String {
    format!("dn7p{}", &hex_sha(&format!("{id}\u{0}{net}"))[..8])
}

/// Lowercase hex of `sha256(s)`.
fn hex_sha(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Deterministic MAC for an IPv4 — Docker's scheme: `02:42:<the four IP octets>`.
/// The `02` low bits mark it locally-administered + unicast.
pub fn mac_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:42:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

/// Whether `s` is a well-formed MAC address (six colon-separated hex octets).
pub fn is_valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_nft(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Parse a `dn7.ports` value: comma-separated `[hostip:]hostport:containerport[/proto]`
/// (proto defaults to tcp, host ip to 0.0.0.0).
pub fn parse_ports(spec: &str) -> Result<Vec<PortMap>> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_one_port)
        .collect()
}

fn parse_one_port(s: &str) -> Result<PortMap> {
    let (addr_part, proto) = match s.rsplit_once('/') {
        Some((a, p)) => (a, parse_proto(p)?),
        None => (s, Proto::Tcp),
    };
    // Docker's bracketed-IPv6 form: name the limitation instead of the generic
    // "bad port spec" (dn7's DNAT is IPv4-only).
    if addr_part.starts_with('[') {
        return Err(Error::Other(format!(
            "IPv6 host addresses are not supported in port mappings ({s:?}); DNAT is IPv4-only"
        )));
    }
    let parts: Vec<&str> = addr_part.split(':').collect();
    let (host_ip, hp, cp) = match parts.as_slice() {
        [hp, cp] => (IpAddr::from([0, 0, 0, 0]), *hp, *cp),
        [ip, hp, cp] => (
            ip.parse::<IpAddr>()
                .map_err(|_| Error::Other(format!("bad host ip in port spec {s:?}")))?,
            *hp,
            *cp,
        ),
        _ => return Err(Error::Other(format!("bad port spec {s:?}"))),
    };
    Ok(PortMap {
        host_ip,
        host_port: hp
            .parse()
            .map_err(|_| Error::Other(format!("bad host port {hp:?}")))?,
        container_port: cp
            .parse()
            .map_err(|_| Error::Other(format!("bad container port {cp:?}")))?,
        proto,
    })
}

fn parse_proto(p: &str) -> Result<Proto> {
    match p.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        other => Err(Error::Other(format!("bad proto {other:?}"))),
    }
}

/// A published port: `host_ip:host_port` → `container_port`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMap {
    pub host_ip: IpAddr,
    pub host_port: u16,
    pub container_port: u16,
    pub proto: Proto,
}

/// The persisted networking receipt for a container (also mirrored to
/// `network.json` so reconciliation survives a torn `state.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetState {
    /// `"bridge"` | `"host"` | `"none"`.
    pub mode: String,
    pub network: String,
    pub bridge: String,
    pub veth_host: String,
    pub ip: Option<Ipv4Addr>,
    pub mac: Option<String>,
    #[serde(default)]
    pub ports: Vec<PortMap>,
    /// Secondary network attachments (docker `network connect`): additional
    /// interfaces (`eth1`, `eth2`, …) beyond the primary `eth0`.
    #[serde(default)]
    pub extra: Vec<Attachment>,
}

/// A secondary network attachment: a container joined to an ADDITIONAL network
/// beyond its primary, with its own veth pair, interface, and IP lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub network: String,
    pub bridge: String,
    pub veth_host: String,
    /// In-container interface name (`eth1`, `eth2`, …).
    pub ifname: String,
    pub ip: Ipv4Addr,
    pub mac: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation() {
        assert!(validate_id("web").is_ok());
        assert!(validate_id("smoke-cy.1_2").is_ok());
        assert!(validate_id("9lives").is_ok());
        assert!(validate_id("").is_err());
        assert!(validate_id("-bad").is_err()); // can't start with '-'
        assert!(validate_id("Bad").is_err()); // uppercase
        assert!(validate_id("a b").is_err()); // space
        assert!(validate_id("x/y").is_err()); // slash (path/arg injection)
        assert!(validate_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn veth_name_is_deterministic_and_short() {
        let n = veth_host_name("web");
        assert!(n.starts_with("dn7v"));
        assert_eq!(n.len(), 12);
        assert!(n.len() <= 15, "must fit IFNAMSIZ");
        assert_eq!(n, veth_host_name("web")); // stable
        assert_ne!(n, veth_host_name("web2")); // distinct
    }

    #[test]
    fn mac_matches_docker_scheme() {
        assert_eq!(mac_for(Ipv4Addr::new(172, 18, 0, 2)), "02:42:ac:12:00:02");
        assert_eq!(mac_for(Ipv4Addr::new(10, 0, 0, 5)), "02:42:0a:00:00:05");
    }

    #[test]
    fn parse_ports_forms() {
        let p = parse_ports("8080:80").unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].host_ip, IpAddr::from([0, 0, 0, 0]));
        assert_eq!(p[0].host_port, 8080);
        assert_eq!(p[0].container_port, 80);
        assert_eq!(p[0].proto, Proto::Tcp);

        let p = parse_ports("127.0.0.1:5353:53/udp, 443:443").unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].host_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p[0].proto, Proto::Udp);
        assert_eq!(p[1].host_port, 443);

        assert!(parse_ports("").unwrap().is_empty());
        assert!(parse_ports("notaport").is_err());
        assert!(parse_ports("80:80/sctp").is_err());
    }
}
