//! Host address discovery for the launch banner + first-run wizard: the primary
//! LAN (internal) IP and a best-effort public IP. std-only (no TLS, no async
//! runtime), so it is safe to call before the supervisor daemonizes. Used only at
//! init/banner time — never in the resident serving loop.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// The host's primary outbound (LAN) IP via the standard UDP-connect trick:
/// connecting a UDP socket selects the source address without sending packets.
pub fn internal_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// IP-echo services (plain HTTP on :80, caller IP in the body). China-reachable
/// ones first — the international services are often blocked/slow there, so a
/// domestic host still resolves its public IP quickly instead of waiting out
/// every foreign timeout.
const IP_ECHOS: &[(&str, &str)] = &[
    ("ip.3322.net", "/"),
    ("members.3322.org", "/dyndns/getip"),
    ("api.ipify.org", "/"),
    ("ifconfig.me", "/ip"),
    ("ipinfo.io", "/ip"),
];

/// Best-effort public IP: try each IP-echo service in turn (short per-try
/// timeout) and return the first that yields a public IPv4. `None` if all fail.
pub fn public_ip() -> Option<String> {
    IP_ECHOS
        .iter()
        .find_map(|(host, path)| fetch_ip(host, path))
}

/// One tiny HTTP/1.0 GET to an IP-echo service; returns the first public IPv4 in
/// the response body, or `None` on any failure/timeout.
fn fetch_ip(host: &str, path: &str) -> Option<String> {
    let timeout = Duration::from_millis(2500);
    let addr = format!("{host}:80").to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: dn7-panel\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    first_public_ipv4(buf.split("\r\n\r\n").nth(1)?)
}

/// Extract the first *public* IPv4 token from `s` (services return a bare IP or
/// an IP embedded in text). Private/loopback/link-local/unspecified addresses are
/// rejected so a proxy's own LAN address is never mistaken for the public IP.
fn first_public_ipv4(s: &str) -> Option<String> {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter_map(|tok| tok.parse::<Ipv4Addr>().ok())
        .find(|ip| {
            !ip.is_private() && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local()
        })
        .map(|ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::first_public_ipv4;

    #[test]
    fn extracts_public_ipv4_rejecting_private() {
        assert_eq!(first_public_ipv4("1.2.3.4").as_deref(), Some("1.2.3.4"));
        assert_eq!(
            first_public_ipv4("Your IP is 203.0.113.9\n").as_deref(),
            Some("203.0.113.9")
        );
        // Private/loopback are skipped; the following public one wins.
        assert_eq!(
            first_public_ipv4("192.168.1.1 8.8.8.8").as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(first_public_ipv4("10.0.0.1 127.0.0.1"), None);
        assert_eq!(first_public_ipv4("no ip here"), None);
    }
}
