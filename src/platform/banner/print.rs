//! Startup banner printed to the operator's terminal on a supervisor launch.
//!
//! Before first-run setup it prints the token-gated init URLs (internal +
//! public IP, each with `?init_token=`); once initialized it prints the console
//! access URL. `dn7 panel reset` re-arms the init token to re-run setup.

use crate::platform::config::PanelConfig;
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Print the console banner. Reads (seeding on first run) the web settings, then
/// resolves the host's addresses. Before first-run setup it prints the
/// token-gated init URLs (the edge serves the wizard on :80); after setup it
/// prints the console access URL.
pub fn print(cfg: &PanelConfig) {
    let info = crate::web::console_info(cfg.web_port);
    println!();
    println!("  ┌─ DN7 Panel ──────────────────────────────────");
    if !info.initialized {
        let token = &info.init_token;
        let internal = internal_ip();
        println!("  │  内网初始化  →  http://{internal}/?init_token={token}");
        if let Some(pip) = public_ip() {
            println!("  │  外网初始化  →  http://{pip}/?init_token={token}");
        }
        println!("  │  提示        →  打开任一链接完成初始化（令牌仅本次有效）");
    } else {
        let scheme = if info.https_mode == "none" {
            "http"
        } else {
            "https"
        };
        let host = if info.external_address.is_empty() {
            internal_ip()
        } else {
            info.external_address.clone()
        };
        // A bare IPv6 literal must be bracketed to be a valid, browser-openable
        // URL authority (`http://[2001:db8::1]/`); this also matches the route
        // key the edge stores for the console host.
        let host = bracket_if_ipv6(&host);
        println!("  │  控制台 console  →  {scheme}://{host}/");
    }
    println!("  └──────────────────────────────────────────────");
    println!();
}

/// Bracket a bare IPv6 literal (`2001:db8::1` → `[2001:db8::1]`) so it forms a
/// valid URL authority; a hostname, IPv4 literal, or already-bracketed value is
/// returned unchanged.
fn bracket_if_ipv6(host: &str) -> String {
    if !host.starts_with('[') && host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// The host's primary outbound (LAN) IP, via the standard UDP-connect trick:
/// connecting a UDP socket selects the source address without sending packets.
fn internal_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("1.1.1.1:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

/// Best-effort public IP via a tiny HTTP/1.0 GET to an IP-echo service. Uses
/// std-only TCP (no TLS, no async runtime — safe to call before daemonizing)
/// with a short timeout; returns None on any failure/timeout.
fn public_ip() -> Option<String> {
    let timeout = Duration::from_secs(3);
    let addr = "api.ipify.org:80".to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream
        .write_all(
            b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\nUser-Agent: dn7-panel\r\nConnection: close\r\n\r\n",
        )
        .ok()?;
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    let body = buf.split("\r\n\r\n").nth(1)?.trim();
    if body.parse::<std::net::IpAddr>().is_ok() {
        Some(body.to_string())
    } else {
        None
    }
}
