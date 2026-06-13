//! Startup banner printed to the operator's terminal on a supervisor launch.
//!
//! On a fresh install the auto-generated username/password are shown once; once
//! it's been shown the password is irrecoverable, so the banner only prints a
//! notice (with a pointer to `dn7 panel reset` to regenerate it).

use crate::config::PanelConfig;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Print the console banner. Reads (seeding on first run) the web settings so
/// the password exists, then resolves the host's addresses.
pub fn print(cfg: &PanelConfig) {
    let info = crate::web::console_info(cfg.web_enabled, cfg.web_port);
    println!();
    if !info.enabled {
        println!("  DN7 Panel — 本机控制台已关闭（在「设置」中启用并重启后生效）");
        println!();
        return;
    }
    let port = info.port;
    let scheme = if info.https { "https" } else { "http" };
    let entry = if info.entry_path == "/" {
        String::new()
    } else {
        info.entry_path.clone()
    };
    let internal = internal_ip();
    let public = public_ip();

    println!("  ┌─ DN7 Panel ──────────────────────────────────");
    match &public {
        Some(pip) => {
            println!("  │  控制台 console  →  {scheme}://{pip}:{port}{entry}");
            println!("  │                  →  {scheme}://{internal}:{port}{entry}  (内网)");
        }
        None => {
            println!("  │  控制台 console  →  {scheme}://{internal}:{port}{entry}");
        }
    }
    if !entry.is_empty() {
        println!("  │  安全入口 entry  →  {entry}  （必须带此路径才能打开登录页）");
    }
    if let Some(pw) = &info.new_password {
        println!("  │  账号 username   →  {}", info.username);
        println!("  │  密码 password   →  {pw}");
        println!("  │  提示            →  此密码与上面的端口/安全入口仅显示一次，请妥善保存");
    } else {
        println!("  │  账号 / 密码     →  已设置");
        println!("  │                     （忘记密码可在主机运行: dn7 panel reset）");
    }
    println!("  └──────────────────────────────────────────────");
    println!();
}

/// Best public-facing host for building an access URL (public IP, else LAN IP).
pub fn best_host() -> String {
    public_ip().unwrap_or_else(internal_ip)
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
