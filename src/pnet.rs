//! Private overlay network (pnet) data plane on the agent.
//!
//! When the backend clears this server for the private network it sends a
//! `pnet` command carrying the assigned `ip/prefix`. We bring up a TUN device
//! at that address and run a relay task that connects to the backend's
//! `/agent/pnet` WebSocket and pipes raw L3 packets both ways:
//!
//!   local TUN  <->  agent relay task  <->  backend hub  <->  peer agents
//!
//! The WS hop is TLS (wss), so overlay traffic is encrypted in transit, and the
//! backend routes by destination IP within the owning user. Linux-only (TUN);
//! on other targets this is a no-op.
//!
//! Only one overlay membership is active at a time. A new `pnet` command with a
//! different IP replaces the current device; `gone=true` tears it down.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::AgentConfig;

/// Tracks the currently-active overlay (so we can replace/tear-down on command).
#[derive(Default)]
pub struct PnetState {
    /// The IP currently brought up, and a handle to cancel its relay task.
    current: Mutex<Option<Active>>,
}

struct Active {
    ip: String,
    cancel: tokio::sync::watch::Sender<bool>,
}

impl PnetState {
    pub fn new() -> Arc<Self> {
        Arc::new(PnetState::default())
    }
}

/// Apply a `pnet` command: bring the overlay up at `ip/prefix`, replace it if
/// the address changed, or tear it down when `gone`.
pub async fn apply(
    state: &Arc<PnetState>,
    cfg: &AgentConfig,
    token: &str,
    ip: String,
    prefix: u8,
    gone: bool,
) {
    let mut cur = state.current.lock().await;

    // Tear down when asked, or when the active IP differs from the new one.
    if gone || cur.as_ref().map(|a| a.ip != ip).unwrap_or(false) {
        if let Some(active) = cur.take() {
            let _ = active.cancel.send(true);
            tracing::info!(ip = %active.ip, "pnet overlay torn down");
        }
    }
    if gone || ip.is_empty() {
        return;
    }
    // Already up at this IP? Nothing to do.
    if cur.as_ref().map(|a| a.ip == ip).unwrap_or(false) {
        return;
    }

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    *cur = Some(Active {
        ip: ip.clone(),
        cancel: cancel_tx,
    });
    tracing::info!(%ip, prefix, "pnet overlay starting");
    let cfg = cfg.clone();
    let token = token.to_string();
    tokio::spawn(async move {
        if let Err(e) = run_overlay(&cfg, &token, &ip, prefix, cancel_rx).await {
            tracing::warn!(%ip, "pnet overlay ended: {e}");
        }
    });
}

#[cfg(target_os = "linux")]
async fn run_overlay(
    cfg: &AgentConfig,
    token: &str,
    ip: &str,
    prefix: u8,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    use anyhow::anyhow;
    use futures_util::{SinkExt, StreamExt};
    use std::net::Ipv4Addr;
    use tokio_tun::Tun;
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest, http::header::AUTHORIZATION, Message,
    };

    // 1) Bring up the TUN device at ip/prefix.
    let addr: Ipv4Addr = ip.parse().map_err(|_| anyhow!("bad pnet ip: {ip}"))?;
    let netmask = prefix_to_netmask(prefix);
    let tun = Tun::builder()
        .name("teaops0")
        .tap(false)
        .packet_info(false) // IFF_NO_PI: raw IP packets, no 4-byte prefix
        .mtu(1400)
        .up()
        .address(addr)
        .netmask(netmask)
        .try_build()
        .map_err(|e| anyhow!("tun build failed (need root + /dev/net/tun): {e}"))?;
    tracing::info!(name = tun.name(), %ip, "pnet TUN up");
    let tun = Arc::new(tun);

    // 2) Connect the relay WebSocket to the backend.
    let url = format!("{}/agent/pnet", ws_base(cfg));
    let mut req = url
        .into_client_request()
        .map_err(|e| anyhow!("bad pnet ws url: {e}"))?;
    req.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .map_err(|e| anyhow!("bad auth header: {e}"))?,
    );
    let (ws, _resp) = tokio_tungstenite::connect_async(req).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    // 3) Pipe packets both ways until cancelled or either side closes.
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    break;
                }
            }
            // Local TUN -> backend (binary frame per packet).
            n = tun.recv(&mut buf) => {
                match n {
                    Ok(0) => {}
                    Ok(n) => {
                        if ws_tx.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => return Err(anyhow!("tun recv: {e}")),
                }
            }
            // Backend -> local TUN.
            frame = ws_rx.next() => {
                match frame {
                    Some(Ok(Message::Binary(pkt))) => {
                        let _ = tun.send_all(&pkt).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(anyhow!("pnet ws: {e}")),
                }
            }
        }
    }
    tracing::info!(%ip, "pnet overlay relay stopped");
    Ok(())
}

/// Non-Linux: no TUN support; the overlay is a no-op.
#[cfg(not(target_os = "linux"))]
async fn run_overlay(
    _cfg: &AgentConfig,
    _token: &str,
    _ip: &str,
    _prefix: u8,
    _cancel: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::warn!("pnet overlay is only supported on Linux; ignoring");
    Ok(())
}

/// Derive the ws/wss base from the backend URL (http->ws, https->wss).
#[cfg(target_os = "linux")]
fn ws_base(cfg: &AgentConfig) -> String {
    let b = cfg.backend_url.trim_end_matches('/');
    if let Some(rest) = b.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = b.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        b.to_string()
    }
}

/// Convert a CIDR prefix length to an IPv4 netmask address.
#[cfg(target_os = "linux")]
fn prefix_to_netmask(prefix: u8) -> std::net::Ipv4Addr {
    let bits: u32 = if prefix >= 32 {
        u32::MAX
    } else if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    std::net::Ipv4Addr::from(bits)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::prefix_to_netmask;
    use std::net::Ipv4Addr;

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
    }
}
