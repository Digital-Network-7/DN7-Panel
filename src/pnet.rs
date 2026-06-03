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
    use std::net::Ipv4Addr;
    use tokio_tun::Tun;

    // 1) Bring up the TUN device at ip/prefix. Kept up for the whole lifetime
    //    of this overlay (across WS reconnects) so a transient relay drop never
    //    removes the interface or its route.
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

    // 2) Reconnect loop: keep a relay WebSocket to the backend alive for as long
    //    as the overlay is active. If the WS drops (network blip, backend
    //    restart), back off briefly and reconnect — the TUN stays up throughout,
    //    so peers become reachable again automatically instead of the overlay
    //    silently dying (the cause of intermittent ping failures).
    let mut backoff = 1u64;
    loop {
        if *cancel.borrow() {
            break;
        }
        let started = std::time::Instant::now();
        match connect_and_pipe(cfg, token, &tun, &mut cancel).await {
            Ok(_cancelled) => break, // cancelled cleanly
            Err(e) => {
                if *cancel.borrow() {
                    break;
                }
                // A connection that stayed up a while was healthy; reset the
                // backoff so a later blip recovers fast instead of staying
                // stuck at the 15s ceiling.
                if started.elapsed() >= std::time::Duration::from_secs(30) {
                    backoff = 1;
                }
                tracing::warn!(%ip, "pnet relay dropped ({e}); reconnecting in {backoff}s");
                tokio::select! {
                    _ = cancel.changed() => { if *cancel.borrow() { break; } }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(backoff)) => {}
                }
                backoff = (backoff * 2).min(15);
                continue;
            }
        }
    }
    tracing::info!(%ip, "pnet overlay stopped");
    Ok(())
}

/// One relay session: connect the `/agent/pnet` WebSocket and pipe packets
/// between it and the (persistent) TUN device until the WS closes or the
/// overlay is cancelled. Returns Ok(true) when cancelled, Err on WS failure
/// (so the caller reconnects). A successful connection resets the caller's
/// backoff implicitly (it only grows on Err).
#[cfg(target_os = "linux")]
async fn connect_and_pipe(
    cfg: &AgentConfig,
    token: &str,
    tun: &std::sync::Arc<tokio_tun::Tun>,
    cancel: &mut tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<bool> {
    use anyhow::anyhow;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest, http::header::AUTHORIZATION, Message,
    };

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
    tracing::info!("pnet relay connected");

    // Keepalive + dead-connection detection. Without this, an idle relay can be
    // silently dropped by a proxy/NAT and we'd only notice when traffic next
    // flows (the "ping fails until it recovers" symptom). We send a Ping every
    // second (the liveness check cadence) and treat the link as dead if nothing
    // (data/ping/pong) is received for IDLE_TIMEOUT — a few seconds of grace so
    // normal jitter doesn't trigger a spurious reconnect (which would churn the
    // TLS handshake/auth). 1s check + 3s timeout => recovery within ~3-4s.
    const KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(1);
    const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_rx = std::time::Instant::now();

    let mut buf = vec![0u8; 1600];
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                if *cancel.borrow() {
                    return Ok(true);
                }
            }
            // Periodic keepalive ping + idle watchdog.
            _ = keepalive.tick() => {
                if last_rx.elapsed() >= IDLE_TIMEOUT {
                    return Err(anyhow!("relay idle timeout"));
                }
                if ws_tx.send(Message::Ping(Vec::new())).await.is_err() {
                    return Err(anyhow!("relay ping failed"));
                }
            }
            // Local TUN -> backend (binary frame per packet).
            n = tun.recv(&mut buf) => {
                match n {
                    Ok(0) => {}
                    Ok(n) => {
                        if ws_tx.send(Message::Binary(buf[..n].to_vec())).await.is_err() {
                            return Err(anyhow!("relay send failed"));
                        }
                    }
                    Err(e) => return Err(anyhow!("tun recv: {e}")),
                }
            }
            // Backend -> local TUN.
            frame = ws_rx.next() => {
                last_rx = std::time::Instant::now();
                match frame {
                    Some(Ok(Message::Binary(pkt))) => {
                        let _ = tun.send_all(&pkt).await;
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(anyhow!("relay closed by server"));
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(anyhow!("pnet ws: {e}")),
                }
            }
        }
    }
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
