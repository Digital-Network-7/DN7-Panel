//! Panel role: run the on-box web console and keep itself alive.
//!
//! DN7 Panel has no backend connection. The "panel" role (spawned by the
//! supervisor with the `panel` subcommand) simply:
//!   * writes its pid/heartbeat and guards the supervisor (mutual resurrection),
//!   * starts the local web management console,
//!   * drops a boot-ok marker once the console listener is up (so the supervisor
//!     can confirm a self-update build came up healthy), and
//!   * idles until a SIGTERM/SIGINT triggers a clean exit(0) (the console serves
//!     requests in its own tasks the whole time).
//!
//! The web console reuses the per-capability dispatchers directly on the host
//! (`docker::web_dispatch`, `website::web_dispatch`, …) — no relay, no token.

use std::time::Duration;

use anyhow::Result;

use crate::platform::config::PanelConfig;
use crate::platform::guardian;

/// Entry point for the panel role.
pub async fn run(cfg: PanelConfig) -> Result<()> {
    // Write our pid/heartbeat and start guarding the supervisor.
    guardian::write_own_pid(&cfg);
    // Record the running version so a later foreground launch can decide whether
    // it's newer (and should replace us) or not.
    crate::platform::procfile::write_version(&cfg.data_dir);
    guardian::spawn(cfg.clone());

    // On-box web management console. It seeds `<data>/web.json` on first run
    // (random high port + safe-entry path), then serves from the persisted
    // settings in its own tasks.
    crate::web::spawn(cfg.clone());

    // In-process edge server (the pure-Rust reverse proxy that serves :80/:443).
    // When the website capability has been set up, load the current manifests
    // into its route table and bind the listeners in its own tasks.
    tokio::spawn(async {
        crate::infra::website::edge_autostart().await;
        // Finish a CLI first-run setup that DEFERRED Let's Encrypt: now that the
        // edge is serving :80 (so the ACME HTTP-01 challenge can be answered),
        // issue the console cert if it's still missing. Settings live in `web`,
        // so read them here (platform) and pass them down to infra.
        if let Some(s) = crate::web::settings::load() {
            if s.initialized {
                crate::infra::website::ensure_console_cert(&s.https_mode, &s.external_address)
                    .await;
            }
        }
    });

    // Rebuild the edge route table from the persisted manifests once at startup
    // (re-resolving any drifted proxy_container upstreams).
    tokio::spawn(async {
        crate::infra::website::resync_confs().await;
    });

    // Auto-renew Let's Encrypt / self-signed certs before they expire.
    crate::infra::website::spawn_cert_renewal();

    // Periodically re-resolve proxy_container upstreams so a site whose backing
    // container's IP drifted (recreate) heals, and one whose container vanished
    // out-of-band fails closed (503) instead of proxying a recycled IP.
    crate::infra::website::spawn_upstream_resync();

    // Reclaim leaked container network state at boot. A container whose panel
    // was OOM-killed (or whose runtime crashed) can leave a dangling IPAM lease
    // + veth + DNAT rule behind; the in-house runtime's idempotent net gc() frees
    // every lease whose owning pid is dead. Only for the in-house runtime
    // (DN7_RUNTIME=dn7) — the default docker path manages its own teardown — and
    // best-effort so a gc hiccup never blocks the console coming up.
    reclaim_container_net_at_boot();

    // Periodic container-log janitor: rotate any oversized console.log so a
    // chatty container nobody is watching can't fill the disk. The inline
    // rotation points (tty pump, read paths, exit reaper) cover the common
    // cases; this timer is the backstop for a long-running detached container.
    spawn_container_log_janitor();

    // Background self-update checker (GitHub + dn7.cn). Applies automatically
    // only when auto-update is enabled in settings; otherwise just keeps the
    // "update available" hint warm.
    crate::platform::update::spawn_periodic(cfg.clone());

    // Boot-success handshake: once the web console listener is actually accepting
    // connections, drop the boot-ok marker. The supervisor watches for this to
    // confirm a freshly-installed self-update build came up healthy (and rolls
    // back the binary if a post-update child dies before it appears).
    spawn_boot_marker();

    tracing::info!("DN7 Panel role started");

    // A clean-shutdown signal (SIGTERM/SIGINT) from the supervisor's graceful
    // stop. We don't drain in-flight requests (the console does its work in
    // detached tasks); a prompt, orderly exit(0) is far better than being
    // SIGKILL'd mid-write, and lets the supervisor observe a normal exit.
    let mut shutdown = shutdown_signal();

    // Keep the role alive and our heartbeat fresh so the supervisor knows we're
    // up. The console does the real work in background tasks.
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                guardian::touch_own_heartbeat(&cfg);
            }
            _ = shutdown.recv() => {
                tracing::info!("panel received shutdown signal; exiting cleanly");
                // Plain code-0 exit: the supervisor treats it as a normal stop
                // (not EXIT_UPDATED), and — when the whole pair is being torn
                // down — it has already stopped respawning us.
                std::process::exit(0);
            }
        }
    }
}

/// Best-effort one-shot reclaim of leaked container network state (dead-pid IPAM
/// leases + their veth/DNAT rules) at panel boot, guarded to the in-house runtime.
///
/// A container killed out-of-band (OOM, host crash, `SIGKILL`) never runs its
/// own teardown, so its lease/veth/DNAT can outlive it; the runtime already has
/// an idempotent `NetworkManager::gc()` that frees every lease whose pid is dead.
/// Running it once at startup reclaims what the last boot leaked. It is guarded
/// on `DN7_RUNTIME=dn7` so a plain docker install (whose daemon owns its own
/// networking) is untouched, and Linux-gated because the runtime's networking is
/// Linux-only (it doesn't compile off Linux). Failures are logged, never fatal.
#[cfg(target_os = "linux")]
fn reclaim_container_net_at_boot() {
    if !dn7_container::selected() {
        return;
    }
    // `gc()` is synchronous (netlink + on-disk IPAM state), so run it on the
    // blocking pool and don't await it — it must never delay the console coming
    // up, and its result is purely informational.
    tokio::task::spawn_blocking(|| match dn7_container::net::NetworkManager::new().gc() {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            reclaimed = n,
            "boot net gc: reclaimed leaked container leases"
        ),
        Err(e) => tracing::warn!("boot net gc failed: {e}"),
    });
}

/// Off-Linux the in-house runtime doesn't exist, so there's nothing to reclaim.
#[cfg(not(target_os = "linux"))]
fn reclaim_container_net_at_boot() {}

/// Rotate oversized container `console.log`s on a slow timer (in-house runtime
/// only). Synchronous filesystem stats over at most a few dozen containers —
/// runs on the blocking pool each tick.
#[cfg(target_os = "linux")]
fn spawn_container_log_janitor() {
    if !dn7_container::selected() {
        return;
    }
    tokio::spawn(async {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let n = tokio::task::spawn_blocking(dn7_container::container::rotate_all_logs).await;
            if let Ok(n @ 1..) = n {
                tracing::info!(rotated = n, "container log janitor: rotated oversized logs");
            }
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn spawn_container_log_janitor() {}

/// Poll the loopback console port until it accepts a connection (the listener is
/// up), then write the boot-ok marker exactly once. Bounded to a short window so
/// a console that never binds simply never marks booted (the supervisor then
/// treats a post-update child as failed and can roll back) rather than looping
/// forever. Runs in the background so it never blocks the role's main loop.
fn spawn_boot_marker() {
    tokio::spawn(async move {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            dn7_edge::CONSOLE_LOOPBACK_PORT,
        );
        // ~30 attempts * 500ms ≈ 15s: comfortably longer than a normal bind, but
        // still bounded so we don't spin indefinitely on a wedged console.
        for _ in 0..30 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                let marker = crate::platform::paths::boot_marker();
                if let Some(dir) = marker.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                match std::fs::write(&marker, crate::platform::procfile::now_secs().to_string()) {
                    Ok(_) => tracing::info!(?marker, "console up; wrote boot-ok marker"),
                    Err(e) => tracing::warn!("could not write boot-ok marker: {e}"),
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        tracing::warn!("console listener did not come up in time; boot-ok marker not written");
    });
}

/// Receiver that fires once on the first SIGTERM/SIGINT — the supervisor's
/// graceful-stop signal. Mirrors the supervisor's own `signal_stream`.
fn shutdown_signal() -> tokio::sync::mpsc::Receiver<()> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut int = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        let _ = tx.send(()).await;
    });
    rx
}
