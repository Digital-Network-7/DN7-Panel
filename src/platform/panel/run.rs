//! Panel role: run the on-box web console and keep itself alive.
//!
//! DN7 Panel has no backend connection. The "panel" role (spawned by the
//! supervisor with the `panel` subcommand) simply:
//!   * writes its pid/heartbeat and guards the supervisor (mutual resurrection),
//!   * starts the local web management console,
//!   * idles forever (the console serves requests in its own tasks).
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

    // Background self-update checker (GitHub + dn7.cn). Applies automatically
    // only when auto-update is enabled in settings; otherwise just keeps the
    // "update available" hint warm.
    crate::platform::update::spawn_periodic(cfg.clone());

    tracing::info!("DN7 Panel role started");

    // Keep the role alive and our heartbeat fresh so the supervisor knows we're
    // up. The console does the real work in background tasks.
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        guardian::touch_own_heartbeat(&cfg);
    }
}
