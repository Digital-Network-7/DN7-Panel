//! Agent role: run the on-box web console and keep itself alive.
//!
//! DN7 Panel has no backend connection. The "agent" role (spawned by the
//! supervisor with the `agent` subcommand) simply:
//!   * writes its pid/heartbeat and guards the supervisor (mutual resurrection),
//!   * starts the local web management console,
//!   * idles forever (the console serves requests in its own tasks).
//!
//! The web console reuses the per-capability dispatchers directly on the host
//! (`docker::web_dispatch`, `nginx::web_dispatch`, …) — no relay, no token.

use std::time::Duration;

use anyhow::Result;

use crate::config::PanelConfig;
use crate::guardian;

/// Entry point for the agent role.
pub async fn run(cfg: PanelConfig) -> Result<()> {
    // Write our pid/heartbeat and start guarding the supervisor.
    guardian::write_own_pid(&cfg);
    // Record the running version so a later foreground launch can decide whether
    // it's newer (and should replace us) or not.
    crate::procfile::write_version(&cfg.data_dir);
    guardian::spawn(cfg.clone());

    // On-box web management console (default on, port 1080). Runs in its own
    // task; no-op when disabled in settings.
    crate::web::spawn(cfg.clone());

    tracing::info!("DN7 Panel agent role started");

    // Keep the role alive and our heartbeat fresh so the supervisor knows we're
    // up. The console does the real work in background tasks.
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        guardian::touch_own_heartbeat(&cfg);
    }
}
