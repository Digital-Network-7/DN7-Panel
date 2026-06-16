//! Panel-role restart: exit the panel process so the supervisor respawns it.
//!
//! The web console can ask the host to restart the panel (e.g. to apply a port
//! change). There is no separate "reload" path — the supervisor's
//! `supervise_loop` already (re)spawns the panel on every exit, and a fresh
//! panel re-reads `web.json`. So a restart is simply a clean process exit with
//! the normal code (not `EXIT_UPDATED`, which is reserved for self-update).
//!
//! Process exit lives here in `platform`: the `web` layer is forbidden from
//! touching `std::process` directly.

use std::time::Duration;

/// Exit code for an operator-requested restart. Distinct from
/// `update::EXIT_UPDATED` so the supervisor treats it as a plain respawn
/// (re-reading settings) rather than a self-update re-exec.
pub const EXIT_RESTART: i32 = 0;

/// Schedule a panel restart shortly after returning, giving the HTTP handler
/// time to flush its response so the UI can begin polling for the panel to come
/// back. The supervisor respawns the panel on exit, reloading `web.json`.
pub fn request_restart() {
    tokio::spawn(async {
        tracing::info!("operator-requested restart; exiting for respawn");
        tokio::time::sleep(Duration::from_millis(300)).await;
        std::process::exit(EXIT_RESTART);
    });
}
