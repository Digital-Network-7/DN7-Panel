//! Panel-role half of the mutual supervision protocol.
//!
//! The panel role writes its own pid + a periodic heartbeat so the supervisor
//! can detect liveness, and watches the supervisor's heartbeat — relaunching it
//! (under a file lock, with an adoption re-check) if it dies. Relaunch
//! re-executes *this* binary with no args (the supervisor role / self-split).

use std::process::{Command, Stdio};

use fs2::FileExt;

use crate::platform::config::PanelConfig;
use crate::platform::procfile::{role_alive, write_heartbeat, write_pid, RolePaths};

/// Write the panel role's pid file (call once at startup).
pub fn write_own_pid(cfg: &PanelConfig) {
    let _ = std::fs::create_dir_all(&cfg.runtime_dir);
    let me = RolePaths::new(&cfg.runtime_dir, "panel");
    let _ = write_pid(&me.pid);
    touch_own_heartbeat(cfg);
}

/// Refresh the panel role's heartbeat (call each loop iteration).
pub fn touch_own_heartbeat(cfg: &PanelConfig) {
    let me = RolePaths::new(&cfg.runtime_dir, "panel");
    let _ = write_heartbeat(&me.heartbeat);
}

/// Spawn the guardian background task: periodically ensure the supervisor is
/// alive and relaunch it under a lock if it isn't.
///
/// `DN7_NO_GUARDIAN=1` disables this entirely. It exists for LOCAL TESTING: the
/// supervision interval's first tick fires at t=0, so running the `panel` role
/// standalone (no supervisor parent has written a heartbeat) makes the guardian
/// immediately relaunch a full supervisor — which performs the real system
/// install (canonical dir, global CLI, autostart units). In the normal
/// supervisor→panel path the supervisor's heartbeat already exists at t=0, so
/// this never triggers; the opt-out only matters for a hand-run `panel`.
pub fn spawn(cfg: PanelConfig) {
    if std::env::var("DN7_NO_GUARDIAN").is_ok_and(|v| v != "0" && !v.is_empty()) {
        tracing::warn!("DN7_NO_GUARDIAN set: guardian disabled (no supervisor relaunch)");
        return;
    }
    tokio::spawn(async move {
        let supervisor = RolePaths::new(&cfg.runtime_dir, "supervisor");
        let relaunch_lock = cfg.runtime_dir.join("dn7-supervisor-relaunch.lock");
        let interval = cfg.heartbeat_timeout_secs.max(3);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            if role_alive(&supervisor, cfg.heartbeat_timeout_secs) {
                continue;
            }
            // Supervisor looks dead — only one relauncher wins the lock, and we
            // re-check liveness after acquiring it to avoid a duplicate spawn.
            let lock_file = match std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&relaunch_lock)
            {
                Ok(f) => f,
                Err(_) => continue,
            };
            if lock_file.try_lock_exclusive().is_err() {
                continue;
            }
            if role_alive(&supervisor, cfg.heartbeat_timeout_secs) {
                let _ = FileExt::unlock(&lock_file);
                continue;
            }

            tracing::warn!("supervisor appears dead; relaunching it");
            match relaunch_supervisor() {
                Ok(_) => tracing::info!("supervisor relaunched"),
                Err(e) => tracing::warn!("failed to relaunch supervisor: {e}"),
            }
            let _ = FileExt::unlock(&lock_file);
        }
    });
}

/// Re-execute the stable binary with no args to bring the supervisor role back.
/// Uses `paths::stable_bin()` so a post-self-update "(deleted)" `current_exe()`
/// never produces a non-existent path.
fn relaunch_supervisor() -> std::io::Result<std::process::Child> {
    let exe = crate::platform::paths::stable_bin();
    Command::new(exe)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
}
