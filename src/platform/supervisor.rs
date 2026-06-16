//! Supervisor role (the former dn7-paneld).
//!
//! Runs as the default (no-arg) role. It keeps the panel role alive by spawning
//! *itself* with the `panel` subcommand (self-split via `current_exe`) and
//! restarting it on exit. The panel role reciprocally guards the supervisor
//! (see `guardian`), so either half can resurrect the other.
//!
//! Because both roles are the same binary, a self-update replaces one file and
//! both halves come back upgraded.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use tokio::process::{Child, Command};

use crate::platform::config::PanelConfig;
use crate::platform::procfile::{role_alive, try_lock, write_heartbeat, write_pid, RolePaths};

/// Entry point for the supervisor role.
pub async fn run(cfg: PanelConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.runtime_dir).ok();
    std::fs::create_dir_all(&cfg.data_dir).ok();
    std::fs::create_dir_all(&cfg.log_dir).ok();

    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    let panel = RolePaths::new(&cfg.runtime_dir, "panel");

    // Single-instance guard: hold the supervisor lock for our whole lifetime.
    let _lock = match try_lock(&me.lock)? {
        Some(g) => g,
        None => {
            tracing::info!("another supervisor is already running; exiting");
            return Ok(());
        }
    };
    write_pid(&me.pid)?;
    write_heartbeat(&me.heartbeat)?;
    crate::platform::procfile::write_version(&cfg.data_dir);
    tracing::info!(pid = std::process::id(), "supervisor started");

    // Heartbeat task: keep our heartbeat fresh so the panel's guardian sees us.
    spawn_heartbeat(me.heartbeat.clone(), cfg.supervise_interval_secs.max(1));
    // Janitor task: trim the daemon log so it can't grow without bound.
    crate::platform::logrotate::spawn(cfg.clone());

    let mut shutdown = signal_stream()?;

    // If a panel is already alive (e.g. started by hand or by a previous
    // supervisor), adopt it: monitor until it dies instead of spawning a dup.
    if adopt_if_alive(&panel, &cfg, &mut shutdown).await {
        return Ok(());
    }

    supervise_loop(&cfg, &_lock, shutdown).await
}

/// Background task that refreshes our heartbeat file every `interval` seconds so
/// the panel's guardian can see the supervisor is alive.
fn spawn_heartbeat(heartbeat: std::path::PathBuf, interval: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            let _ = write_heartbeat(&heartbeat);
        }
    });
}

/// If a panel role is already alive, monitor it (don't spawn a duplicate) until
/// it dies or we're asked to shut down. Returns `true` when a shutdown signal
/// arrived (the caller should exit), `false` when there was no live panel or it
/// died (the caller should proceed to (re)spawn).
async fn adopt_if_alive(
    panel: &RolePaths,
    cfg: &PanelConfig,
    shutdown: &mut tokio::sync::mpsc::Receiver<()>,
) -> bool {
    if !role_alive(panel, cfg.heartbeat_timeout_secs) {
        return false;
    }
    tracing::info!("found a live panel on startup; adopting (monitor-only)");
    tokio::select! {
        _ = wait_until_panel_dead(panel, cfg) => false,
        _ = shutdown.recv() => {
            tracing::info!("shutdown signal received");
            true
        }
    }
}

/// Supervise the panel child for the process lifetime: (re)spawn it, restart on
/// exit, re-exec ourselves when a self-update lands a newer binary, and tear it
/// down on a shutdown signal.
async fn supervise_loop(
    cfg: &PanelConfig,
    lock: &crate::platform::procfile::LockGuard,
    mut shutdown: tokio::sync::mpsc::Receiver<()>,
) -> Result<()> {
    let mut child: Option<Child> = None;

    // Periodically check whether a self-update replaced the on-disk binary with
    // a newer version than this (long-lived) supervisor is running. If so,
    // re-exec ourselves so the supervisor — not just the panel child — runs the
    // new code (including any new cleanup/migration logic). Without this the
    // supervisor could run stale code indefinitely after an auto-update.
    let mut version_check =
        tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1) * 20));
    version_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if child.is_none() {
            match spawn_panel() {
                Ok(c) => {
                    tracing::info!(pid = c.id(), "spawned panel role");
                    child = Some(c);
                }
                Err(e) => {
                    tracing::error!("failed to spawn panel: {e}");
                    tokio::time::sleep(Duration::from_secs(cfg.restart_backoff_secs.max(1))).await;
                    continue;
                }
            }
        }

        let c = child.as_mut().unwrap();
        tokio::select! {
            status = c.wait() => {
                let updated = matches!(&status, Ok(s) if s.code() == Some(crate::platform::update::EXIT_UPDATED));
                match status {
                    Ok(s) => tracing::warn!("panel exited with {s}; restarting"),
                    Err(e) => tracing::warn!("panel wait error: {e}; restarting"),
                }
                child = None;
                // If the panel exited because a self-update swapped in a newer
                // binary (signalled by EXIT_UPDATED), re-exec the supervisor
                // *now* so both halves come up on the new version in a single
                // restart — instead of respawning the panel here and then
                // re-exec'ing (a second, disruptive restart) up to a
                // version_check interval later. The panel is already gone, so
                // there's nothing to kill first.
                if updated || on_disk_is_newer(cfg) {
                    tracing::info!("panel exited for self-update; re-exec'ing supervisor now");
                    lock.release();
                    reexec_supervisor();
                    // reexec only returns on FAILURE. We already released our
                    // single-instance lock for the (expected) exec, so re-acquire
                    // it before carrying on — otherwise the supervisor would run
                    // unprotected and a second one could start. If another process
                    // took it meanwhile, exit and let that one own the role.
                    if !lock.reacquire() {
                        tracing::error!("re-exec failed and role lock lost; exiting");
                        return Ok(());
                    }
                    tracing::warn!("re-exec failed; continuing on current binary");
                }
                tokio::time::sleep(Duration::from_secs(cfg.restart_backoff_secs)).await;
            }
            _ = version_check.tick() => {
                if on_disk_is_newer(cfg) {
                    tracing::info!("on-disk binary is newer than this supervisor; re-exec'ing");
                    // Stop the current panel child cleanly first, then re-exec
                    // the (new) supervisor binary in our place. Release our role
                    // lock first — the locked fd is inherited across exec, so
                    // the replacement would otherwise see the lock still held.
                    let _ = c.start_kill();
                    let _ = c.wait().await;
                    lock.release();
                    reexec_supervisor();
                    // reexec only returns on failure; re-acquire the lock we just
                    // released so we don't run unprotected. Exit if it's gone.
                    if !lock.reacquire() {
                        tracing::error!("re-exec failed and role lock lost; exiting");
                        return Ok(());
                    }
                    tracing::warn!("re-exec failed; continuing on current binary");
                    child = None;
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("shutdown signal received; terminating panel");
                let _ = c.start_kill();
                let _ = c.wait().await;
                break;
            }
        }
    }

    Ok(())
}

/// Whether the on-disk canonical binary reports a strictly newer version than
/// this running supervisor. Reads the version file that the running panel keeps
/// updated (`procfile::write_version`, written on every panel startup) instead
/// of fork+exec'ing the whole binary every ~60s just to print a version. False
/// on any error so we never re-exec on a flaky/missing read.
fn on_disk_is_newer(cfg: &PanelConfig) -> bool {
    match crate::platform::procfile::read_version(&cfg.data_dir) {
        Some(disk) => crate::platform::supervisor::version_gt(&disk, env!("CARGO_PKG_VERSION")),
        None => false,
    }
}

/// Parse-and-compare semver; true if `a` > `b`. Local copy to avoid a cross-
/// module dependency (mirrors the backend's util::version_gt).
pub fn version_gt(a: &str, b: &str) -> bool {
    fn parse(s: &str) -> Option<(u64, u64, u64)> {
        let s = s.trim().trim_start_matches('v');
        let mut it = s.split('.');
        let x = it.next()?.parse().ok()?;
        let y = it.next().unwrap_or("0").parse().ok()?;
        let z = it.next().unwrap_or("0").parse().ok()?;
        Some((x, y, z))
    }
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x > y,
        _ => false,
    }
}

/// Re-exec the canonical supervisor binary in this process's place (no args, so
/// it comes back as the supervisor role). On success this never returns.
fn reexec_supervisor() {
    use std::os::unix::process::CommandExt;
    let exe = crate::platform::paths::stable_bin();
    let err = std::process::Command::new(&exe)
        .current_dir(crate::platform::paths::INSTALL_DIR)
        .exec();
    tracing::warn!("supervisor re-exec failed: {err}");
}

/// Spawn the panel role by re-executing the stable panel binary with the
/// `panel` subcommand (the "self-split"). Uses `paths::stable_bin()` rather
/// than `current_exe()` because, after a self-update, the running file is
/// unlinked and `current_exe()` resolves to a non-existent "(deleted)" path —
/// which is exactly what caused "failed to spawn panel: No such file".
/// Stdio is inherited so the panel's logs show.
fn spawn_panel() -> Result<Child> {
    let exe = crate::platform::paths::stable_bin();
    let child = Command::new(exe)
        .arg("panel")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(false)
        .spawn()?;
    Ok(child)
}

/// Poll until the (adopted) panel is no longer alive.
async fn wait_until_panel_dead(panel: &RolePaths, cfg: &PanelConfig) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1)));
    loop {
        ticker.tick().await;
        if !role_alive(panel, cfg.heartbeat_timeout_secs) {
            tracing::warn!("adopted panel is no longer alive");
            return;
        }
    }
}

/// Forcefully stop a running panel+supervisor pair so a newer binary can take
/// over. Called synchronously from the foreground pre-flight (before any tokio
/// runtime) when a launch detects an already-running instance of an *older*
/// version.
///
/// Order matters because the two roles mutually resurrect each other:
///   1. SIGKILL the panel first. SIGKILL can't be caught, so its guardian can't
///      relaunch the supervisor. (SIGTERM would let it clean up / fight back.)
///   2. SIGKILL the supervisor. On panel exit it only restarts after a seconds-
///      long backoff, so killing it immediately wins the race.
///   3. Remove the pid/heartbeat files so the *new* supervisor doesn't "adopt"
///      the just-killed panel as if it were still alive.
///
/// Best-effort: each step ignores "already gone" errors.
pub fn stop_running_instance(cfg: &PanelConfig) {
    use crate::platform::procfile::{read_pid, signal_pid, RolePaths};

    const SIGKILL: i32 = 9;

    let panel = RolePaths::new(&cfg.runtime_dir, "panel");
    let supervisor = RolePaths::new(&cfg.runtime_dir, "supervisor");

    if let Some(pid) = read_pid(&panel.pid) {
        signal_pid(pid, SIGKILL);
    }
    if let Some(pid) = read_pid(&supervisor.pid) {
        signal_pid(pid, SIGKILL);
    }
    // Also kill the daemonized parent recorded by the daemonizer, in case it
    // differs from the supervisor role pid.
    let daemon_pid = cfg.runtime_dir.join(crate::platform::daemon::PID_FILE);
    if let Some(pid) = read_pid(&daemon_pid) {
        signal_pid(pid, SIGKILL);
    }

    // Give the kernel a moment to reap them, then clear stale liveness markers
    // so the replacement supervisor starts a fresh panel instead of adopting.
    std::thread::sleep(std::time::Duration::from_millis(300));
    for p in [
        &panel.pid,
        &panel.heartbeat,
        &supervisor.pid,
        &supervisor.heartbeat,
    ] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_file(&daemon_pid);
}

/// Combined SIGTERM/SIGINT receiver.
fn signal_stream() -> Result<tokio::sync::mpsc::Receiver<()>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        loop {
            let send: Result<(), _> = tokio::select! {
                _ = term.recv() => tx.send(()).await,
                _ = int.recv() => tx.send(()).await,
            };
            if send.is_err() {
                break;
            }
        }
    });
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::version_gt;

    #[test]
    fn newer_than_running_triggers() {
        assert!(version_gt("1.0.22", "1.0.21"));
        assert!(version_gt("1.1.0", "1.0.99"));
        assert!(version_gt("v1.0.22", "1.0.21"));
        // Minor-series bump: 1.4.0 must supersede the last 1.3.x build so
        // deployed v1.3.99 panels self-update across the 1.3 → 1.4 boundary.
        assert!(version_gt("1.4.0", "1.3.99"));
    }

    #[test]
    fn equal_or_older_does_not() {
        assert!(!version_gt("1.0.21", "1.0.21"));
        assert!(!version_gt("1.0.20", "1.0.21"));
        // Unparseable => never re-exec.
        assert!(!version_gt("", "1.0.21"));
        assert!(!version_gt("oops", "1.0.21"));
    }
}
