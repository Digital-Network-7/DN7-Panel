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
    // One-shot post-update rollback cap for this supervisor's lifetime. The
    // physical `.prev` removal in `rollback_to_prev` already makes a rollback
    // unrepeatable across re-execs; this flag additionally stops a second
    // rollback within a single supervisor process (belt and braces).
    let mut rolled_back = false;

    // Periodically check whether a self-update replaced the on-disk binary with
    // a newer version than this (long-lived) supervisor is running. If so,
    // re-exec ourselves so the supervisor — not just the panel child — runs the
    // new code (including any new cleanup/migration logic). Without this the
    // supervisor could run stale code indefinitely after an auto-update.
    let mut version_check =
        tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1) * 20));
    version_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Once a (post-update) build has confirmed it booted, drop the saved
        // previous binary so a *later*, unrelated crash can never be mistaken for
        // a failed update and roll us back onto stale code.
        if boot_marker_present() {
            clear_prev_backup();
        }

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

                // Failed-update detection: a post-update build (a `.prev` backup
                // exists) that died WITHOUT writing its boot-ok marker never came
                // up healthy. Roll the binary back to the saved previous build —
                // once — then re-exec onto it. `updated` exits are a *further*
                // self-update, not a failed boot, so they skip this. The rollback
                // is capped by both this flag and the physical `.prev` removal, so
                // a genuinely-broken previous build can't loop forever; after the
                // single attempt we fall through to a plain respawn.
                if should_rollback(updated, rolled_back, update_pending_verify()) {
                    tracing::error!(
                        "post-update panel died before confirming boot; rolling back to previous binary"
                    );
                    rolled_back = true;
                    if rollback_to_prev() {
                        lock.release();
                        reexec_supervisor();
                        if !lock.reacquire() {
                            tracing::error!("rollback re-exec failed and role lock lost; exiting");
                            return Ok(());
                        }
                        tracing::error!("rollback re-exec failed; continuing on current binary");
                    } else {
                        tracing::error!(
                            "rollback could not restore a previous binary; respawning current build"
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(cfg.restart_backoff_secs)).await;
                    continue;
                }

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
                    graceful_stop(c).await;
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
                graceful_stop(c).await;
                break;
            }
        }
    }

    Ok(())
}

/// Grace period the supervisor gives a panel child to exit on SIGTERM before
/// escalating to SIGKILL.
const STOP_GRACE_SECS: u64 = 5;

/// Stop the panel child gracefully: send SIGTERM (the panel installs a handler
/// that exits 0 cleanly), wait up to [`STOP_GRACE_SECS`], and escalate to
/// SIGKILL only if it hasn't exited by then. Always awaits the child so it's
/// reaped (no zombie). Unlike the old unconditional `start_kill()` (SIGKILL),
/// this lets the panel shut its listeners down in an orderly way; the escalation
/// guarantees the stop still completes if the child is wedged.
async fn graceful_stop(c: &mut Child) {
    // SIGTERM via the child's pid (tokio's `start_kill` only sends SIGKILL). A
    // `None` pid means the child already exited — nothing to signal; the wait
    // below just reaps it.
    if let Some(pid) = c.id() {
        const SIGTERM: i32 = 15;
        crate::platform::procfile::signal_pid(pid, SIGTERM);
    }
    if tokio::time::timeout(Duration::from_secs(STOP_GRACE_SECS), c.wait())
        .await
        .is_err()
    {
        tracing::warn!("panel did not exit within {STOP_GRACE_SECS}s of SIGTERM; sending SIGKILL");
        let _ = c.start_kill();
        let _ = c.wait().await;
    }
}

/// Whether a fresh boot-ok marker exists — i.e. the currently-running panel build
/// confirmed its web console came up. Used to gate the one-shot post-update
/// rollback: a just-installed build that never writes this (its child dies first)
/// is treated as a failed update.
fn boot_marker_present() -> bool {
    crate::platform::paths::boot_marker().exists()
}

/// True when an update is *pending verification*: a saved previous binary exists
/// but the new build hasn't written its boot-ok marker yet. This on-disk state
/// survives the supervisor re-exec that a self-update performs, so the (new)
/// supervisor that spawns the first post-update panel can recognise it's on
/// probation without any in-memory flag.
fn update_pending_verify() -> bool {
    crate::platform::paths::prev_bin().exists() && !boot_marker_present()
}

/// Pure decision for the one-shot post-update rollback (extracted so it's unit-
/// testable without touching the filesystem or spawning processes):
///   * `exited_updated` — the child left with `EXIT_UPDATED` (a *further* self-
///     update, not a failed boot): never a rollback.
///   * `already_rolled_back` — we already spent our single rollback this
///     supervisor lifetime: don't loop.
///   * `pending_verify` — a `.prev` backup exists and the new build never wrote
///     its boot-ok marker: the update did not come up healthy.
///
/// We roll back only when a genuinely-unverified update child died on its own.
fn should_rollback(exited_updated: bool, already_rolled_back: bool, pending_verify: bool) -> bool {
    !exited_updated && !already_rolled_back && pending_verify
}

/// Restore the saved previous binary over the canonical target (one-shot
/// rollback after a failed update). Removes the `.prev` copy afterwards so the
/// rollback can never repeat — a genuinely-broken previous build must not cause
/// an infinite restore loop. Returns true on success.
fn rollback_to_prev() -> bool {
    let prev = crate::platform::paths::prev_bin();
    let target = crate::platform::paths::stable_bin();
    if !prev.exists() {
        return false;
    }
    // `rename` within the same dir is atomic; the running (deleted-inode) child
    // is already gone by the time we roll back, so replacing the file is safe.
    match std::fs::rename(&prev, &target) {
        Ok(_) => {
            tracing::error!(
                ?target,
                "self-update rollback: restored previous binary after the new build failed to boot"
            );
            true
        }
        Err(e) => {
            tracing::error!("self-update rollback: could not restore previous binary: {e}");
            // Drop the (possibly bad) copy so we don't retry endlessly.
            let _ = std::fs::remove_file(&prev);
            false
        }
    }
}

/// Drop a confirmed-good update's saved previous binary. Called once the new
/// build's boot-ok marker appears, so a *later* unrelated crash can never be
/// misread as a failed update and trigger a rollback.
fn clear_prev_backup() {
    let prev = crate::platform::paths::prev_bin();
    if prev.exists() {
        let _ = std::fs::remove_file(&prev);
        tracing::info!("self-update confirmed healthy; cleared previous-binary backup");
    }
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

/// Re-exec the canonical supervisor binary in this process's place. On success
/// this never returns.
///
/// MUST pass `--foreground`: this process is already detached (systemd launches
/// us as `{BIN} --foreground`, or we self-daemonized), so re-entering `main`
/// with empty argv would make it daemonize AGAIN — double-forking out from under
/// systemd, which then sees MainPID exit and fires `Restart=always` (restart
/// churn on every auto-update, logs silently leaving journald). The flag routes
/// to the supervisor role and skips daemonization, keeping the PID stable.
fn reexec_supervisor() {
    use std::os::unix::process::CommandExt;
    let exe = crate::platform::paths::stable_bin();
    let err = std::process::Command::new(&exe)
        .arg("--foreground")
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
    use super::{should_rollback, version_gt};

    // The one-shot post-update rollback must fire exactly once, and only for an
    // unverified update child that died on its own — never for a `EXIT_UPDATED`
    // (further self-update) exit, an already-spent rollback, or a build that
    // confirmed boot (no pending-verify). This pins that decision table so a
    // genuinely-broken previous binary can't drive an infinite restore loop.
    #[test]
    fn rollback_fires_once_for_a_failed_update_only() {
        // Fresh failed update: not an update-exit, not yet rolled back, pending.
        assert!(should_rollback(false, false, true));

        // A further self-update (EXIT_UPDATED) is never a failed boot.
        assert!(!should_rollback(true, false, true));

        // Already used our single rollback this lifetime → don't loop.
        assert!(!should_rollback(false, true, true));

        // Nothing pending verification (marker present or no `.prev`): no rollback
        // even on an ordinary crash.
        assert!(!should_rollback(false, false, false));

        // Combined guards all hold simultaneously.
        assert!(!should_rollback(true, true, true));
        assert!(!should_rollback(true, true, false));
    }

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
