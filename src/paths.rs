//! Canonical install location and stable-path resolution.
//!
//! The panel installs and runs itself from `/var/ops/dn7-panel` so that:
//!   - the operator never has to create directories by hand, and
//!   - respawns + self-update use a *stable on-disk path*.
//!
//! Why the stable path matters: a self-update renames the new binary over the
//! running file. On Linux the old inode is then unlinked, so `current_exe()`
//! (which reads `/proc/self/exe`) returns "<path> (deleted)". The supervisor
//! that respawns the panel via `current_exe()` then hits
//! `No such file or directory`. Resolving against the canonical install path
//! (or a cleaned `current_exe`) avoids that.

use std::path::PathBuf;

/// Directory the panel installs itself into.
pub const INSTALL_DIR: &str = "/var/ops";
/// Canonical panel binary path.
pub const INSTALL_BIN: &str = "/var/ops/dn7-panel";

/// Subdirectory names under the base dir, grouping the previously-flat files:
///   - `data/` : values that must persist (token, version, encryption key)
///   - `run/`  : transient process state (pid, heartbeat, lock)
///   - `log/`  : the daemon log
pub const DATA_SUBDIR: &str = "data";
pub const RUN_SUBDIR: &str = "run";
pub const LOG_SUBDIR: &str = "log";

/// Persisted-data directory (`<base>/data`): token, version, `.panel_key`.
pub fn data_dir() -> PathBuf {
    default_base_dir().join(DATA_SUBDIR)
}

/// Transient runtime directory (`<base>/run`): pid/heartbeat/lock files.
pub fn run_dir() -> PathBuf {
    default_base_dir().join(RUN_SUBDIR)
}

/// Log directory (`<base>/log`): the daemon log.
pub fn log_dir() -> PathBuf {
    default_base_dir().join(LOG_SUBDIR)
}

/// Create the data/run/log subdirectories under the base dir (best-effort).
pub fn ensure_dirs() {
    for d in [data_dir(), run_dir(), log_dir()] {
        let _ = std::fs::create_dir_all(&d);
    }
}

/// The path to spawn / relaunch / self-update against. Prefers the canonical
/// install binary when present; otherwise falls back to the current exe with
/// any trailing " (deleted)" stripped.
pub fn stable_bin() -> PathBuf {
    let canonical = PathBuf::from(INSTALL_BIN);
    if canonical.exists() {
        return canonical;
    }
    current_exe_clean()
}

/// `current_exe()` with a trailing " (deleted)" removed. Linux appends that
/// suffix once the running binary's file has been replaced/unlinked (e.g. after
/// a self-update), and the raw value is not a usable path.
pub fn current_exe_clean() -> PathBuf {
    match std::env::current_exe() {
        Ok(p) => clean_deleted(&p),
        Err(_) => PathBuf::from(INSTALL_BIN),
    }
}

/// Strip a trailing " (deleted)" suffix from a path (see `current_exe_clean`).
fn clean_deleted(p: &std::path::Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_suffix(" (deleted)") {
        Some(stripped) => PathBuf::from(stripped),
        None => p.to_path_buf(),
    }
}

/// Base directory for runtime files (pid/heartbeat/lock/token/log) when the
/// operator hasn't overridden it via env. Prefers `/var/ops` (created by the
/// install step); falls back to the current directory when it's unavailable
/// (e.g. a non-root run that couldn't write `/var/ops`).
pub fn default_base_dir() -> PathBuf {
    let p = PathBuf::from(INSTALL_DIR);
    if p.is_dir() {
        p
    } else {
        PathBuf::from(".")
    }
}

/// Ensure the panel is installed at and running from `/var/ops/dn7-panel`.
///
/// If the current executable isn't the canonical install binary, this copies
/// itself there (creating `/var/ops`), migrates any older install's runtime
/// files out of the old directory (and stops the old running instance so it
/// stops re-creating its heartbeat/pid), deletes the original downloaded
/// binary, then re-execs the canonical binary with the same args + env so every
/// subsequent self-split / self-update operates on the stable path. No-ops
/// (returns false) when already canonical, when the binary was unlinked by a
/// self-update, or when `/var/ops` can't be written (e.g. unprivileged run) —
/// in those cases the panel keeps running from where it is.
pub fn ensure_installed() -> bool {
    use std::os::unix::fs::PermissionsExt;

    let current = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    // After a self-update the running file is unlinked ("<path> (deleted)");
    // don't try to migrate from a phantom path.
    if current.to_string_lossy().ends_with(" (deleted)") {
        return false;
    }

    let canonical = PathBuf::from(INSTALL_BIN);
    // Already running from the canonical path → nothing to do.
    if let (Ok(a), Ok(b)) = (current.canonicalize(), canonical.canonicalize()) {
        if a == b {
            return false;
        }
    } else if current == canonical {
        return false;
    }

    // Create /var/ops and copy ourselves in. (Copy fails with ETXTBSY if an old
    // instance is still executing the canonical binary; the caller retries after
    // killing it — see the version-takeover path.)
    if std::fs::create_dir_all(INSTALL_DIR).is_err() {
        return false; // can't write there (likely unprivileged) — keep running here
    }
    if std::fs::copy(&current, &canonical).is_err() {
        return false;
    }
    let _ = std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o755));

    // Migrate + clean up the old location(s): the directory the binary was run
    // from and the current working directory. This moves the token/log/version
    // into /var/ops and removes the old runtime state so everything is anchored
    // at /var/ops from now on.
    let mut old_dirs: Vec<PathBuf> = Vec::new();
    if let Some(parent) = current.parent() {
        old_dirs.push(parent.to_path_buf());
    }
    if let Ok(cwd) = std::env::current_dir() {
        if !old_dirs.contains(&cwd) {
            old_dirs.push(cwd);
        }
    }
    for dir in &old_dirs {
        migrate_old_runtime(dir);
    }

    // Delete the original (downloaded) binary; we run from the canonical path
    // now. Unlinking a running executable is safe on Linux (the inode persists
    // until exit), and we re-exec the canonical copy immediately below.
    let _ = std::fs::remove_file(&current);

    // Re-exec the canonical binary with the same args + env, from /var/ops.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cmd = std::process::Command::new(&canonical);
    cmd.args(&args).current_dir(INSTALL_DIR);
    use std::os::unix::process::CommandExt;
    // `exec` replaces this process on success; on failure we fall through and
    // keep running from the original location.
    let err = cmd.exec();
    tracing::warn!("re-exec from {INSTALL_BIN} failed: {err}");
    false
}

/// Runtime files worth preserving across a move to `/var/ops`.
const VALUABLE_FILES: &[&str] = &[
    "dn7-panel.token",
    "dn7-panel.token.pending",
    "dn7-panel.version",
    ".panel_key",
];

/// Transient process-state files that are meaningless once the old instance is
/// stopped; they're deleted from the old directory rather than migrated.
const TRANSIENT_FILES: &[&str] = &[
    "dn7-supervisor.pid",
    "dn7-supervisor.heartbeat",
    "dn7-supervisor.lock",
    "dn7-supervisor.daemon.pid",
    "dn7-supervisor-relaunch.lock",
    "dn7-panel.pid",
    "dn7-panel.heartbeat",
    "dn7-panel.lock",
];

const LOG_FILE_NAME: &str = "dn7-panel.log";

/// Move an older install's runtime files out of `old_dir` into `/var/ops` and
/// stop the old running instance.
///
/// The old supervisor keeps re-writing its heartbeat/pid every few seconds, so
/// deleting those files without first stopping it would just have them reappear
/// (the exact "dn7-supervisor.heartbeat can't be deleted until reboot"
/// symptom). We therefore SIGKILL the old instance first, then migrate the
/// valuable files (without clobbering anything already in /var/ops), append the
/// old log into the canonical one, and delete the transient state.
fn migrate_old_runtime(old_dir: &std::path::Path) {
    let canonical_dir = std::path::Path::new(INSTALL_DIR);
    // Nothing to do when the "old" dir is /var/ops itself, or doesn't exist.
    if old_dir == canonical_dir || !old_dir.is_dir() {
        return;
    }
    // Only act if this really looks like an old install dir (has at least one of
    // our runtime files), so we never disturb an unrelated directory.
    let looks_like_install = VALUABLE_FILES
        .iter()
        .chain(TRANSIENT_FILES.iter())
        .any(|f| old_dir.join(f).exists())
        || old_dir.join(LOG_FILE_NAME).exists();
    if !looks_like_install {
        return;
    }

    // 1) Stop the old instance so it stops re-creating heartbeat/pid files.
    //    Kill the PANEL first: its guardian would otherwise relaunch the
    //    supervisor the moment we kill it. SIGKILL can't be caught, so the
    //    guardian can't fight back. Then kill the supervisor (and its
    //    daemonized parent). Repeat once after a short pause to mop up anything
    //    a race brought back.
    const SIGKILL: i32 = 9;
    let kill_order = [
        "dn7-panel.pid",
        "dn7-supervisor.pid",
        "dn7-supervisor.daemon.pid",
    ];
    for _ in 0..2 {
        for name in kill_order {
            if let Some(pid) = crate::procfile::read_pid(&old_dir.join(name)) {
                if pid != std::process::id() {
                    crate::procfile::signal_pid(pid, SIGKILL);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // 2-4) Move valuables, fold the log, drop transient state — into the new
    // grouped subdirs under /var/ops (data/run/log).
    migrate_files(old_dir, canonical_dir);
    tracing::info!(dir = %old_dir.display(), "migrated old panel runtime files to /var/ops");
}

/// Migrate a *flat* `/var/ops` layout (everything directly under the base dir,
/// as written by older panels) into the grouped `data/`, `run/`, `log/`
/// subdirs. Idempotent and best-effort: if there are no flat files it does
/// nothing. Runs on every supervisor launch so an upgrade picks up its existing
/// token/key without re-pairing. The old running instance (if any) is *this*
/// process about to start, so there's nothing to stop here.
pub fn migrate_flat_layout() {
    let base = default_base_dir();
    // Only act when at least one known flat file is present directly in base.
    let has_flat = VALUABLE_FILES
        .iter()
        .chain(TRANSIENT_FILES.iter())
        .any(|f| base.join(f).is_file())
        || base.join(LOG_FILE_NAME).is_file();
    if !has_flat {
        return;
    }
    ensure_dirs();
    migrate_files(&base, &base);
    tracing::info!("migrated flat /var/ops layout into data/run/log subdirs");
}

/// Move the valuable runtime files from `old_dir` into the grouped subdirs under
/// `dest_base` (`data/` for persisted files, `log/` for the log), without
/// clobbering existing ones, and delete the transient process-state files from
/// `old_dir`. Split out from `migrate_old_runtime` (which also stops the old
/// process) so it's unit testable against temp dirs.
///
/// `old_dir == dest_base` is supported: that's the in-place flat→subdir
/// migration (files move from the base into its own data/run/log children).
fn migrate_files(old_dir: &std::path::Path, dest_base: &std::path::Path) {
    use std::io::Write;

    let data_dst = dest_base.join(DATA_SUBDIR);
    let log_dst_dir = dest_base.join(LOG_SUBDIR);
    let _ = std::fs::create_dir_all(&data_dst);
    let _ = std::fs::create_dir_all(&log_dst_dir);

    // Move valuable (persisted) files into <dest_base>/data if not already there.
    for name in VALUABLE_FILES {
        let src = old_dir.join(name);
        if !src.is_file() {
            continue;
        }
        let dst = data_dst.join(name);
        if dst.exists() {
            let _ = std::fs::remove_file(&src); // keep the existing copy
        } else if std::fs::rename(&src, &dst).is_err() {
            // rename fails across filesystems; fall back to copy + remove.
            if std::fs::copy(&src, &dst).is_ok() {
                let _ = std::fs::remove_file(&src);
            }
        }
    }

    // Append the old log into <dest_base>/log/dn7-panel.log, then remove it.
    let old_log = old_dir.join(LOG_FILE_NAME);
    if old_log.is_file() {
        let dst_log = log_dst_dir.join(LOG_FILE_NAME);
        // Skip if it's literally the same file (shouldn't happen: old is flat,
        // dst is under log/), guarding against truncating-into-self.
        if old_log != dst_log {
            if let Ok(bytes) = std::fs::read(&old_log) {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&dst_log)
                {
                    let _ = f.write_all(&bytes);
                }
            }
            let _ = std::fs::remove_file(&old_log);
        }
    }

    // Delete transient state from the old directory (regenerated under run/).
    for name in TRANSIENT_FILES {
        let _ = std::fs::remove_file(old_dir.join(name));
    }
}

/// Candidate directories an older panel may have left runtime files in. These
/// are the places the panel could have been started from before it adopted
/// `/var/ops` (home, `/`, `/root`, and the current working directory).
fn legacy_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if p != std::path::Path::new(INSTALL_DIR) && !dirs.contains(&p) {
            dirs.push(p);
        }
    };
    push(PathBuf::from("/root"));
    push(PathBuf::from("/"));
    if let Some(home) = std::env::var_os("HOME") {
        push(PathBuf::from(home));
    }
    if let Ok(cwd) = std::env::current_dir() {
        push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            push(parent.to_path_buf());
        }
    }
    dirs
}

/// Scan well-known legacy locations on *every* launch and clean up any panel
/// runtime files left there (stopping a stale old instance first, migrating the
/// token, deleting heartbeat/pid/lock/log residue).
///
/// This is needed in addition to the install-time migration because a host that
/// already moved to `/var/ops` runs `ensure_installed()` as a no-op, yet an
/// *old supervisor* may still be alive in `/root` (or `~`) — written there
/// before the binary learned to relocate — re-creating its heartbeat every few
/// seconds. That's the "heartbeat won't delete" symptom: a different runtime
/// dir means a different lock, so the single-instance guard never caught it.
/// Runs only when `/var/ops` is usable (the canonical home for everything).
pub fn cleanup_legacy_locations() {
    let canonical = std::path::Path::new(INSTALL_DIR);
    if !canonical.is_dir() {
        return; // not installed canonically yet; nothing to anchor cleanup to
    }
    for dir in legacy_dirs() {
        migrate_old_runtime(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::clean_deleted;
    use std::path::Path;

    #[test]
    fn strips_deleted_suffix() {
        // The exact shape Linux reports for a replaced/unlinked running binary.
        assert_eq!(
            clean_deleted(Path::new("/var/ops/dn7-panel (deleted)")),
            Path::new("/var/ops/dn7-panel")
        );
    }

    #[test]
    fn leaves_normal_paths_untouched() {
        assert_eq!(
            clean_deleted(Path::new("/var/ops/dn7-panel")),
            Path::new("/var/ops/dn7-panel")
        );
        // A path that merely contains the word shouldn't be altered.
        assert_eq!(
            clean_deleted(Path::new("/opt/deleted/dn7-panel")),
            Path::new("/opt/deleted/dn7-panel")
        );
    }

    #[test]
    fn migrate_files_moves_valuables_folds_log_drops_transient() {
        use super::{migrate_files, DATA_SUBDIR, LOG_SUBDIR};
        use std::fs;

        // Build an isolated old dir + dest base under a unique temp path.
        let base = std::env::temp_dir().join(format!("dn7-mig-{}", std::process::id()));
        let old = base.join("old");
        let dest = base.join("var-ops");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&old).unwrap();
        fs::create_dir_all(&dest).unwrap();
        let data = dest.join(DATA_SUBDIR);
        let logd = dest.join(LOG_SUBDIR);

        // Valuable files in the old dir.
        fs::write(old.join("dn7-panel.token"), "tok").unwrap();
        fs::write(old.join(".panel_key"), "key").unwrap();
        // A valuable file that ALSO exists at the destination (kept, not clobbered).
        fs::write(old.join("dn7-panel.version"), "0.0.1").unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("dn7-panel.version"), "0.1.0").unwrap();
        // Transient state + a log to fold.
        fs::write(old.join("dn7-supervisor.heartbeat"), "123").unwrap();
        fs::write(old.join("dn7-supervisor.pid"), "999").unwrap();
        fs::write(old.join("dn7-panel.log"), "old-log\n").unwrap();
        fs::create_dir_all(&logd).unwrap();
        fs::write(logd.join("dn7-panel.log"), "new-log\n").unwrap();

        migrate_files(&old, &dest);

        // Valuables moved into <dest>/data.
        assert_eq!(
            fs::read_to_string(data.join("dn7-panel.token")).unwrap(),
            "tok"
        );
        assert_eq!(fs::read_to_string(data.join(".panel_key")).unwrap(), "key");
        assert!(!old.join("dn7-panel.token").exists());
        assert!(!old.join(".panel_key").exists());
        // Existing version preserved; old copy removed.
        assert_eq!(
            fs::read_to_string(data.join("dn7-panel.version")).unwrap(),
            "0.1.0"
        );
        assert!(!old.join("dn7-panel.version").exists());
        // Log folded into <dest>/log (contains both), old log gone.
        let folded = fs::read_to_string(logd.join("dn7-panel.log")).unwrap();
        assert!(folded.contains("new-log"));
        assert!(folded.contains("old-log"));
        assert!(!old.join("dn7-panel.log").exists());
        // Transient state deleted from the old dir (the heartbeat symptom).
        assert!(!old.join("dn7-supervisor.heartbeat").exists());
        assert!(!old.join("dn7-supervisor.pid").exists());

        let _ = fs::remove_dir_all(&base);
    }
}
