//! Canonical install location and stable-path resolution.
//!
//! The panel installs and runs itself from `/var/dn7/panel/dn7-panel` so that:
//!   - the operator never has to create directories by hand, and
//!   - respawns + self-update use a *stable on-disk path*.
//!
//! `/var/dn7` is the Digital Network 7 root; each product lives in its own
//! subdirectory (`/var/dn7/panel` here), leaving room for future tools.
//!
//! Why the stable path matters: a self-update renames the new binary over the
//! running file. On Linux the old inode is then unlinked, so `current_exe()`
//! (which reads `/proc/self/exe`) returns "<path> (deleted)". The supervisor
//! that respawns the panel via `current_exe()` then hits
//! `No such file or directory`. Resolving against the canonical install path
//! (or a cleaned `current_exe`) avoids that.

use std::path::PathBuf;

/// Directory the panel installs itself into (its data/run/log hang off here).
pub const INSTALL_DIR: &str = "/var/dn7/panel";
/// Canonical panel binary path.
pub const INSTALL_BIN: &str = "/var/dn7/panel/dn7-panel";

/// Subdirectory names under the base dir:
///   - `data/` : values that must persist (settings, encryption key, version)
///   - `run/`  : transient process state (pid, heartbeat, lock)
///   - `log/`  : the daemon log
pub const DATA_SUBDIR: &str = "data";
pub const RUN_SUBDIR: &str = "run";
pub const LOG_SUBDIR: &str = "log";

/// Persisted-data directory (`<base>/data`): settings, `.panel_key`, version.
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

/// Base directory for runtime files (pid/heartbeat/lock/settings/log). Prefers
/// the canonical install dir (`/var/dn7/panel`) when it exists; falls back to
/// the current directory when it's unavailable (e.g. a non-root run that
/// couldn't write under `/var/dn7`).
pub fn default_base_dir() -> PathBuf {
    let p = PathBuf::from(INSTALL_DIR);
    if p.is_dir() {
        p
    } else {
        PathBuf::from(".")
    }
}

/// Ensure the panel is installed at and running from `/var/dn7/panel/dn7-panel`.
///
/// If the current executable isn't the canonical install binary, this copies
/// itself there (creating `/var/dn7/panel`), deletes the original downloaded
/// binary, then re-execs the canonical binary with the same args + env so every
/// subsequent self-split / self-update operates on the stable path. No-ops
/// (returns false) when already canonical, when the binary was unlinked by a
/// self-update, or when `/var/dn7/panel` can't be written (e.g. unprivileged
/// run) — in those cases the panel keeps running from where it is.
pub fn ensure_installed() -> bool {
    use std::os::unix::fs::PermissionsExt;

    let current = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    // After a self-update the running file is unlinked ("<path> (deleted)");
    // don't try to relocate from a phantom path.
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

    // Create the install dir and copy ourselves in. (Copy fails with ETXTBSY if
    // an old instance is still executing the canonical binary; the caller
    // retries after killing it — see the version-takeover path.)
    if std::fs::create_dir_all(INSTALL_DIR).is_err() {
        return false; // can't write there (likely unprivileged) — keep running here
    }
    if std::fs::copy(&current, &canonical).is_err() {
        return false;
    }
    let _ = std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o755));

    // Delete the original (downloaded) binary; we run from the canonical path
    // now. Unlinking a running executable is safe on Linux (the inode persists
    // until exit), and we re-exec the canonical copy immediately below.
    let _ = std::fs::remove_file(&current);

    // Re-exec the canonical binary with the same args + env, from the install dir.
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

#[cfg(test)]
mod tests {
    use super::clean_deleted;
    use std::path::Path;

    #[test]
    fn strips_deleted_suffix() {
        // The exact shape Linux reports for a replaced/unlinked running binary.
        assert_eq!(
            clean_deleted(Path::new("/var/dn7/panel/dn7-panel (deleted)")),
            Path::new("/var/dn7/panel/dn7-panel")
        );
    }

    #[test]
    fn leaves_normal_paths_untouched() {
        assert_eq!(
            clean_deleted(Path::new("/var/dn7/panel/dn7-panel")),
            Path::new("/var/dn7/panel/dn7-panel")
        );
        // A path that merely contains the word shouldn't be altered.
        assert_eq!(
            clean_deleted(Path::new("/opt/deleted/dn7-panel")),
            Path::new("/opt/deleted/dn7-panel")
        );
    }
}
