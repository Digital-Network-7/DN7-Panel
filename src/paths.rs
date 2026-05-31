//! Canonical install location and stable-path resolution.
//!
//! The agent installs and runs itself from `/var/ops/teaops-agent` so that:
//!   - the operator never has to create directories by hand, and
//!   - respawns + self-update use a *stable on-disk path*.
//!
//! Why the stable path matters: a self-update renames the new binary over the
//! running file. On Linux the old inode is then unlinked, so `current_exe()`
//! (which reads `/proc/self/exe`) returns "<path> (deleted)". The supervisor
//! that respawns the agent via `current_exe()` then hits
//! `No such file or directory`. Resolving against the canonical install path
//! (or a cleaned `current_exe`) avoids that.

use std::path::PathBuf;

/// Directory the agent installs itself into.
pub const INSTALL_DIR: &str = "/var/ops";
/// Canonical agent binary path.
pub const INSTALL_BIN: &str = "/var/ops/teaops-agent";

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

/// Ensure the agent is installed at and running from `/var/ops/teaops-agent`.
///
/// If the current executable isn't the canonical install binary, this copies
/// itself there (creating `/var/ops`), changes the working directory to
/// `/var/ops`, and re-execs the canonical binary with the same args + env so
/// every subsequent self-split / self-update operates on the stable path.
/// No-ops (returns false) when already canonical, when the binary was unlinked
/// by a self-update, or when `/var/ops` can't be written (e.g. unprivileged
/// run) — in those cases the agent keeps running from where it is.
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

    // Create /var/ops and copy ourselves in.
    if std::fs::create_dir_all(INSTALL_DIR).is_err() {
        return false; // can't write there (likely unprivileged) — keep running here
    }
    if std::fs::copy(&current, &canonical).is_err() {
        return false;
    }
    let _ = std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o755));

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

#[cfg(test)]
mod tests {
    use super::clean_deleted;
    use std::path::Path;

    #[test]
    fn strips_deleted_suffix() {
        // The exact shape Linux reports for a replaced/unlinked running binary.
        assert_eq!(
            clean_deleted(Path::new("/var/ops/teaops-agent (deleted)")),
            Path::new("/var/ops/teaops-agent")
        );
    }

    #[test]
    fn leaves_normal_paths_untouched() {
        assert_eq!(
            clean_deleted(Path::new("/var/ops/teaops-agent")),
            Path::new("/var/ops/teaops-agent")
        );
        // A path that merely contains the word shouldn't be altered.
        assert_eq!(
            clean_deleted(Path::new("/opt/deleted/teaops-agent")),
            Path::new("/opt/deleted/teaops-agent")
        );
    }
}
