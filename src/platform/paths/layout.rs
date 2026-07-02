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
///   - `data/` : values that must persist (settings, version, sessions)
///   - `run/`  : transient process state (pid, heartbeat, lock)
///   - `log/`  : the daemon log
pub const DATA_SUBDIR: &str = "data";
pub const RUN_SUBDIR: &str = "run";
pub const LOG_SUBDIR: &str = "log";

/// Persisted-data directory (`<base>/data`): settings (web.json), version, sessions.
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

/// Atomically write `data` to `path` with owner-only (0600) permissions from
/// the moment of creation. The bytes are written to a temp file in the *same*
/// directory (created with O_EXCL + mode 0600, so it can't be pre-planted as a
/// symlink and never lands world-readable), fsynced, then renamed over the
/// target. Use this for every sensitive on-disk file (keys, session tokens,
/// account config, update state) instead of `write` + later `chmod`, which
/// leaves a brief window where a wide umask exposes the contents.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret");
    let mut last_err = None;
    for _ in 0..16 {
        let tmp = dir.join(format!(".{base}.tmp-{:016x}", rand::random::<u64>()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&tmp) {
            Ok(mut f) => {
                let r = f.write_all(data).and_then(|_| f.sync_all());
                if let Err(e) = r {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                drop(f);
                if let Err(e) = std::fs::rename(&tmp, path) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temp file name collision",
        )
    }))
}

/// Atomically write `data` to `path` with default (non-secret) permissions.
/// Same temp-file + fsync + rename dance as [`write_private`] — so a reader
/// never observes a torn/half-written file and a crash mid-write can't corrupt
/// the target — but without forcing 0600. Use for non-sensitive manifests/config
/// (site lists, access metadata, tuning) that must survive partial writes.
pub fn write_public(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let base = path.file_name().and_then(|s| s.to_str()).unwrap_or("state");
    let mut last_err = None;
    for _ in 0..16 {
        let tmp = dir.join(format!(".{base}.tmp-{:016x}", rand::random::<u64>()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        match opts.open(&tmp) {
            Ok(mut f) => {
                let r = f.write_all(data).and_then(|_| f.sync_all());
                if let Err(e) = r {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                drop(f);
                if let Err(e) = std::fs::rename(&tmp, path) {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temp file name collision",
        )
    }))
}

/// Install the global `dn7` CLI as a symlink to the panel binary (best-effort;
/// needs root). There is ONE binary: launched as `dn7` (via this symlink) it
/// dispatches to the unified CLI (crate `dn7-cli`, by argv[0]); as `dn7-panel`
/// it runs the panel/supervisor. Rewritten on each supervisor launch so it
/// always points at the canonical install path.
pub fn install_global_cli() {
    for dir in ["/usr/local/bin", "/usr/bin"] {
        if !std::path::Path::new(dir).is_dir() {
            continue;
        }
        let link = std::path::Path::new(dir).join("dn7");
        let _ = std::fs::remove_file(&link); // replace any stale link/shim
        if std::os::unix::fs::symlink(INSTALL_BIN, &link).is_ok() {
            tracing::info!(path = %link.display(), "installed global `dn7` CLI (symlink → panel)");
            return;
        }
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
/// the canonical install dir (`/var/dn7/panel`) when it exists. When it isn't
/// available (e.g. an unprivileged run that couldn't create `/var/dn7`), it
/// falls back to a *stable per-user* state dir rather than the current working
/// directory — sensitive files (`web.json`, `sessions.json`, private keys, …)
/// must never drift with the launch directory or land in a shared/downloads
/// folder.
pub fn default_base_dir() -> PathBuf {
    // An explicit override wins so every path helper (data/run/log + the website
    // (`nginx/`) and web stores that resolve through here) shares one base with
    // `PanelConfig::from_env`. Without this the supervisor's pid/lock/version
    // would honor the override while persisted credentials/state stayed under
    // /var/dn7/panel — a split that breaks isolated/test deployments.
    if let Some(dir) = std::env::var_os("DN7_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let p = PathBuf::from(INSTALL_DIR);
    if p.is_dir() {
        return p;
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/state/dn7-panel");
        }
    }
    // Last resort (HOME unset): a fixed temp-based dir — still not the CWD.
    std::env::temp_dir().join("dn7-panel")
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
