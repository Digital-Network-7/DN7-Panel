//! Process coordination primitives shared by the supervisor and panel roles:
//! pid files, heartbeat timestamps, liveness checks, and an flock-based guard
//! that prevents two instances of the same role from running concurrently.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use fs2::FileExt;

/// Paths for one role ("panel" or "supervisor") within a runtime directory.
pub struct RolePaths {
    pub pid: PathBuf,
    pub heartbeat: PathBuf,
    pub lock: PathBuf,
}

impl RolePaths {
    pub fn new(runtime_dir: &Path, role: &str) -> Self {
        RolePaths {
            pid: runtime_dir.join(format!("dn7-{role}.pid")),
            heartbeat: runtime_dir.join(format!("dn7-{role}.heartbeat")),
            lock: runtime_dir.join(format!("dn7-{role}.lock")),
        }
    }
}

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write the current process pid to `path`.
pub fn write_pid(path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    write!(f, "{}", std::process::id())?;
    Ok(())
}

/// Read a pid from `path`, if present and parseable.
pub fn read_pid(path: &Path) -> Option<u32> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

/// Touch the heartbeat file with the current timestamp.
pub fn write_heartbeat(path: &Path) -> Result<()> {
    let mut f = File::create(path)?;
    write!(f, "{}", now_secs())?;
    Ok(())
}

/// Read the last heartbeat timestamp, if present.
pub fn read_heartbeat(path: &Path) -> Option<u64> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

/// Whether a role's heartbeat is fresh (peer considered alive).
pub fn heartbeat_fresh(path: &Path, timeout_secs: u64) -> bool {
    match read_heartbeat(path) {
        Some(ts) => now_secs().saturating_sub(ts) <= timeout_secs,
        None => false,
    }
}

/// Whether a process with `pid` is currently alive (kill -0 semantics).
pub fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 performs error checking without sending a signal.
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

/// Send a signal to a pid (best-effort; errors such as ESRCH are ignored).
pub fn signal_pid(pid: u32, sig: i32) {
    // SAFETY: a plain kill(2); failure (e.g. the pid already exited) is fine.
    unsafe {
        libc_kill(pid as i32, sig);
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Path of the file recording the version of the currently-running panel. The
/// supervisor writes it on startup; a fresh foreground launch reads it to decide
/// whether to replace the running instance with a newer binary. Lives in the
/// persisted-data dir (callers pass `cfg.data_dir`).
pub fn version_path(data_dir: &Path) -> PathBuf {
    data_dir.join("dn7-panel.version")
}

/// Record this binary's version as the running version (best-effort).
pub fn write_version(data_dir: &Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let _ = std::fs::write(version_path(data_dir), env!("CARGO_PKG_VERSION"));
}

/// Read the recorded running version, if present.
pub fn read_version(data_dir: &Path) -> Option<String> {
    std::fs::read_to_string(version_path(data_dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A held flock guard. Dropping it releases the lock.
pub struct LockGuard {
    _file: File,
}

impl LockGuard {
    /// Explicitly release the flock now (rather than waiting for drop). Needed
    /// before a re-exec: the locked fd is inherited across exec (no CLOEXEC),
    /// so the replacement process would otherwise fail to re-acquire its own
    /// role lock and exit as "already running".
    pub fn release(&self) {
        let _ = fs2::FileExt::unlock(&self._file);
    }

    /// Re-acquire the flock on the same fd after a [`release`](Self::release).
    /// Used to recover the single-instance guard when a re-exec fails and the
    /// supervisor must keep running — otherwise it would carry on holding no
    /// lock, letting a second supervisor start. Returns true if the lock is held
    /// again; false if another process grabbed it in the meantime.
    pub fn reacquire(&self) -> bool {
        fs2::FileExt::try_lock_exclusive(&self._file).is_ok()
    }
}

/// Try to acquire an exclusive, non-blocking lock for a role. Returns None if
/// another instance already holds it (i.e. that role is already running).
pub fn try_lock(path: &Path) -> Result<Option<LockGuard>> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(LockGuard { _file: file })),
        Err(_) => Ok(None),
    }
}

/// True if a role appears alive: a live pid or a fresh heartbeat.
pub fn role_alive(paths: &RolePaths, timeout_secs: u64) -> bool {
    if let Some(pid) = read_pid(&paths.pid) {
        if pid_alive(pid) {
            return true;
        }
    }
    heartbeat_fresh(&paths.heartbeat, timeout_secs)
}
