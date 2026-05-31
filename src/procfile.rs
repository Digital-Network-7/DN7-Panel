//! Process coordination primitives shared by the supervisor and agent roles:
//! pid files, heartbeat timestamps, liveness checks, and an flock-based guard
//! that prevents two instances of the same role from running concurrently.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use fs2::FileExt;

/// Paths for one role ("agent" or "supervisor") within a runtime directory.
pub struct RolePaths {
    pub pid: PathBuf,
    pub heartbeat: PathBuf,
    pub lock: PathBuf,
}

impl RolePaths {
    pub fn new(runtime_dir: &Path, role: &str) -> Self {
        RolePaths {
            pid: runtime_dir.join(format!("teaops-{role}.pid")),
            heartbeat: runtime_dir.join(format!("teaops-{role}.heartbeat")),
            lock: runtime_dir.join(format!("teaops-{role}.lock")),
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

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// A held flock guard. Dropping it releases the lock.
pub struct LockGuard {
    _file: File,
}

/// Try to acquire an exclusive, non-blocking lock for a role. Returns None if
/// another instance already holds it (i.e. that role is already running).
pub fn try_lock(path: &Path) -> Result<Option<LockGuard>> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
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
