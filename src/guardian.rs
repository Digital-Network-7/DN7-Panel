//! Agent-side half of the mutual supervision protocol.
//!
//! The agent:
//! - writes its own pid + a periodic heartbeat so agentd can detect liveness,
//! - optionally watches agentd's heartbeat and relaunches agentd (under a file
//!   lock, with an adoption check) if it dies.
//!
//! This mirrors the primitives in teaops-agentd's `procfile` module.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;

use crate::config::AgentConfig;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn role_path(dir: &Path, role: &str, ext: &str) -> PathBuf {
    dir.join(format!("teaops-{role}.{ext}"))
}

fn write_file(path: &Path, contents: &str) {
    if let Ok(mut f) = File::create(path) {
        let _ = f.write_all(contents.as_bytes());
    }
}

fn read_u64(path: &Path) -> Option<u64> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

fn read_u32(path: &Path) -> Option<u32> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    s.trim().parse().ok()
}

fn pid_alive(pid: u32) -> bool {
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

/// Write the agent's own pid file (call once at startup).
pub fn write_own_pid(cfg: &AgentConfig) {
    let _ = std::fs::create_dir_all(&cfg.runtime_dir);
    write_file(
        &role_path(&cfg.runtime_dir, "agent", "pid"),
        &std::process::id().to_string(),
    );
    touch_own_heartbeat(cfg);
}

/// Refresh the agent's heartbeat (call each loop iteration).
pub fn touch_own_heartbeat(cfg: &AgentConfig) {
    write_file(
        &role_path(&cfg.runtime_dir, "agent", "heartbeat"),
        &now_secs().to_string(),
    );
}

/// Whether agentd appears alive (fresh heartbeat or live pid).
fn agentd_alive(cfg: &AgentConfig) -> bool {
    if let Some(pid) = read_u32(&role_path(&cfg.runtime_dir, "agentd", "pid")) {
        if pid_alive(pid) {
            return true;
        }
    }
    match read_u64(&role_path(&cfg.runtime_dir, "agentd", "heartbeat")) {
        Some(ts) => now_secs().saturating_sub(ts) <= cfg.heartbeat_timeout_secs,
        None => false,
    }
}

/// Spawn the guardian background task: periodically ensure agentd is alive and
/// relaunch it under a lock if it isn't. No-op unless `guard_agentd` is set.
/// If the agentd binary is missing, it is fetched first (GitHub-first).
pub fn spawn(cfg: AgentConfig) {
    if !cfg.guard_agentd {
        return;
    }
    tokio::spawn(async move {
        let interval = cfg.heartbeat_timeout_secs.max(3);
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
        loop {
            ticker.tick().await;
            if agentd_alive(&cfg) {
                continue;
            }
            // agentd looks dead — try to relaunch it, but only one relauncher
            // wins the lock, and we re-check liveness after acquiring it.
            let lock_path = role_path(&cfg.runtime_dir, "agentd-relaunch", "lock");
            let lock_file = match OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(f) => f,
                Err(_) => continue,
            };
            if lock_file.try_lock_exclusive().is_err() {
                // Someone else is relaunching; skip.
                continue;
            }
            // Re-check after locking to avoid a race / duplicate spawn.
            if agentd_alive(&cfg) {
                let _ = fs2::FileExt::unlock(&lock_file);
                continue;
            }

            // Ensure the agentd binary exists (re-fetch if deleted/missing).
            if let Err(e) =
                crate::update::ensure_binary(&cfg, crate::fetch::Component::Agentd, &cfg.agentd_bin)
                    .await
            {
                tracing::warn!("cannot relaunch agentd, binary unavailable: {e}");
                let _ = fs2::FileExt::unlock(&lock_file);
                continue;
            }

            tracing::warn!("agentd appears dead; relaunching it");
            match Command::new(&cfg.agentd_bin)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(_) => tracing::info!("agentd relaunched"),
                Err(e) => tracing::warn!("failed to relaunch agentd: {e}"),
            }
            let _ = fs2::FileExt::unlock(&lock_file);
        }
    });
}
