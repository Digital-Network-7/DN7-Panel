//! Self-update and binary installation.
//!
//! Self-update: fetch the latest binary (GitHub-first, see `fetch`), atomically
//! replace the running executable, and exit so the supervisor role relaunches
//! it on the new version. There is a single binary that runs as either role, so
//! one self-update covers both.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use anyhow::{anyhow, Context, Result};

use crate::config::AgentConfig;
use crate::fetch;

// ---------------------------------------------------------------------------
// Global self-update progress state.
//
// Self-update runs in its own task so the metrics loop keeps reporting while a
// (possibly slow) download is in flight. Each tick the loop reads this state and
// includes it in the report, so the mini program can show live progress instead
// of the server appearing to hang/offline.
// ---------------------------------------------------------------------------

/// Update phase, encoded as a small integer for a lock-free atomic.
pub const PHASE_IDLE: u8 = 0;
pub const PHASE_CHECKING: u8 = 1;
pub const PHASE_DOWNLOADING: u8 = 2;
pub const PHASE_INSTALLING: u8 = 3;
pub const PHASE_ERROR: u8 = 4;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_IDLE);
/// Download progress percent (0..100); only meaningful while DOWNLOADING.
static PROGRESS: AtomicU64 = AtomicU64::new(0);
/// Total bytes of the binary being downloaded (0 until known); lets the UI show
/// "current MB / total MB" instead of just a percent.
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
/// Bytes downloaded so far (only meaningful while DOWNLOADING).
static DONE_BYTES: AtomicU64 = AtomicU64::new(0);

/// True while a self-update task is running (download/install in progress), used
/// to coalesce duplicate upgrade triggers.
static IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn phase() -> u8 {
    PHASE.load(Ordering::Relaxed)
}
pub fn progress() -> u64 {
    PROGRESS.load(Ordering::Relaxed)
}
/// Total bytes of the in-flight download (0 until the content length is known).
pub fn total_bytes() -> u64 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}
/// Bytes downloaded so far in the in-flight download.
pub fn done_bytes() -> u64 {
    DONE_BYTES.load(Ordering::Relaxed)
}
pub fn phase_str() -> &'static str {
    match phase() {
        PHASE_CHECKING => "checking",
        PHASE_DOWNLOADING => "downloading",
        PHASE_INSTALLING => "installing",
        PHASE_ERROR => "error",
        _ => "idle",
    }
}
fn set_phase(p: u8) {
    PHASE.store(p, Ordering::Relaxed);
}
fn set_progress(pct: u64) {
    PROGRESS.store(pct.min(100), Ordering::Relaxed);
}
/// Record the total/done byte counts for the in-flight download.
pub fn set_bytes(done: u64, total: u64) {
    DONE_BYTES.store(done, Ordering::Relaxed);
    TOTAL_BYTES.store(total, Ordering::Relaxed);
}

/// Try to claim the single in-flight update slot. Returns false if one is
/// already running.
pub fn try_begin() -> bool {
    IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}
fn end() {
    IN_PROGRESS.store(false, Ordering::SeqCst);
}

/// Write `bytes` to `target` atomically with executable permissions.
pub async fn install_bytes(bytes: &[u8], target: &Path) -> Result<()> {
    if bytes.is_empty() {
        return Err(anyhow!("refusing to install empty binary"));
    }
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("target has no parent dir"))?;
    tokio::fs::create_dir_all(dir).await.ok();
    let tmp = dir.join(format!(
        ".{}.dl",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("bin")
    ));
    tokio::fs::write(&tmp, bytes)
        .await
        .context("write temp binary")?;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .await
        .context("chmod temp binary")?;
    // Rename over the target. Safe on Linux even if the target is running:
    // the running process keeps the old inode until it exits.
    tokio::fs::rename(&tmp, target)
        .await
        .context("install (rename) binary")?;
    Ok(())
}

/// Self-update: fetch latest (GitHub-first) and replace the binary at the stable
/// install path (`/var/ops/teaops-agent`, falling back to a cleaned current
/// exe). Writing to the stable path — not the raw `current_exe()` — means a
/// post-update "(deleted)" path never breaks the next update, and the canonical
/// binary the supervisor respawns is the one that gets upgraded.
/// Returns the replaced path; the caller should then exit.
pub async fn self_update(cfg: &AgentConfig) -> Result<PathBuf> {
    let target = crate::paths::stable_bin();
    tracing::info!(?target, "self-update: fetching latest binary");
    set_phase(PHASE_DOWNLOADING);
    set_progress(0);
    set_bytes(0, 0);
    let bytes = fetch::fetch_latest_with_progress(cfg, set_progress).await?;
    set_phase(PHASE_INSTALLING);
    install_bytes(&bytes, &target).await?;
    tracing::info!(
        bytes = bytes.len(),
        "self-update installed; exiting for restart"
    );
    Ok(target)
}

/// Run a full self-update in the background: download the new binary first (the
/// metrics loop keeps reporting + the UI shows progress), then swap it in and
/// exit so the supervisor relaunches us on the new version. Downloading BEFORE
/// exiting means a slow network never leaves the host without a running agent.
pub async fn run_self_update(cfg: &AgentConfig) {
    if !try_begin() {
        tracing::info!("self-update already in progress; ignoring duplicate trigger");
        return;
    }
    match self_update(cfg).await {
        Ok(_) => {
            tracing::info!("upgrade complete; exiting for restart");
            // Give the metrics loop one beat to flush the "installing" phase.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            std::process::exit(0);
        }
        Err(e) => {
            tracing::warn!("self-update failed: {e}");
            set_phase(PHASE_ERROR);
            // Clear the error after a short while so the UI returns to normal and
            // a later attempt can retry.
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            set_phase(PHASE_IDLE);
            set_progress(0);
            set_bytes(0, 0);
            end();
        }
    }
}
