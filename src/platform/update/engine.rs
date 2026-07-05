//! Self-update engine: download/verify/install, version state, periodic checker.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::infra::support::fetch;
use crate::platform::config::PanelConfig;

use super::skiplist::{is_version_skipped, record_attempted_version};

// ---------------------------------------------------------------------------
// Global self-update progress state (read by the UI via /api/update/status).
// ---------------------------------------------------------------------------

pub const PHASE_IDLE: u8 = 0;
pub const PHASE_CHECKING: u8 = 1;
pub const PHASE_DOWNLOADING: u8 = 2;
pub const PHASE_INSTALLING: u8 = 3;
pub const PHASE_ERROR: u8 = 4;

/// Exit code the panel uses after a successful self-update, signalling the
/// supervisor to re-exec itself immediately (single combined restart) instead
/// of respawning the panel and re-exec'ing a version_check interval later.
pub const EXIT_UPDATED: i32 = 77;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_IDLE);
static PROGRESS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
static DONE_BYTES: AtomicU64 = AtomicU64::new(0);
static IN_PROGRESS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn phase() -> u8 {
    PHASE.load(Ordering::Relaxed)
}
pub fn progress() -> u64 {
    PROGRESS.load(Ordering::Relaxed)
}
pub fn total_bytes() -> u64 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}
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
pub fn set_bytes(done: u64, total: u64) {
    DONE_BYTES.store(done, Ordering::Relaxed);
    TOTAL_BYTES.store(total, Ordering::Relaxed);
}
fn end() {
    IN_PROGRESS.store(false, Ordering::SeqCst);
}
pub fn in_progress() -> bool {
    IN_PROGRESS.load(Ordering::SeqCst)
}

/// RAII guard proving this task holds the single in-progress slot. Obtained via
/// [`try_begin_guard`]; its `Drop` releases the slot on **every** exit path
/// (success, error, panic), so an owned runner can never leak the flag. The
/// success path `std::process::exit`s before Drop runs, which is fine — the
/// process is going away, so the slot doesn't need releasing.
pub struct InProgressGuard {
    _private: (),
}

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        end();
    }
}

/// Atomically claim the in-progress slot, returning an RAII guard on success or
/// `None` if an update is already running. This is the single point of mutual
/// exclusion: callers must hold the returned guard for the whole update and let
/// it drop to release the slot.
pub fn try_begin_guard() -> Option<InProgressGuard> {
    IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
        .then_some(InProgressGuard { _private: () })
}

// ---------------------------------------------------------------------------
// Persisted update preferences (`<data>/update.json`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateState {
    /// Apply updates automatically when a newer version is found.
    #[serde(default)]
    pub auto: bool,
    /// Version last swapped in but whose boot the supervisor hasn't confirmed —
    /// persisted before the swap so a rollback can learn which version failed even
    /// across the re-exec. See the [`skiplist`](super::skiplist) module.
    #[serde(default)]
    pub attempted_version: Option<String>,
    /// Versions that were installed, failed to boot, and were rolled back. The
    /// auto-checker + install path refuse these (breaks the re-download loop). See
    /// the [`skiplist`](super::skiplist) module.
    #[serde(default)]
    pub failed_versions: Vec<String>,
    /// Legacy fields kept for backward compatibility with older state files.
    #[serde(default)]
    pub chosen: Option<String>,
    #[serde(default)]
    pub probed_at: u64,
}

fn state_path() -> PathBuf {
    crate::platform::paths::data_dir().join("update.json")
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl UpdateState {
    pub fn load() -> Self {
        crate::infra::support::json_store::load_or_default(&state_path())
    }

    pub fn save(&self) -> Result<()> {
        crate::infra::support::json_store::save_private(&state_path(), self)
    }
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

pub(crate) fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

/// True if `latest` is a strictly newer semver than `current`.
pub fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(cur), Some(lat)) => lat > cur,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Latest-version resolution
// ---------------------------------------------------------------------------

/// The latest published version, from the `releases.json` index raced across all
/// mirror lines (whichever answers fastest wins). The index lists every release;
/// the newest by semver is the latest. `None` if no line served a valid index.
async fn latest_version(cfg: &PanelConfig) -> Option<String> {
    let index = fetch::releases_index_raced(cfg).await.ok()?;
    index
        .iter()
        .filter_map(|e| parse_semver(&e.version).map(|s| (s, e.version.clone())))
        .max_by_key(|(s, _)| *s)
        .map(|(_, v)| v)
}

/// Result of an update check, surfaced to the UI.
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub current: String,
    pub latest: Option<String>,
    pub has_update: bool,
    pub auto: bool,
}

/// Resolve the latest version (fastest reachable line) and report whether a
/// newer build is available.
pub async fn check(cfg: &PanelConfig) -> CheckResult {
    set_phase(PHASE_CHECKING);
    let st = UpdateState::load();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = latest_version(cfg).await;
    // A version we already rolled back isn't offered (don't nag to re-install a
    // build known to fail to boot).
    let has_update = latest
        .as_deref()
        .map(|l| is_newer(&current, l) && !is_version_skipped(&st.failed_versions, l))
        .unwrap_or(false);
    if phase() == PHASE_CHECKING {
        set_phase(PHASE_IDLE);
    }
    CheckResult {
        current,
        latest,
        has_update,
        auto: st.auto,
    }
}

// ---------------------------------------------------------------------------
// Install + self-update
// ---------------------------------------------------------------------------

/// Write `bytes` to `target` atomically, but only after the freshly-downloaded
/// (already signature-verified) binary reports a **strictly newer** version
/// than ours — an anti-rollback guard so a compromised mirror can't push an old
/// but validly-signed (vulnerable) build. The binary keeps the old inode while
/// running, so the rename is safe even though we're replacing ourselves.
pub async fn install_verified(bytes: &[u8], target: &Path) -> Result<()> {
    if bytes.is_empty() {
        return Err(anyhow!("refusing to install empty binary"));
    }
    let dir = target
        .parent()
        .ok_or_else(|| anyhow!("target has no parent dir"))?;
    tokio::fs::create_dir_all(dir).await.ok();
    // Unpredictable name + O_EXCL: a predictable `.{name}.dl` that we write with
    // a symlink-following, non-exclusive open let a local attacker pre-plant a
    // symlink and redirect the (root) write. create_new refuses to follow a
    // pre-existing path, and the random suffix isn't guessable.
    let suffix: u64 = rand::random();
    let tmp = dir.join(format!(
        ".{}.{suffix:016x}.dl",
        target.file_name().and_then(|n| n.to_str()).unwrap_or("bin")
    ));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never follow/clobber an existing path
            .mode(0o755)
            .open(&tmp)
            .context("create temp binary")?;
        f.write_all(bytes).context("write temp binary")?;
        f.flush().context("flush temp binary")?;
    }
    // Anti-rollback: refuse anything not strictly newer than us, and refuse a
    // version we already tried and rolled back (the `skiplist`) — without it the
    // same bad build passes `is_newer` against the old running version forever.
    let current = env!("CARGO_PKG_VERSION");
    let new_version = match read_binary_version(&tmp).await {
        Ok(v) if is_newer(current, &v) => v,
        Ok(v) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(anyhow!(
                "downloaded version {v} is not newer than {current} — refusing (rollback?)"
            ));
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(anyhow!("could not read downloaded binary version: {e}"));
        }
    };
    if is_version_skipped(&UpdateState::load().failed_versions, &new_version) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "downloaded version {new_version} previously failed to boot and was rolled back — refusing"
        ));
    }
    tracing::info!(from = current, to = %new_version, "self-update: version gate passed");
    // Persist the attempted version *before* the swap so a rollback (which
    // re-execs the supervisor) can still move it onto the failed-boot skiplist
    // even though nothing in memory survives the re-exec.
    record_attempted_version(&new_version);
    // Preserve the outgoing binary as a `.prev` sibling of the target (0755) so
    // the supervisor can restore it (one-shot) if the new build fails to come up.
    // Best-effort: a copy failure must never block a legitimate update — the
    // boot-success handshake still gates the swap, we just lose the rollback net.
    // Deriving the path from `target` (not a fresh `stable_bin()`) keeps the copy
    // on the same filesystem as the binary we're replacing.
    let prev = dir.join(format!(
        "{}.prev",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dn7-panel")
    ));
    match tokio::fs::copy(target, &prev).await {
        Ok(_) => {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&prev, std::fs::Permissions::from_mode(0o755)).await;
            tracing::info!(?prev, "self-update: saved previous binary for rollback");
        }
        Err(e) => {
            tracing::warn!("self-update: could not save previous binary ({e}); proceeding without rollback backup");
        }
    }
    // Clear any stale boot-ok marker: the marker's *reappearance* (written by the
    // next panel role once its console is up) is how the supervisor confirms this
    // new build booted. Absence-of-marker + presence-of-`.prev` is the on-disk
    // "update pending verification" state that survives the supervisor re-exec.
    let _ = tokio::fs::remove_file(crate::platform::paths::boot_marker()).await;

    tokio::fs::rename(&tmp, target)
        .await
        .context("install (rename) binary")?;
    Ok(())
}

/// Run `<path> version` and return its reported compiled version.
async fn read_binary_version(path: &Path) -> Result<String> {
    let out = tokio::process::Command::new(path)
        .arg("version")
        .output()
        .await?;
    if !out.status.success() {
        return Err(anyhow!("version subcommand exited with {}", out.status));
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        return Err(anyhow!("empty version output"));
    }
    Ok(v)
}

/// Fetch the latest binary (resolved source, failing over on download error)
/// and replace the binary at the stable install path. Returns the replaced
/// path; the caller should then exit so the supervisor relaunches the new build.
pub async fn self_update(cfg: &PanelConfig) -> Result<PathBuf> {
    let target = crate::platform::paths::stable_bin();
    set_phase(PHASE_DOWNLOADING);
    set_progress(0);
    set_bytes(0, 0);
    let version = latest_version(cfg)
        .await
        .ok_or_else(|| anyhow!("could not resolve the latest version from any line"))?;
    let current = env!("CARGO_PKG_VERSION");
    if !is_newer(current, &version) {
        return Err(anyhow!(
            "latest version {version} is not newer than {current} — nothing to do"
        ));
    }
    tracing::info!(%version, ?target, "self-update: downloading");
    // `download_binary_raced` probes every line, downloads from the fastest, and
    // fails over to the next on any error — so there is no outer failover here.
    let bytes = fetch::download_binary_raced(cfg, &version, set_progress).await?;
    set_phase(PHASE_INSTALLING);
    install_verified(&bytes, &target).await?;
    tracing::info!(
        bytes = bytes.len(),
        "self-update installed; exiting for restart"
    );
    Ok(target)
}

/// Run a full self-update in the background: download first (the UI shows
/// progress), then swap the binary in and exit so the supervisor relaunches us
/// on the new version. Downloading BEFORE exiting means a slow network never
/// leaves the host without a running panel.
pub async fn run_self_update(cfg: &PanelConfig) {
    match try_begin_guard() {
        Some(guard) => run_self_update_owned(cfg, guard).await,
        None => {
            tracing::info!("self-update already in progress; ignoring duplicate trigger");
        }
    }
}

/// Same as [`run_self_update`] but the caller has **already** claimed the
/// in-progress slot and passes ownership of the [`InProgressGuard`]. Used by the
/// apply handler, which must claim the slot before spawning so a concurrent
/// request can be rejected synchronously instead of both reporting success. The
/// guard releases the slot on every error/return path via its `Drop`.
pub async fn run_self_update_owned(cfg: &PanelConfig, guard: InProgressGuard) {
    match self_update(cfg).await {
        Ok(_) => {
            tracing::info!("upgrade complete; exiting for restart");
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            std::process::exit(EXIT_UPDATED);
        }
        Err(e) => {
            tracing::warn!("self-update failed: {e}");
            set_phase(PHASE_ERROR);
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            set_phase(PHASE_IDLE);
            set_progress(0);
            set_bytes(0, 0);
            drop(guard);
        }
    }
}

// ---------------------------------------------------------------------------
// Periodic checker (spawned by the panel role)
// ---------------------------------------------------------------------------

/// Background loop: check for a newer version periodically. When auto-update is
/// on it checks every minute and applies a newer build automatically; when off
/// it checks hourly (so the UI's "update available" hint stays warm) and never
/// applies on its own.
pub fn spawn_periodic(cfg: PanelConfig) {
    tokio::spawn(async move {
        // Small initial delay so startup isn't slowed by a network round-trip.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            let st = UpdateState::load();
            let interval = if st.auto { 60 } else { 3600 };
            if !in_progress() {
                // A cheap version check: race the lines for the release index and
                // read the newest version.
                if let Some(version) = latest_version(&cfg).await {
                    let current = env!("CARGO_PKG_VERSION");
                    // Skip a version we already tried and rolled back: re-offering
                    // it would just loop the same failed boot (see `skiplist`).
                    let skipped = is_version_skipped(&st.failed_versions, &version);
                    if is_newer(current, &version) && !skipped {
                        tracing::info!(%version, auto = st.auto, "update available");
                        if st.auto {
                            run_self_update(&cfg).await;
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // The apply handler relies on `try_begin_guard` being the single point of
    // mutual exclusion: exactly one caller may hold the slot, and dropping the
    // guard must release it (RAII) so a later attempt can succeed. This is the
    // invariant that stops two concurrent /api/update/apply requests from both
    // reporting `started: true`.
    #[test]
    fn guard_is_exclusive_and_released_on_drop() {
        // NOTE: touches the process-global IN_PROGRESS flag; keep this the only
        // test that does so to avoid cross-test interference.
        let g = try_begin_guard().expect("first claim succeeds");
        assert!(in_progress(), "slot is held while the guard is alive");
        assert!(
            try_begin_guard().is_none(),
            "a second claim is rejected while the guard is held"
        );
        drop(g);
        assert!(!in_progress(), "dropping the guard releases the slot");

        // A fresh claim works again now that the slot is free.
        let g2 = try_begin_guard().expect("re-claim after release succeeds");
        drop(g2);
        assert!(!in_progress());
    }
}
