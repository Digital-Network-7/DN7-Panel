//! Self-update: dual-source download, atomic binary replacement, and the
//! persisted update preferences that drive it.
//!
//! There is a single binary that runs as either role, so one self-update covers
//! both: fetch the latest binary (see `fetch`), atomically replace the running
//! executable at the stable install path, and exit so the supervisor relaunches
//! it on the new version.
//!
//! Source selection (GitHub vs dn7.cn) is sticky: an explicit preference is
//! honoured; otherwise a remembered probe winner is reused for a week, and a
//! download failure fails over to the other source (forcing a re-probe).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::PanelConfig;
use crate::fetch::{self, Release, SourceKind};

mod changelog;
pub(crate) use changelog::*;

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
pub fn try_begin() -> bool {
    IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}
fn end() {
    IN_PROGRESS.store(false, Ordering::SeqCst);
}
pub fn in_progress() -> bool {
    IN_PROGRESS.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Persisted update preferences (`<data>/update.json`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateState {
    /// Apply updates automatically when a newer version is found.
    #[serde(default)]
    pub auto: bool,
    /// Update source: `dn7` (default; Digital Network 7 mirror) or `github`
    /// (the "preview experience" channel). No auto speed-probe.
    #[serde(default = "default_pref")]
    pub source_pref: String,
    /// Legacy fields kept for backward compatibility with older state files.
    #[serde(default)]
    pub chosen: Option<String>,
    #[serde(default)]
    pub probed_at: u64,
}

fn default_pref() -> String {
    "dn7".to_string()
}

impl Default for UpdateState {
    fn default() -> Self {
        UpdateState {
            auto: false,
            source_pref: default_pref(),
            chosen: None,
            probed_at: 0,
        }
    }
}

fn state_path() -> PathBuf {
    crate::paths::data_dir().join("update.json")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl UpdateState {
    pub fn load() -> Self {
        if let Ok(raw) = std::fs::read_to_string(state_path()) {
            if let Ok(s) = serde_json::from_str::<UpdateState>(&raw) {
                return s;
            }
        }
        UpdateState::default()
    }

    pub fn save(&self) -> Result<()> {
        let path = state_path();
        crate::paths::write_private(&path, serde_json::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Version comparison
// ---------------------------------------------------------------------------

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
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
// Source resolution
// ---------------------------------------------------------------------------

/// Pick the release to use per the persisted preference. No speed probing: the
/// "preview" toggle maps to `github`; default is the Digital Network 7 mirror
/// (`dn7`), which is reliable from mainland China.
async fn resolve_release(cfg: &PanelConfig) -> Result<Release> {
    let st = UpdateState::load();
    let k = SourceKind::from_str(&st.source_pref).unwrap_or(SourceKind::Dn7);
    fetch::release_from(cfg, k).await
}

/// Result of an update check, surfaced to the UI.
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub current: String,
    pub latest: Option<String>,
    pub has_update: bool,
    pub source: Option<String>,
    pub auto: bool,
    pub source_pref: String,
}

/// Resolve the latest version from the selected source (no probing) and report
/// whether a newer build is available.
pub async fn check(cfg: &PanelConfig) -> CheckResult {
    set_phase(PHASE_CHECKING);
    let st = UpdateState::load();
    let k = SourceKind::from_str(&st.source_pref).unwrap_or(SourceKind::Dn7);
    let current = env!("CARGO_PKG_VERSION").to_string();
    let latest = fetch::release_from(cfg, k).await.ok().map(|r| r.version);
    let has_update = latest
        .as_deref()
        .map(|l| is_newer(&current, l))
        .unwrap_or(false);
    if phase() == PHASE_CHECKING {
        set_phase(PHASE_IDLE);
    }
    CheckResult {
        current,
        latest,
        has_update,
        source: Some(k.as_str().to_string()),
        auto: st.auto,
        source_pref: st.source_pref,
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
    // Anti-rollback: refuse anything that isn't strictly newer than us.
    let current = env!("CARGO_PKG_VERSION");
    match read_binary_version(&tmp).await {
        Ok(v) if is_newer(current, &v) => {
            tracing::info!(from = current, to = %v, "self-update: version gate passed");
        }
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
    }
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
    let target = crate::paths::stable_bin();
    set_phase(PHASE_DOWNLOADING);
    set_progress(0);
    set_bytes(0, 0);
    let primary = resolve_release(cfg).await?;
    tracing::info!(
        source = primary.source.as_str(),
        version = %primary.version,
        ?target,
        "self-update: downloading"
    );
    let bytes = match fetch::download_release(&primary, set_progress).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                "self-update: source {} failed ({e}); failing over",
                primary.source.as_str()
            );
            // Force a re-probe next time and try the other source now.
            let mut st = UpdateState::load();
            st.chosen = None;
            st.probed_at = 0;
            let _ = st.save();
            set_progress(0);
            set_bytes(0, 0);
            let fb = fetch::release_from(cfg, primary.source.other()).await?;
            fetch::download_release(&fb, set_progress).await?
        }
    };
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
    if !try_begin() {
        tracing::info!("self-update already in progress; ignoring duplicate trigger");
        return;
    }
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
            end();
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
                // A cheap version check (no speed probe): resolve the source and
                // read its latest version.
                if let Ok(rel) = resolve_release(&cfg).await {
                    let current = env!("CARGO_PKG_VERSION");
                    if is_newer(current, &rel.version) {
                        tracing::info!(
                            latest = %rel.version,
                            source = rel.source.as_str(),
                            auto = st.auto,
                            "update available"
                        );
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
