//! Self-update engine: download/verify/install, version state, periodic checker.
//! The progress-state atomics + in-progress guard live in [`super::progress`].
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::infra::support::fetch;
use crate::platform::config::PanelConfig;

use super::progress::*;
use super::skiplist::{is_version_skipped, record_attempted_release};

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

/// This build's independent build number (compiled in via build.rs → DN7_BUILD;
/// "0" for local/dev builds where the env isn't set).
pub(crate) fn current_build() -> u64 {
    option_env!("DN7_BUILD")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// True if release `(new_ver, new_build)` is strictly newer than `(cur_ver,
/// cur_build)`: versions are compared by semver first, then the build number.
/// This is what lets a pure build bump (same version, higher build) count as an
/// update.
pub fn is_newer_build(cur_ver: &str, cur_build: u64, new_ver: &str, new_build: u64) -> bool {
    match (parse_semver(cur_ver), parse_semver(new_ver)) {
        (Some(c), Some(n)) => (n, new_build) > (c, cur_build),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Latest-release resolution
// ---------------------------------------------------------------------------

/// The latest published `(version, build)`, from the `releases.json` index raced
/// across all mirror lines (whichever answers fastest wins). The index lists every
/// release; the newest by (semver, build) wins. `None` if no line served a valid
/// index.
async fn latest_release(cfg: &PanelConfig) -> Option<(String, u64)> {
    let index = fetch::releases_index_raced(cfg).await.ok()?;
    index
        .iter()
        .filter_map(|e| {
            parse_semver(&e.version).map(|s| {
                (
                    s,
                    e.build.trim().parse::<u64>().unwrap_or(0),
                    e.version.clone(),
                )
            })
        })
        .max_by_key(|(s, b, _)| (*s, *b))
        .map(|(_, b, v)| (v, b))
}

/// Result of an update check, surfaced to the UI.
#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub current: String,
    pub build: u64,
    pub latest: Option<String>,
    pub latest_build: Option<u64>,
    pub has_update: bool,
    pub auto: bool,
}

/// Resolve the latest release (fastest reachable line) and report whether a newer
/// build — by (version, build) — is available.
pub async fn check(cfg: &PanelConfig) -> CheckResult {
    set_phase(PHASE_CHECKING);
    let st = UpdateState::load();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let cur_build = current_build();
    let latest = latest_release(cfg).await;
    // A build we already rolled back isn't offered (don't nag to re-install a
    // build known to fail to boot).
    let has_update = latest
        .as_ref()
        .map(|(lv, lb)| {
            is_newer_build(&current, cur_build, lv, *lb)
                && !is_version_skipped(&st.failed_versions, lv, *lb)
        })
        .unwrap_or(false);
    if phase() == PHASE_CHECKING {
        set_phase(PHASE_IDLE);
    }
    CheckResult {
        current,
        build: cur_build,
        latest: latest.as_ref().map(|(v, _)| v.clone()),
        latest_build: latest.as_ref().map(|(_, b)| *b),
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
    // Anti-rollback: refuse anything not strictly newer than us by (version,
    // build) — read the DOWNLOADED binary's own reported build, never the mirror's
    // claim, so a hostile line can't downgrade us to an older signed build of the
    // same version. Also refuse a build we already tried and rolled back (the
    // `skiplist`), else the same bad build passes the gate forever.
    let current = env!("CARGO_PKG_VERSION");
    let cur_build = current_build();
    let (new_version, new_build) = match read_binary_release(&tmp).await {
        Ok((v, b)) if is_newer_build(current, cur_build, &v, b) => (v, b),
        Ok((v, b)) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(anyhow!(
                "downloaded {v} (build {b}) is not newer than {current} (build {cur_build}) — refusing (rollback?)"
            ));
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(anyhow!("could not read downloaded binary version: {e}"));
        }
    };
    if is_version_skipped(
        &UpdateState::load().failed_versions,
        &new_version,
        new_build,
    ) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(anyhow!(
            "downloaded {new_version} (build {new_build}) previously failed to boot and was rolled back — refusing"
        ));
    }
    tracing::info!(from = current, from_build = cur_build, to = %new_version, to_build = new_build, "self-update: version gate passed");
    // Persist the attempted release *before* the swap so a rollback (which
    // re-execs the supervisor) can still move it onto the failed-boot skiplist
    // even though nothing in memory survives the re-exec.
    record_attempted_release(&new_version, new_build);
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

/// Run `<path> version` and parse its reported `(version, build)`. The subcommand
/// prints `"<version> (build <N>)"`; older binaries print just `"<version>"`, in
/// which case the build reads as 0.
async fn read_binary_release(path: &Path) -> Result<(String, u64)> {
    let out = tokio::process::Command::new(path)
        .arg("version")
        .output()
        .await?;
    if !out.status.success() {
        return Err(anyhow!("version subcommand exited with {}", out.status));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let version = s.split_whitespace().next().unwrap_or("").to_string();
    if version.is_empty() {
        return Err(anyhow!("empty version output"));
    }
    // Build number = the first run of digits after the word "build"; absent → 0.
    let build = s
        .split_once("build")
        .and_then(|(_, rest)| {
            let digits: String = rest
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            digits.parse().ok()
        })
        .unwrap_or(0);
    Ok((version, build))
}

/// Fetch the latest binary (resolved source, failing over on download error)
/// and replace the binary at the stable install path. Returns the replaced
/// path; the caller should then exit so the supervisor relaunches the new build.
pub async fn self_update(cfg: &PanelConfig) -> Result<PathBuf> {
    let target = crate::platform::paths::stable_bin();
    set_phase(PHASE_DOWNLOADING);
    set_progress(0);
    set_bytes(0, 0);
    let (version, build) = latest_release(cfg)
        .await
        .ok_or_else(|| anyhow!("could not resolve the latest release from any line"))?;
    let current = env!("CARGO_PKG_VERSION");
    let cur_build = current_build();
    if !is_newer_build(current, cur_build, &version, build) {
        return Err(anyhow!(
            "latest {version} (build {build}) is not newer than {current} (build {cur_build}) — nothing to do"
        ));
    }
    tracing::info!(%version, build, ?target, "self-update: downloading");
    // `download_binary_raced` probes every line, downloads from the fastest, and
    // fails over to the next on any error — so there is no outer failover here.
    let bytes = fetch::download_binary_raced(cfg, &version, build, set_progress).await?;
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
                // A cheap check: race the lines for the release index and read the
                // newest (version, build).
                if let Some((version, build)) = latest_release(&cfg).await {
                    let current = env!("CARGO_PKG_VERSION");
                    let cur_build = current_build();
                    // Skip a build we already tried and rolled back: re-offering it
                    // would just loop the same failed boot (see `skiplist`).
                    let skipped = is_version_skipped(&st.failed_versions, &version, build);
                    if is_newer_build(current, cur_build, &version, build) && !skipped {
                        tracing::info!(%version, build, auto = st.auto, "update available");
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
