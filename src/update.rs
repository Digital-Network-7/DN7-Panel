//! Agent self-update and binary installation.
//!
//! Self-update: fetch the latest agent binary (GitHub-first, see `fetch`),
//! atomically replace the running executable, and exit so the supervisor
//! (teaops-agentd or systemd) relaunches it on the new version.
//!
//! Also exposes `install_bytes` so a missing/deleted binary (agent or agentd)
//! can be re-fetched and written to a target path without exiting.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::config::AgentConfig;
use crate::fetch::{self, Component};

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

/// Self-update the agent: fetch latest (GitHub-first) and replace own exe.
/// Returns the replaced path; the caller should then exit.
pub async fn self_update(cfg: &AgentConfig) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve current exe path")?;
    tracing::info!(target = ?exe, "self-update: fetching latest agent binary");
    let bytes = fetch::fetch_latest(cfg, Component::Agent).await?;
    install_bytes(&bytes, &exe).await?;
    tracing::info!(bytes = bytes.len(), "self-update installed; exiting for restart");
    Ok(exe)
}

/// Ensure a component's binary exists at `path`; if missing, fetch and install
/// it (GitHub-first). No-op if the file is already present.
pub async fn ensure_binary(cfg: &AgentConfig, component: Component, path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    tracing::warn!(?path, "binary missing; fetching");
    let bytes = fetch::fetch_latest(cfg, component).await?;
    install_bytes(&bytes, path).await?;
    tracing::info!(?path, bytes = bytes.len(), "fetched missing binary");
    Ok(())
}
