//! Self-update and binary installation.
//!
//! Self-update: fetch the latest binary (GitHub-first, see `fetch`), atomically
//! replace the running executable, and exit so the supervisor role relaunches
//! it on the new version. There is a single binary that runs as either role, so
//! one self-update covers both.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::config::AgentConfig;
use crate::fetch;

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

/// Self-update: fetch latest (GitHub-first) and replace own exe.
/// Returns the replaced path; the caller should then exit.
pub async fn self_update(cfg: &AgentConfig) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve current exe path")?;
    tracing::info!(target = ?exe, "self-update: fetching latest binary");
    let bytes = fetch::fetch_latest(cfg).await?;
    install_bytes(&bytes, &exe).await?;
    tracing::info!(bytes = bytes.len(), "self-update installed; exiting for restart");
    Ok(exe)
}
