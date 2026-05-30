//! Agent self-update.
//!
//! On an upgrade command, the agent downloads the latest binary from the
//! download/CDN service, atomically replaces its own executable, and exits so
//! the service manager (systemd, `Restart=always`) relaunches it on the new
//! version.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};

/// Download the binary at `url` and replace the currently-running executable
/// with it. Returns the path that was replaced. The caller should then exit.
pub async fn self_replace(url: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("resolve current exe path")?;
    tracing::info!(%url, target = ?exe, "downloading update");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;
    let resp = http.get(url).send().await?.error_for_status()?;
    let bytes = resp.bytes().await?;
    if bytes.is_empty() {
        return Err(anyhow!("downloaded binary is empty"));
    }

    // Write to a temp file alongside the target, set +x, then atomically rename
    // over the current executable. Rename over a running binary is safe on
    // Linux: the running process keeps the old inode until it exits.
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("exe has no parent dir"))?;
    let tmp = dir.join(format!(
        ".{}.update",
        exe.file_name().and_then(|n| n.to_str()).unwrap_or("agent")
    ));

    tokio::fs::write(&tmp, &bytes)
        .await
        .context("write update temp file")?;
    let perms = std::fs::Permissions::from_mode(0o755);
    tokio::fs::set_permissions(&tmp, perms)
        .await
        .context("chmod update temp file")?;
    tokio::fs::rename(&tmp, &exe)
        .await
        .context("replace current executable")?;

    tracing::info!(bytes = bytes.len(), "update installed; exiting for service manager restart");
    Ok(exe)
}
