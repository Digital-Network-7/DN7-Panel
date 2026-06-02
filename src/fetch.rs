//! Binary acquisition from the TeaOps backend's distribution endpoints.
//!
//! There is a single binary (it runs as either the supervisor or the agent
//! role depending on argv). The backend (`api.teaops.dn7.cn`) is now the sole
//! update source — it mirrors agent releases (CI push + multi-source pull) and
//! serves them rate-limited under `/agent/dist/*`. The agent never contacts
//! GitHub or the old downloader directly.
//!
//! Used both for self-update and for re-fetching a missing/deleted binary.

use anyhow::{anyhow, Result};

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("teaops-agent/updater")
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .expect("http client")
}

/// Architecture token the backend expects (`x86_64` / `arm64`).
fn arch() -> &'static str {
    // Compile-time target arch; the agent binary is arch-specific anyway.
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

/// Download the latest agent binary from the backend, reporting download
/// percent (0..100) via `on_progress` as bytes arrive.
pub async fn fetch_latest_with_progress<F: Fn(u64) + Copy>(
    cfg: &crate::config::AgentConfig,
    on_progress: F,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}/agent/dist/download?arch={}&rate=3145728",
        cfg.backend_url.trim_end_matches('/'),
        arch()
    );
    let resp = http().get(&url).send().await?.error_for_status()?;
    let bytes = download_streaming(resp, on_progress).await?;
    if bytes.is_empty() {
        return Err(anyhow!("backend returned an empty binary"));
    }
    tracing::info!("fetched agent binary from backend");
    Ok(bytes)
}

/// Stream a response body into a Vec, reporting download percent via callback.
async fn download_streaming<F: Fn(u64)>(
    resp: reqwest::Response,
    on_progress: F,
) -> Result<Vec<u8>> {
    use futures_util::StreamExt;
    let total = resp.content_length();
    let mut bytes: Vec<u8> = Vec::with_capacity(total.unwrap_or(0) as usize);
    let mut got: u64 = 0;
    let mut last_pct: u64 = 0;
    on_progress(0);
    // Surface absolute byte counts too, so the UI can show "current / total MB".
    crate::update::set_bytes(0, total.unwrap_or(0));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("download stream error: {e}"))?;
        bytes.extend_from_slice(&chunk);
        got += chunk.len() as u64;
        crate::update::set_bytes(got, total.unwrap_or(0));
        if let Some(total) = total.filter(|t| *t > 0) {
            let pct = (got * 100 / total).min(100);
            if pct != last_pct {
                last_pct = pct;
                on_progress(pct);
            }
        }
    }
    on_progress(100);
    Ok(bytes)
}

/// Resolve the latest available agent version from the backend, used to decide
/// whether a self-update is actually needed before downloading the binary.
pub async fn latest_version(cfg: &crate::config::AgentConfig) -> Result<String> {
    let url = format!(
        "{}/agent/dist/version",
        cfg.backend_url.trim_end_matches('/')
    );
    let manifest: serde_json::Value = http()
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    manifest
        .get("data")
        .and_then(|d| d.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('v').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("no version in backend manifest"))
}
