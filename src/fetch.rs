//! Binary acquisition with a GitHub-first strategy.
//!
//! There is a single binary (it runs as either the supervisor or the agent
//! role depending on argv). Download order:
//!   1. GitHub: parse `releases.atom` for the highest version, then fetch the
//!      release asset directly from GitHub.
//!   2. Fallback: the download/CDN service (`/download/agent/latest`).
//!
//! Used both for self-update and for re-fetching a missing/deleted binary.

use anyhow::{anyhow, Result};

const BIN_NAME: &str = "teaops-agent";
/// Component name used in download-service URLs.
const URL_NAME: &str = "agent";

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("teaops-agent/updater")
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .expect("http client")
}

/// Download the latest binary into memory, GitHub-first. Invokes
/// `on_progress(percent)` as bytes arrive (0..100). Percent is based on
/// Content-Length; if the server doesn't send it, progress jumps 0 -> 100 on
/// completion. GitHub-first with CDN fallback.
pub async fn fetch_latest_with_progress<F: Fn(u64) + Copy>(
    cfg: &crate::config::AgentConfig,
    on_progress: F,
) -> Result<Vec<u8>> {
    match fetch_from_github(cfg, on_progress).await {
        Ok(bytes) => {
            tracing::info!("fetched binary from GitHub");
            return Ok(bytes);
        }
        Err(e) => {
            tracing::warn!("GitHub fetch failed ({e}); falling back to download service")
        }
    }
    let bytes = fetch_from_download_service(cfg, on_progress).await?;
    tracing::info!("fetched binary from download service");
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
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("download stream error: {e}"))?;
        bytes.extend_from_slice(&chunk);
        got += chunk.len() as u64;
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

/// Resolve the latest available version string (e.g. "1.0.12"), GitHub-first
/// with the download service as a fallback. Used to decide whether a self-update
/// is actually needed before fetching the whole binary.
pub async fn latest_version(cfg: &crate::config::AgentConfig) -> Result<String> {
    let atom_url = format!("https://github.com/{}/releases.atom", cfg.repo);
    if let Ok(resp) = http().get(&atom_url).send().await {
        if let Ok(resp) = resp.error_for_status() {
            if let Ok(body) = resp.text().await {
                if let Some(v) = highest_version(&body) {
                    return Ok(v);
                }
            }
        }
    }

    let url = format!("{}/latest/{}", cfg.download_url, URL_NAME);
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
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("no version in download-service manifest"))
}

/// GitHub path: releases.atom -> highest version -> release asset download.
async fn fetch_from_github<F: Fn(u64)>(
    cfg: &crate::config::AgentConfig,
    on_progress: F,
) -> Result<Vec<u8>> {
    let client = http();
    let atom_url = format!("https://github.com/{}/releases.atom", cfg.repo);
    let body = client
        .get(&atom_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let version = highest_version(&body).ok_or_else(|| anyhow!("no version found in releases.atom"))?;

    let asset = format!("{BIN_NAME}-linux-x86_64-v{version}");
    let asset_url = format!(
        "https://github.com/{}/releases/download/v{version}/{asset}",
        cfg.repo
    );
    let resp = client.get(&asset_url).send().await?.error_for_status()?;
    let bytes = download_streaming(resp, on_progress).await?;
    if bytes.is_empty() {
        return Err(anyhow!("downloaded asset is empty"));
    }
    Ok(bytes)
}

/// Download-service path: GET /download/agent/latest.
async fn fetch_from_download_service<F: Fn(u64)>(
    cfg: &crate::config::AgentConfig,
    on_progress: F,
) -> Result<Vec<u8>> {
    let url = format!("{}/download/{}/latest", cfg.download_url, URL_NAME);
    let resp = http().get(&url).send().await?.error_for_status()?;
    let bytes = download_streaming(resp, on_progress).await?;
    if bytes.is_empty() {
        return Err(anyhow!("download service returned empty body"));
    }
    Ok(bytes)
}

/// Find the highest `1.0.x`-style version in a releases Atom feed.
fn highest_version(xml: &str) -> Option<String> {
    let mut best: Option<((u64, u64, u64), String)> = None;
    for raw in xml.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
        if !raw.starts_with('v') {
            continue;
        }
        let v = raw.trim_start_matches('v');
        if let Some(parsed) = parse_ver(v) {
            if best.as_ref().map(|(b, _)| parsed > *b).unwrap_or(true) {
                best = Some((parsed, v.to_string()));
            }
        }
    }
    best.map(|(_, v)| v)
}

fn parse_ver(s: &str) -> Option<(u64, u64, u64)> {
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_highest() {
        let xml = "x/v1.0.3 y v1.0.10 z v1.0.2";
        assert_eq!(highest_version(xml).as_deref(), Some("1.0.10"));
    }
}
