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

/// Download the latest binary into memory, GitHub-first.
pub async fn fetch_latest(cfg: &crate::config::AgentConfig) -> Result<Vec<u8>> {
    match fetch_from_github(cfg).await {
        Ok(bytes) => {
            tracing::info!("fetched binary from GitHub");
            return Ok(bytes);
        }
        Err(e) => {
            tracing::warn!("GitHub fetch failed ({e}); falling back to download service")
        }
    }
    let bytes = fetch_from_download_service(cfg).await?;
    tracing::info!("fetched binary from download service");
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
async fn fetch_from_github(cfg: &crate::config::AgentConfig) -> Result<Vec<u8>> {
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
    let bytes = client
        .get(&asset_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if bytes.is_empty() {
        return Err(anyhow!("downloaded asset is empty"));
    }
    Ok(bytes.to_vec())
}

/// Download-service path: GET /download/agent/latest.
async fn fetch_from_download_service(cfg: &crate::config::AgentConfig) -> Result<Vec<u8>> {
    let url = format!("{}/download/{}/latest", cfg.download_url, URL_NAME);
    let bytes = http()
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    if bytes.is_empty() {
        return Err(anyhow!("download service returned empty body"));
    }
    Ok(bytes.to_vec())
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
