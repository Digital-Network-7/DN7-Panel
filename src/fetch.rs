//! Binary acquisition with a GitHub-first strategy.
//!
//! For a component (agent/agentd), download its latest Linux x86_64 release
//! binary. Order:
//!   1. GitHub: parse `releases.atom` for the highest version, then fetch the
//!      release asset directly from GitHub.
//!   2. Fallback: the download/CDN service (`/download/<component>/latest`).
//!
//! Used both for self-update and for re-fetching a missing/deleted binary.

use anyhow::{anyhow, Result};

/// Which component to fetch.
#[derive(Clone, Copy, Debug)]
pub enum Component {
    Agent,
    Agentd,
}

impl Component {
    fn bin(&self) -> &'static str {
        match self {
            Component::Agent => "teaops-agent",
            Component::Agentd => "teaops-agentd",
        }
    }
    fn url_name(&self) -> &'static str {
        match self {
            Component::Agent => "agent",
            Component::Agentd => "agentd",
        }
    }
}

/// Resolve a repo (`owner/name`) for a component from config.
fn repo_for(cfg: &crate::config::AgentConfig, c: Component) -> &str {
    match c {
        Component::Agent => &cfg.agent_repo,
        Component::Agentd => &cfg.agentd_repo,
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("teaops-agent/updater")
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .expect("http client")
}

/// Download the latest binary for `component` into memory, GitHub-first.
pub async fn fetch_latest(cfg: &crate::config::AgentConfig, component: Component) -> Result<Vec<u8>> {
    // 1. GitHub first.
    match fetch_from_github(cfg, component).await {
        Ok(bytes) => {
            tracing::info!(component = component.url_name(), "fetched binary from GitHub");
            return Ok(bytes);
        }
        Err(e) => tracing::warn!(
            component = component.url_name(),
            "GitHub fetch failed ({e}); falling back to download service"
        ),
    }

    // 2. Download service fallback.
    let bytes = fetch_from_download_service(cfg, component).await?;
    tracing::info!(component = component.url_name(), "fetched binary from download service");
    Ok(bytes)
}

/// GitHub path: releases.atom -> highest version -> release asset download.
async fn fetch_from_github(cfg: &crate::config::AgentConfig, component: Component) -> Result<Vec<u8>> {
    let repo = repo_for(cfg, component);
    let atom_url = format!("https://github.com/{repo}/releases.atom");
    let client = http();

    let body = client
        .get(&atom_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let version = highest_version(&body)
        .ok_or_else(|| anyhow!("no version found in releases.atom"))?;

    let asset = format!("{}-linux-x86_64-v{}", component.bin(), version);
    let asset_url = format!("https://github.com/{repo}/releases/download/v{version}/{asset}");
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

/// Download-service path: GET /download/<component>/latest.
async fn fetch_from_download_service(
    cfg: &crate::config::AgentConfig,
    component: Component,
) -> Result<Vec<u8>> {
    let url = format!("{}/download/{}/latest", cfg.download_url, component.url_name());
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
    // Cheap scan: tokenize and look for "vX.Y.Z" tokens.
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
