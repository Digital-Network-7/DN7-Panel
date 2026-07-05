//! Binary acquisition for self-update — GitHub via the fastest available line.
//!
//! There is a single binary (it runs as either the supervisor or the panel role
//! depending on argv). Self-update pulls a new binary from GitHub release assets,
//! addressed deterministically (`.../releases/download/v{ver}/dn7-panel-linux-
//! {arch}-v{ver}`) and the latest version from the published `releases.json`
//! changelog asset — so api.github.com is never touched (no API rate limit).
//!
//! Every request can travel through one of several mirror "lines" (see
//! [`mirror`]); the updater **races** them and uses whichever responds fastest,
//! silently dropping any that are dead or geo-blocked. There is no user-visible
//! source selection — the fastest reachable line always wins.

use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::platform::config::PanelConfig;

mod mirror;
use mirror::{mirrors, Mirror};

/// Architecture token used in asset names (`x86_64`/`arm64`).
pub fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

// ---------------------------------------------------------------------------
// Canonical GitHub URLs (never api.github.com)
// ---------------------------------------------------------------------------

/// The changelog index, published as a release asset of the latest release.
fn canonical_index(repo: &str) -> String {
    format!("https://github.com/{repo}/releases/latest/download/releases.json")
}

/// The signed binary asset for a specific build. Each build is its own release,
/// tagged `b<build>`; the asset name still carries the semver for readability.
fn canonical_asset(repo: &str, version: &str, build: u64) -> String {
    format!(
        "https://github.com/{repo}/releases/download/b{build}/dn7-panel-linux-{}-v{version}",
        arch()
    )
}

// ---------------------------------------------------------------------------
// HTTP clients
// ---------------------------------------------------------------------------

/// Small-request client (version/index lookups). Short timeout.
fn http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .timeout(Duration::from_secs(15))
        .build()
}

/// Line-liveness probe client: quick connect, short overall budget. Probes are
/// one-shot and deliberately drop the response after the first chunk, so disable
/// idle-connection pooling — a dropped, partially-read connection shouldn't
/// linger in the pool.
fn probe_http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .connect_timeout(Duration::from_secs(6))
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
}

/// Binary-download client. No overall timeout: a slow-but-progressing download
/// on a tiny-bandwidth line can legitimately take many minutes. Only connect +
/// idle-read are bounded, so a dead/stalled connection is still caught while a
/// slow, steadily-progressing download runs to completion.
fn download_http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(300))
        .build()
}

// ---------------------------------------------------------------------------
// Changelog index (release notes + latest version), raced across lines
// ---------------------------------------------------------------------------

/// One release's notes, as published in the `releases.json` changelog index.
/// `notes` is a per-language map (locale → paragraph); the UI shows the entry
/// for the current language. `codename` is the release codename (e.g. "Phanes")
/// and `build` the independent build number, both shown alongside the version.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReleaseNote {
    pub version: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub codename: String,
    #[serde(default)]
    pub build: String,
    #[serde(default)]
    pub notes: std::collections::HashMap<String, String>,
}

/// Cap on the (tiny) release index to stop a hostile mirror OOM-ing the host.
const INDEX_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Fetch + parse the changelog index from one already-rewritten URL.
async fn fetch_index_one(client: &reqwest::Client, url: &str) -> Result<Vec<ReleaseNote>> {
    use futures::StreamExt;
    let resp = client.get(url).send().await?.error_for_status()?;
    // Reject an oversized *declared* length up front...
    if resp.content_length().is_some_and(|n| n > INDEX_MAX_BYTES) {
        return Err(anyhow!("release index too large"));
    }
    // ...and enforce the cap while streaming: an untrusted line can omit
    // Content-Length (chunked) and stream an unbounded body, which `resp.json()`
    // would buffer straight into memory and OOM the host. Read chunk-by-chunk and
    // abort past the cap — the same guard the binary download uses.
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("index stream error: {e}"))?;
        if buf.len() as u64 + chunk.len() as u64 > INDEX_MAX_BYTES {
            return Err(anyhow!(
                "release index exceeded {INDEX_MAX_BYTES} bytes — aborting"
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    let v: serde_json::Value = serde_json::from_slice(&buf)?;
    // Accept {releases:[…]}, {data:{releases:[…]}}, or a bare [...].
    let arr = v
        .get("data")
        .and_then(|d| d.get("releases"))
        .or_else(|| v.get("releases"))
        .cloned()
        .unwrap_or(v);
    Ok(serde_json::from_value(arr)?)
}

/// Fetch the release index (`releases.json`), racing every line and returning
/// the first non-empty valid parse. As soon as the fastest line answers, the
/// slower/failed ones are dropped. Errors only if no line yields a valid index.
pub async fn releases_index_raced(cfg: &PanelConfig) -> Result<Vec<ReleaseNote>> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let canonical = canonical_index(&cfg.github_repo);
    let client = http()?;
    let mut futs: FuturesUnordered<_> = mirrors()
        .iter()
        .map(|m| {
            let url = m.rewrite(&canonical);
            let client = client.clone();
            let name = m.name;
            async move { (name, fetch_index_one(&client, &url).await) }
        })
        .collect();
    while let Some((name, res)) = futs.next().await {
        match res {
            Ok(list) if !list.is_empty() => {
                tracing::debug!(mirror = name, count = list.len(), "release index fetched");
                return Ok(list);
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(mirror = name, "index fetch failed: {e}"),
        }
    }
    Err(anyhow!("no line returned a valid release index"))
}

// ---------------------------------------------------------------------------
// Binary download, ranked-raced across lines
// ---------------------------------------------------------------------------

/// Length of the Ed25519 signature appended to every published binary.
const SIG_LEN: usize = 64;

/// Hard ceiling on a self-update binary download. The body is buffered fully in
/// memory (and the panel runs as root), so without a cap a compromised/MITM'd
/// line could OOM-DoS the host via an oversized or unbounded response.
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Probe one already-rewritten asset URL: succeed if a small ranged GET returns
/// bytes within the budget. Reads only the first chunk (then drops the stream)
/// so a proxy that ignores `Range` and streams the whole binary is not fully
/// downloaded during probing.
async fn probe_line(client: &reqwest::Client, url: &str) -> bool {
    use futures::StreamExt;
    let attempt = async {
        let resp = client
            .get(url)
            .header(reqwest::header::RANGE, "bytes=0-65535")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let mut stream = resp.bytes_stream();
        match stream.next().await {
            Some(Ok(chunk)) if !chunk.is_empty() => Some(()),
            _ => None,
        }
        // `stream`/`resp` drop here → the transfer is aborted after one chunk.
    };
    tokio::time::timeout(Duration::from_secs(8), attempt)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Rank the lines fastest-first for `canonical`, dropping unreachable ones.
/// Probes every line concurrently and orders survivors by response time.
async fn rank_lines(canonical: &str) -> Vec<Mirror> {
    let Ok(client) = probe_http() else {
        return Vec::new();
    };
    let probes = mirrors().iter().map(|m| {
        let url = m.rewrite(canonical);
        let client = client.clone();
        async move {
            let t = tokio::time::Instant::now();
            probe_line(&client, &url).await.then(|| (*m, t.elapsed()))
        }
    });
    let mut ok: Vec<(Mirror, Duration)> = futures::future::join_all(probes)
        .await
        .into_iter()
        .flatten()
        .collect();
    ok.sort_by_key(|(_, d)| *d);
    ok.into_iter().map(|(m, _)| m).collect()
}

/// Download the signed binary for `version`, racing the lines: probe all, then
/// download from the fastest, failing over to the next on any error. The bytes
/// returned are the binary with its appended Ed25519 signature already verified
/// and stripped — nothing unverified is ever returned.
pub async fn download_binary_raced<F: Fn(u64) + Copy>(
    cfg: &PanelConfig,
    version: &str,
    build: u64,
    on_progress: F,
) -> Result<Vec<u8>> {
    let canonical = canonical_asset(&cfg.github_repo, version, build);
    let ranked = rank_lines(&canonical).await;
    if ranked.is_empty() {
        return Err(anyhow!(
            "no reachable download line for v{version} (build {build})"
        ));
    }
    tracing::info!(
        lines = ranked.len(),
        fastest = ranked[0].name,
        "self-update: download lines ranked"
    );
    let mut last_err: Option<anyhow::Error> = None;
    for m in ranked {
        let url = m.rewrite(&canonical);
        on_progress(0);
        match download_and_verify(&url, on_progress).await {
            Ok(bytes) => {
                tracing::info!(
                    mirror = m.name,
                    bytes = bytes.len(),
                    "fetched panel binary; signature verified"
                );
                return Ok(bytes);
            }
            Err(e) => {
                tracing::warn!(mirror = m.name, "download failed ({e}); trying next line");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("all download lines failed")))
}

/// Download one already-rewritten binary URL with progress, then split off and
/// verify the appended 64-byte Ed25519 signature, returning the stripped binary.
async fn download_and_verify<F: Fn(u64) + Copy>(url: &str, on_progress: F) -> Result<Vec<u8>> {
    let resp = download_http()?.get(url).send().await?.error_for_status()?;
    let mut bytes = download_streaming(resp, on_progress).await?;
    strip_and_verify(&mut bytes)?;
    Ok(bytes)
}

/// Split the appended 64-byte Ed25519 signature off `data`, verify it against
/// the embedded trusted key(s) over the remaining (binary) bytes, and truncate
/// `data` in place to just the binary. Errors (and leaves `data` unspecified)
/// on a too-small, unsigned, tampered, or untrusted input.
fn strip_and_verify(data: &mut Vec<u8>) -> Result<()> {
    if data.len() <= SIG_LEN {
        return Err(anyhow!("returned a too-small/empty binary"));
    }
    let split = data.len() - SIG_LEN;
    let sig = data.split_off(split); // `data` now holds the binary; `sig` the trailer
    if !crate::platform::signing::verify(data, &sig) {
        return Err(anyhow!(
            "signature verification FAILED — refusing to install (untrusted, tampered, or unsigned binary)"
        ));
    }
    Ok(())
}

/// Stream a response body into a Vec, reporting download percent via callback.
async fn download_streaming<F: Fn(u64)>(
    resp: reqwest::Response,
    on_progress: F,
) -> Result<Vec<u8>> {
    use futures::StreamExt;
    let total = resp.content_length();
    // Reject an oversized declared length up front (before allocating).
    if total.is_some_and(|t| t > MAX_BINARY_BYTES) {
        return Err(anyhow!(
            "download too large: declared {} bytes exceeds the {} byte limit",
            total.unwrap(),
            MAX_BINARY_BYTES
        ));
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(total.unwrap_or(0) as usize);
    let mut got: u64 = 0;
    let mut last_pct: u64 = 0;
    on_progress(0);
    crate::platform::update::set_bytes(0, total.unwrap_or(0));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!("download stream error: {e}"))?;
        got += chunk.len() as u64;
        // Abort an unbounded/chunked body that runs past the cap (no Content-Length).
        if got > MAX_BINARY_BYTES {
            return Err(anyhow!(
                "download exceeded the {} byte limit — aborting",
                MAX_BINARY_BYTES
            ));
        }
        bytes.extend_from_slice(&chunk);
        crate::platform::update::set_bytes(got, total.unwrap_or(0));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_urls_shape() {
        assert_eq!(
            canonical_index("o/r"),
            "https://github.com/o/r/releases/latest/download/releases.json"
        );
        let a = canonical_asset("o/r", "27.0.0", 2);
        assert!(a.starts_with("https://github.com/o/r/releases/download/b2/dn7-panel-linux-"));
        assert!(a.ends_with("-v27.0.0"));
    }

    #[test]
    fn strip_and_verify_accepts_appended_signature() {
        // "binary" + appended 64-byte signature, produced by OpenSSL with the
        // release key over the message "dn7-panel-signing-test".
        const SIG: [u8; 64] = [
            211, 133, 253, 20, 41, 65, 53, 133, 192, 5, 141, 183, 171, 14, 67, 104, 51, 101, 67,
            19, 119, 250, 153, 134, 141, 27, 153, 97, 137, 112, 38, 67, 214, 75, 236, 251, 138,
            202, 255, 32, 164, 4, 102, 36, 188, 21, 49, 159, 103, 216, 92, 170, 133, 159, 120, 126,
            39, 228, 60, 82, 73, 16, 62, 1,
        ];
        let mut data = b"dn7-panel-signing-test".to_vec();
        data.extend_from_slice(&SIG);
        assert!(strip_and_verify(&mut data).is_ok());
        assert_eq!(data, b"dn7-panel-signing-test"); // trailer stripped

        // Tampered binary byte must fail.
        let mut bad = b"dn7-panel-signing-tesT".to_vec();
        bad.extend_from_slice(&SIG);
        assert!(strip_and_verify(&mut bad).is_err());

        // Too small / unsigned input must fail.
        let mut tiny = vec![0u8; 10];
        assert!(strip_and_verify(&mut tiny).is_err());
    }
}
