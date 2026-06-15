//! Binary acquisition for self-update — dual source (GitHub + dn7.cn).
//!
//! There is a single binary (it runs as either the supervisor or the panel
//! role depending on argv). Self-update can pull a new binary from two sources:
//!
//!   * **GitHub** — release assets are addressed deterministically
//!     (`.../releases/download/v{ver}/dn7-panel-linux-{arch}-v{ver}`), and the
//!     latest version is read from the `releases/latest` redirect. This avoids
//!     api.github.com entirely, so there is no API rate limit to exhaust.
//!   * **dn7.cn** — a JSON manifest (`/api/panel/version?arch=`) gives the
//!     version + download URL + sha256; the binary is mirrored domestically for
//!     speed in regions where GitHub is slow/blocked.
//!
//! Source selection is sticky: a lightweight speed probe picks a winner that is
//! remembered (see `update::UpdateState`); steady-state checks reuse it, and a
//! download failure fails over to the other source.

use anyhow::{anyhow, Result};

use crate::config::PanelConfig;

/// Which mirror a release came from / should be fetched from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Github,
    Dn7,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Github => "github",
            SourceKind::Dn7 => "dn7",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "github" => Some(SourceKind::Github),
            "dn7" => Some(SourceKind::Dn7),
            _ => None,
        }
    }
    pub fn other(self) -> Self {
        match self {
            SourceKind::Github => SourceKind::Dn7,
            SourceKind::Dn7 => SourceKind::Github,
        }
    }
}

/// A resolved, downloadable release. The published binary has its 64-byte
/// Ed25519 signature appended to the end (see `download_release`).
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub source: SourceKind,
}

/// Architecture token used in asset names / manifest queries (`x86_64`/`arm64`).
pub fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

/// Small-request HTTP client (version lookups, manifests). Short timeouts.
fn http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .timeout(std::time::Duration::from_secs(20))
        .build()
}

/// HTTP client for the (potentially very slow) binary download.
///
/// No overall timeout: a server with tiny bandwidth can legitimately take many
/// minutes. We bound only connect + idle-read time, so a dead/stalled
/// connection is still caught, but a slow-but-progressing download runs to
/// completion (the read timeout resets after every successful read).
fn download_http() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .connect_timeout(std::time::Duration::from_secs(30))
        .read_timeout(std::time::Duration::from_secs(300))
        .build()
}

// ---------------------------------------------------------------------------
// Per-source release resolution
// ---------------------------------------------------------------------------

/// Resolve the latest GitHub release without touching api.github.com: follow
/// the `releases/latest` redirect to read the tag, then address the asset
/// deterministically.
pub async fn github_release(cfg: &PanelConfig) -> Result<Release> {
    let repo = &cfg.github_repo;
    let latest = format!("https://github.com/{repo}/releases/latest");
    // Disable auto-redirect so we can read the Location → /tag/vX.Y.Z.
    let client = reqwest::Client::builder()
        .user_agent("dn7-panel/updater")
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client.get(&latest).send().await?;
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow!("github: no redirect to latest tag"))?;
    let tag = loc
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow!("github: malformed latest location"))?;
    let version = tag.trim_start_matches('v').to_string();
    if version.is_empty() {
        return Err(anyhow!("github: empty version tag"));
    }
    let asset = format!("dn7-panel-linux-{}-v{}", arch(), version);
    let url = format!("https://github.com/{repo}/releases/download/{tag}/{asset}");
    Ok(Release {
        version,
        url,
        source: SourceKind::Github,
    })
}

/// Resolve the latest dn7.cn release from the JSON manifest.
pub async fn dn7_release(cfg: &PanelConfig) -> Result<Release> {
    let url = format!("{}/api/panel/version?arch={}", cfg.dn7_base, arch());
    let manifest: serde_json::Value = http()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Accept either a flat object or {data:{...}}.
    let m = manifest.get("data").unwrap_or(&manifest);
    let version = m
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('v').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("dn7: no version in manifest"))?;
    let dl = m
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}/api/panel/download?arch={}", cfg.dn7_base, arch()));
    Ok(Release {
        version,
        url: dl,
        source: SourceKind::Dn7,
    })
}

/// Resolve a release from a specific source.
pub async fn release_from(cfg: &PanelConfig, source: SourceKind) -> Result<Release> {
    match source {
        SourceKind::Github => github_release(cfg).await,
        SourceKind::Dn7 => dn7_release(cfg).await,
    }
}

// ---------------------------------------------------------------------------
// Changelog index (release notes)
// ---------------------------------------------------------------------------

/// One release's notes, as published in the `releases.json` changelog index.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReleaseNote {
    pub version: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Fetch + parse the changelog index from a specific source. GitHub serves it
/// as a release asset via the deterministic `releases/latest/download/` path
/// (no api.github.com); dn7.cn mirrors it at `/api/panel/releases`.
pub async fn releases_index_from(
    cfg: &PanelConfig,
    source: SourceKind,
) -> Result<Vec<ReleaseNote>> {
    let url = match source {
        SourceKind::Github => format!(
            "https://github.com/{}/releases/latest/download/releases.json",
            cfg.github_repo
        ),
        SourceKind::Dn7 => format!("{}/api/panel/releases", cfg.dn7_base),
    };
    let v: serde_json::Value = http()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Accept {releases:[…]}, {data:{releases:[…]}}, or a bare [...].
    let arr = v
        .get("data")
        .and_then(|d| d.get("releases"))
        .or_else(|| v.get("releases"))
        .cloned()
        .unwrap_or(v);
    let list: Vec<ReleaseNote> = serde_json::from_value(arr)?;
    Ok(list)
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/// Length of the Ed25519 signature appended to every published binary.
const SIG_LEN: usize = 64;

/// Download a resolved release with progress. The published file is the binary
/// with its 64-byte Ed25519 signature appended; this splits off the trailing
/// signature, verifies it against the embedded trusted key(s) over the binary
/// bytes, and returns the **stripped** binary. A missing/invalid signature is a
/// hard error — nothing is ever installed unverified.
pub async fn download_release<F: Fn(u64) + Copy>(
    release: &Release,
    on_progress: F,
) -> Result<Vec<u8>> {
    let resp = download_http()?
        .get(&release.url)
        .send()
        .await?
        .error_for_status()?;
    let mut bytes = download_streaming(resp, on_progress).await?;
    let src = release.source.as_str();
    strip_and_verify(&mut bytes).map_err(|e| anyhow!("{src}: {e}"))?;
    tracing::info!(
        source = src,
        bytes = bytes.len(),
        "fetched panel binary; signature verified"
    );
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
    if !crate::signing::verify(data, &sig) {
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
    use futures_util::StreamExt;
    let total = resp.content_length();
    let mut bytes: Vec<u8> = Vec::with_capacity(total.unwrap_or(0) as usize);
    let mut got: u64 = 0;
    let mut last_pct: u64 = 0;
    on_progress(0);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_kind_roundtrip() {
        assert_eq!(SourceKind::from_str("github"), Some(SourceKind::Github));
        assert_eq!(SourceKind::from_str("dn7"), Some(SourceKind::Dn7));
        assert_eq!(SourceKind::from_str("x"), None);
        assert_eq!(SourceKind::Github.other(), SourceKind::Dn7);
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
