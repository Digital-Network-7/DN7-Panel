//! A minimal OCI distribution (registry v2) client over blocking HTTP. Handles
//! the anonymous bearer-token dance (the `WWW-Authenticate` challenge → token
//! endpoint → retry), manifest fetch (with the full `Accept` set), and streaming
//! blob downloads. Private-registry basic auth comes with the auth matrix in P4.

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::image::manifest::media;

pub struct Registry {
    agent: ureq::Agent,
    host: String,
    repo: String,
    token: Option<String>,
}

#[derive(Deserialize)]
struct TokenResp {
    #[serde(default)]
    token: String,
    #[serde(default)]
    access_token: String,
}

impl Registry {
    pub fn new(host: &str, repo: &str) -> Registry {
        Self::with_connect_timeout(host, repo, Duration::from_secs(20))
    }

    /// Like [`Registry::new`] with a caller-chosen connect timeout — mirror
    /// probing wants to fail over to the next host in seconds, not the default
    /// 20 s a direct pull tolerates.
    pub fn with_connect_timeout(host: &str, repo: &str, connect: Duration) -> Registry {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(connect)
            .timeout_read(Duration::from_secs(120))
            .build();
        Registry {
            agent,
            host: host.to_string(),
            repo: repo.to_string(),
            token: None,
        }
    }

    /// Fetch a manifest (or index) by tag/digest. Returns the raw bytes and the
    /// `Content-Type` so the caller can tell an index from a manifest.
    pub fn get_manifest(&mut self, reference: &str) -> Result<(Vec<u8>, String)> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            self.host, self.repo, reference
        );
        let resp = self
            .authed_get(&url, media::ACCEPT)
            .map_err(|e| self.friendly_pull_err(reference, e))?;
        let ct = resp.header("content-type").unwrap_or("").to_string();
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| Error::Other(format!("read manifest: {e}")))?;
        Ok((buf, ct))
    }

    /// Turn a raw registry auth/not-found failure on a manifest fetch into a
    /// message a human can act on. A registry (Docker Hub especially) answers
    /// `401` — not `404` — for a repository that doesn't exist or that the
    /// anonymous token can't reach, so a bare "HTTP 401" reads as a bug when the
    /// real cause is almost always a typo'd name/tag or a private image.
    fn friendly_pull_err(&self, reference: &str, e: Error) -> Error {
        let msg = e.to_string();
        if [
            "registry HTTP 401",
            "registry HTTP 403",
            "registry HTTP 404",
        ]
        .iter()
        .any(|p| msg.contains(p))
        {
            return Error::Other(format!(
                "image not found: {}/{}:{} — no such name or tag, \
                 or it is a private image that requires login",
                self.host, self.repo, reference
            ));
        }
        e
    }

    /// Open a blob (config or layer) by digest as a streaming reader. The caller
    /// caps + hashes the copy (see `Store::save_blob_from_reader`), so a hostile
    /// registry streaming an unbounded layer can't fill the disk — the cap trips
    /// mid-copy and the partial temp file is discarded.
    pub fn blob_reader(&mut self, digest: &str) -> Result<impl Read + Send> {
        self.blob_reader_at(digest, 0).map(|(r, _)| r)
    }

    /// Open a blob reader starting at byte `offset` (an HTTP `Range` request, to
    /// resume a partial download). Returns the reader and the offset it actually
    /// starts at: `offset` when the registry honored the range (206), else 0 —
    /// the caller must then restart its copy from scratch.
    pub fn blob_reader_at(&mut self, digest: &str, offset: u64) -> Result<(impl Read + Send, u64)> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.host, self.repo, digest);
        let resp = match self.authed_get_at(&url, "*/*", offset) {
            // 416 = our partial file is at/past the blob's end (stale or already
            // complete tmp) — the range is useless, restart from byte 0.
            Err(Error::Other(ref m)) if offset > 0 && m.contains("registry HTTP 416") => {
                self.authed_get_at(&url, "*/*", 0)?
            }
            other => other?,
        };
        let start = if offset > 0 && resp.status() == 206 {
            offset
        } else {
            0
        };
        Ok((resp.into_reader(), start))
    }

    /// GET `url`, transparently acquiring a bearer token on a 401 and retrying.
    /// Transient failures (transport errors, 5xx) are retried with a short
    /// backoff so one dropped connection doesn't abort a multi-layer pull.
    fn authed_get(&mut self, url: &str, accept: &str) -> Result<ureq::Response> {
        self.authed_get_at(url, accept, 0)
    }

    fn authed_get_at(&mut self, url: &str, accept: &str, offset: u64) -> Result<ureq::Response> {
        let mut refreshed_token = false;
        let mut attempt = 0u32;
        loop {
            match self.send(url, accept, offset) {
                Ok(resp) => return Ok(resp),
                Err(ureq::Error::Status(401, resp)) if !refreshed_token => {
                    let challenge = resp
                        .header("www-authenticate")
                        .ok_or_else(|| Error::Other("401 without WWW-Authenticate".into()))?
                        .to_string();
                    self.acquire_token(&challenge)?;
                    refreshed_token = true;
                }
                Err(e) if attempt + 1 < SEND_ATTEMPTS && is_transient(&e) => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(500 * u64::from(attempt)));
                }
                Err(e) => return Err(map_ureq(e)),
            }
        }
    }

    // `ureq::Error` is large (~272 B) and is the external type we must pass
    // through here; boxing it would only churn the one call site in `authed_get`.
    #[allow(clippy::result_large_err)]
    fn send(
        &self,
        url: &str,
        accept: &str,
        offset: u64,
    ) -> std::result::Result<ureq::Response, ureq::Error> {
        let mut r = self.agent.get(url).set("Accept", accept);
        if let Some(t) = &self.token {
            r = r.set("Authorization", &format!("Bearer {t}"));
        }
        if offset > 0 {
            r = r.set("Range", &format!("bytes={offset}-"));
        }
        r.call()
    }

    /// Resolve a `Bearer realm=…,service=…,scope=…` challenge into a token.
    fn acquire_token(&mut self, challenge: &str) -> Result<()> {
        let params = parse_challenge(challenge);
        let realm = params
            .get("realm")
            .ok_or_else(|| Error::Other("auth challenge without realm".into()))?;

        let mut query = Vec::new();
        if let Some(s) = params.get("service") {
            query.push(format!("service={}", urlencode(s)));
        }
        if let Some(s) = params.get("scope") {
            query.push(format!("scope={}", urlencode(s)));
        }
        let url = if query.is_empty() {
            realm.clone()
        } else {
            format!("{realm}?{}", query.join("&"))
        };

        let resp = self.agent.get(&url).call().map_err(map_ureq)?;
        let tok: TokenResp = resp
            .into_json()
            .map_err(|e| Error::Other(format!("token response json: {e}")))?;
        let token = if !tok.token.is_empty() {
            tok.token
        } else {
            tok.access_token
        };
        if token.is_empty() {
            return Err(Error::Other("registry returned an empty token".into()));
        }
        self.token = Some(token);
        Ok(())
    }
}

/// Parse the `key="value"` pairs of a `Bearer …` challenge.
fn parse_challenge(s: &str) -> HashMap<String, String> {
    let body = s
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| s.trim().strip_prefix("bearer "))
        .unwrap_or(s.trim());
    let mut map = HashMap::new();
    for part in body.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    map
}

/// Percent-encode a query value (encode everything but the RFC3986 unreserved
/// set), so a scope like `repository:library/alpine:pull` survives.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Total send attempts per request (1 initial + retries) for transient failures.
const SEND_ATTEMPTS: u32 = 3;

/// Worth retrying: network-level failures and registry-side 5xx. Auth failures
/// and 4xx are deterministic — retrying only wastes the user's time.
fn is_transient(e: &ureq::Error) -> bool {
    match e {
        ureq::Error::Transport(_) => true,
        ureq::Error::Status(code, _) => *code >= 500,
    }
}

fn map_ureq(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(200).collect();
            Error::Other(format!("registry HTTP {code}: {snippet}"))
        }
        ureq::Error::Transport(t) => Error::Other(format!("registry transport: {t}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bearer_challenge() {
        let c = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let p = parse_challenge(c);
        assert_eq!(p.get("realm").unwrap(), "https://auth.docker.io/token");
        assert_eq!(p.get("service").unwrap(), "registry.docker.io");
        assert_eq!(p.get("scope").unwrap(), "repository:library/alpine:pull");
    }

    #[test]
    fn urlencode_escapes_scope_separators() {
        assert_eq!(
            urlencode("repository:library/alpine:pull"),
            "repository%3Alibrary%2Falpine%3Apull"
        );
    }
}
