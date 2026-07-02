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
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(20))
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
        let resp = self.authed_get(&url, media::ACCEPT)?;
        let ct = resp.header("content-type").unwrap_or("").to_string();
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| Error::Other(format!("read manifest: {e}")))?;
        Ok((buf, ct))
    }

    /// Open a blob (config or layer) by digest as a streaming reader. The caller
    /// caps + hashes the copy (see `Store::save_blob_from_reader`), so a hostile
    /// registry streaming an unbounded layer can't fill the disk — the cap trips
    /// mid-copy and the partial temp file is discarded.
    pub fn blob_reader(&mut self, digest: &str) -> Result<impl Read> {
        let url = format!("https://{}/v2/{}/blobs/{}", self.host, self.repo, digest);
        let resp = self.authed_get(&url, "*/*")?;
        Ok(resp.into_reader())
    }

    /// GET `url`, transparently acquiring a bearer token on a 401 and retrying.
    fn authed_get(&mut self, url: &str, accept: &str) -> Result<ureq::Response> {
        match self.send(url, accept) {
            Ok(resp) => return Ok(resp),
            Err(ureq::Error::Status(401, resp)) => {
                let challenge = resp
                    .header("www-authenticate")
                    .ok_or_else(|| Error::Other("401 without WWW-Authenticate".into()))?
                    .to_string();
                self.acquire_token(&challenge)?;
            }
            Err(e) => return Err(map_ureq(e)),
        }
        // Retry once now that we hold a token.
        self.send(url, accept).map_err(map_ureq)
    }

    // `ureq::Error` is large (~272 B) and is the external type we must pass
    // through here; boxing it would only churn the one call site in `authed_get`.
    #[allow(clippy::result_large_err)]
    fn send(&self, url: &str, accept: &str) -> std::result::Result<ureq::Response, ureq::Error> {
        let mut r = self.agent.get(url).set("Accept", accept);
        if let Some(t) = &self.token {
            r = r.set("Authorization", &format!("Bearer {t}"));
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
