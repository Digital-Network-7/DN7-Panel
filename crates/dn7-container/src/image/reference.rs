//! Parse an image reference (`alpine`, `alpine:3.19`, `library/nginx:latest`,
//! `ghcr.io/owner/repo@sha256:…`) into registry + repository + tag/digest, using
//! Docker's defaulting rules (Docker Hub host, `library/` for official images).

use crate::error::{Error, Result};

/// Docker Hub's *API* endpoint (the `docker.io` name is a UI alias).
pub const DOCKER_HUB_API: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host[:port] for the v2 API, e.g. `registry-1.docker.io`.
    pub registry: String,
    /// Full repository path, e.g. `library/alpine`.
    pub repository: String,
    /// Tag (`latest`) or digest (`sha256:…`); see `is_digest`.
    pub reference: String,
    pub is_digest: bool,
}

impl Reference {
    /// Parse `input` with Docker's defaults.
    pub fn parse(input: &str) -> Result<Reference> {
        if input.is_empty() {
            return Err(Error::Other("empty image reference".into()));
        }

        // Split the optional registry host: it's the part before the first '/'
        // *iff* that part looks like a host (has '.', ':', or is "localhost").
        let (host, remainder) = match input.split_once('/') {
            Some((first, rest)) if is_registry_host(first) => (first.to_string(), rest.to_string()),
            _ => (DOCKER_HUB_API.to_string(), input.to_string()),
        };

        // Split the tag or digest off the repository path. A digest uses '@'; a
        // tag uses the last ':' that isn't part of a registry port (already
        // handled, since the host was split off above).
        let (repo_part, reference, is_digest) = if let Some((r, d)) = remainder.split_once('@') {
            (r.to_string(), d.to_string(), true)
        } else if let Some((r, t)) = remainder.rsplit_once(':') {
            (r.to_string(), t.to_string(), false)
        } else {
            (remainder.clone(), "latest".to_string(), false)
        };

        if repo_part.is_empty() {
            return Err(Error::Other(format!("no repository in '{input}'")));
        }

        // Docker Hub: a single-segment repo is an official image → `library/<x>`.
        let repository = if host == DOCKER_HUB_API && !repo_part.contains('/') {
            format!("library/{repo_part}")
        } else {
            repo_part
        };

        if is_digest && !reference.starts_with("sha256:") {
            return Err(Error::Other(format!("unsupported digest '{reference}'")));
        }

        Ok(Reference {
            registry: host,
            repository,
            reference,
            is_digest,
        })
    }

    /// A filesystem-safe identifier for this image (for the on-disk image dir).
    pub fn store_key(&self) -> String {
        let r = self.reference.replace(':', "-");
        format!(
            "{}_{}_{}",
            self.registry,
            self.repository.replace('/', "_"),
            r
        )
    }

    /// Human form, e.g. `registry-1.docker.io/library/alpine:latest`.
    pub fn canonical(&self) -> String {
        let sep = if self.is_digest { "@" } else { ":" };
        format!(
            "{}/{}{}{}",
            self.registry, self.repository, sep, self.reference
        )
    }
}

/// Does `s` look like a registry host (vs the first path segment of a Docker Hub
/// repo)? Docker's rule: contains '.' or ':' or equals "localhost".
fn is_registry_host(s: &str) -> bool {
    s == "localhost" || s.contains('.') || s.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_image_gets_library_prefix() {
        let r = Reference::parse("alpine").unwrap();
        assert_eq!(r.registry, DOCKER_HUB_API);
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
        assert!(!r.is_digest);
    }

    #[test]
    fn tag_is_parsed() {
        let r = Reference::parse("alpine:3.19").unwrap();
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "3.19");
    }

    #[test]
    fn user_repo_on_hub() {
        let r = Reference::parse("grafana/grafana:11.0.0").unwrap();
        assert_eq!(r.registry, DOCKER_HUB_API);
        assert_eq!(r.repository, "grafana/grafana");
        assert_eq!(r.reference, "11.0.0");
    }

    #[test]
    fn explicit_registry_host() {
        let r = Reference::parse("ghcr.io/owner/repo:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/repo");
        assert_eq!(r.reference, "v1");
    }

    #[test]
    fn registry_with_port() {
        let r = Reference::parse("localhost:5000/myimg:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "myimg");
        assert_eq!(r.reference, "dev");
    }

    #[test]
    fn digest_reference() {
        let d = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let r = Reference::parse(&format!("alpine@{d}")).unwrap();
        assert!(r.is_digest);
        assert_eq!(r.reference, d);
    }
}
