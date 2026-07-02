//! OCI / Docker manifest, index (manifest list), and image-config types — only
//! the fields the runtime needs. Both the OCI and legacy Docker media types use
//! the same JSON shape here, so one set of structs covers both.

use serde::Deserialize;

/// A content descriptor (config, layer, or a per-platform manifest in an index).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    #[serde(default)]
    pub size: i64,
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default)]
    pub variant: Option<String>,
}

/// A single-platform image manifest: points at the config blob + ordered layers.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub config: Descriptor,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
}

/// A multi-platform index / manifest list.
#[derive(Debug, Clone, Deserialize)]
pub struct Index {
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
}

/// The image config blob — the container defaults + the rootfs diff_ids.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: ContainerConfig,
    pub rootfs: Option<RootFs>,
}

/// Container runtime defaults (Docker capitalises these keys).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ContainerConfig {
    #[serde(default, rename = "Env")]
    pub env: Vec<String>,
    #[serde(default, rename = "Cmd")]
    pub cmd: Vec<String>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: String,
    #[serde(default, rename = "User")]
    pub user: String,
    /// Image labels (`org.opencontainers.image.*`, `dn7.*`, …) — feed the panel's
    /// container `description`/`managed` fields.
    #[serde(default, rename = "Labels")]
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RootFs {
    #[serde(default, rename = "diff_ids")]
    pub diff_ids: Vec<String>,
}

/// Media-type predicates (OCI + Docker spellings).
pub mod media {
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

    /// The `Accept` header value advertising every manifest/index type we read.
    pub const ACCEPT: &str = "application/vnd.oci.image.index.v1+json,\
application/vnd.docker.distribution.manifest.list.v2+json,\
application/vnd.oci.image.manifest.v1+json,\
application/vnd.docker.distribution.manifest.v2+json";

    pub fn is_index(mt: &str) -> bool {
        mt.starts_with(OCI_INDEX) || mt.starts_with(DOCKER_LIST)
    }
    pub fn is_manifest(mt: &str) -> bool {
        mt.starts_with(OCI_MANIFEST) || mt.starts_with(DOCKER_MANIFEST)
    }
}

impl Index {
    /// Pick the descriptor matching `arch`/`os` (ignoring variant for simplicity;
    /// arm64 `v8` is the only common variant and matches plain arm64).
    pub fn select(&self, arch: &str, os: &str) -> Option<&Descriptor> {
        self.manifests.iter().find(|d| {
            d.platform
                .as_ref()
                .is_some_and(|p| p.architecture == arch && p.os == os)
        })
    }
}
