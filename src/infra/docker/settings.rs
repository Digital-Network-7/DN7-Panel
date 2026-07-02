//! Registry/mirror lists consulted by the (legacy bollard) image-pull selector.
//! The Docker daemon-settings editor + the "install Docker" flow were removed
//! (DN7 Panel runs its own built-in runtime — there's no daemon to configure or
//! install). Only the mirror/registry lists `pull.rs` reads remain; they default
//! to the built-in mirror set and are no longer user-configurable.
use super::*;

pub(crate) fn default_mirrors() -> Vec<String> {
    [
        "docker.m.daocloud.io",
        "docker.1panel.live",
        "hub.rat.dev",
        "mirror.ccs.tencentyun.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DockerSettings {
    #[serde(default = "default_mirrors")]
    pub(crate) mirrors: Vec<String>,
    #[serde(default)]
    pub(crate) registries: Vec<String>,
}
impl Default for DockerSettings {
    fn default() -> Self {
        DockerSettings {
            mirrors: default_mirrors(),
            registries: Vec::new(),
        }
    }
}

fn dk_settings_path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("docker-settings.json")
}

pub(crate) fn load_dk_settings() -> DockerSettings {
    std::fs::read_to_string(dk_settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<DockerSettings>(&s).ok())
        .unwrap_or_default()
}
