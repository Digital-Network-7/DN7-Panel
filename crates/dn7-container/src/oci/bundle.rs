//! An OCI *bundle*: a directory holding `config.json` plus the container's
//! `rootfs`. This is the runtime's input unit (the image layer assembles one in
//! P2/P4; for P1 a bundle is prepared by hand or by the test harness).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::oci::spec::Spec;

/// A loaded bundle: its directory and parsed spec.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub dir: PathBuf,
    pub spec: Spec,
}

impl Bundle {
    /// Load `<dir>/config.json` and validate the bundle has a rootfs.
    pub fn load(dir: impl AsRef<Path>) -> Result<Bundle> {
        let dir = dir.as_ref().to_path_buf();
        let config = dir.join("config.json");
        let bytes = std::fs::read(&config).map_err(Error::io(&config))?;
        let spec = Spec::parse(&bytes)?;

        let root = spec.require_root()?;
        let rootfs = Self::resolve_rootfs(&dir, &root.path);
        if !rootfs.is_dir() {
            return Err(Error::Bundle(format!(
                "rootfs {} is not a directory",
                rootfs.display()
            )));
        }
        Ok(Bundle { dir, spec })
    }

    /// Absolute rootfs path. A relative `root.path` is resolved against the
    /// bundle dir (per the spec); an absolute one is taken as-is.
    pub fn rootfs(&self) -> PathBuf {
        let root = self
            .spec
            .root
            .as_ref()
            .map(|r| r.path.as_str())
            .unwrap_or("rootfs");
        Self::resolve_rootfs(&self.dir, root)
    }

    fn resolve_rootfs(dir: &Path, root_path: &str) -> PathBuf {
        let p = Path::new(root_path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            dir.join(p)
        }
    }
}
