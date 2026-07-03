//! Volume mounts: `-v src:dst[:ro|rw]`. A `src` containing `/` is a host bind
//! mount; otherwise it names a managed volume — a directory under the store,
//! auto-created on first use (Docker's `-v name:/path` behavior). Resolved specs
//! become OCI bind mounts in the generated `config.json`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

const VOLUMES_DIR: &str = "/var/lib/dn7-container/volumes";

#[derive(Debug, Clone)]
pub struct VolumeMount {
    pub source: PathBuf,
    pub dest: String,
    pub ro: bool,
}

/// A named volume on disk.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub name: String,
    pub path: PathBuf,
}

/// Create a named volume (a managed directory). Idempotent.
pub fn create(name: &str) -> Result<()> {
    create_with_mount(name, None)
}

/// Create a named volume, optionally backed by a host path (docker's `local`
/// driver host bind). A host-path volume is a symlink at the volume name pointing
/// at the (created) host directory, so `resolve`/`list`/bind all follow it. The
/// CALLER must have vetted the host path against the bind deny-list. Idempotent.
pub fn create_with_mount(name: &str, mountpoint: Option<&Path>) -> Result<()> {
    let p = named_path(name)?;
    match mountpoint {
        Some(mp) => {
            std::fs::create_dir_all(mp).map_err(Error::io(mp))?;
            if p.exists() {
                return Ok(());
            }
            std::fs::create_dir_all(Path::new(VOLUMES_DIR)).map_err(Error::io(VOLUMES_DIR))?;
            std::os::unix::fs::symlink(mp, &p).map_err(Error::io(&p))
        }
        None => std::fs::create_dir_all(&p).map_err(Error::io(&p)),
    }
}

/// Remove a named volume and its contents. Absent is OK. A host-path (symlink)
/// volume only has its symlink dropped — the host data is NEVER deleted.
pub fn remove(name: &str) -> Result<()> {
    let p = named_path(name)?;
    match std::fs::symlink_metadata(&p) {
        Ok(m) if m.file_type().is_symlink() => std::fs::remove_file(&p).map_err(Error::io(&p)),
        Ok(_) => match std::fs::remove_dir_all(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&p)(e)),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(&p)(e)),
    }
}

/// Path of a named volume, with a name-safety check (no traversal/separators).
fn named_path(name: &str) -> Result<PathBuf> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !ok {
        return Err(Error::Other(format!("bad volume name {name:?}")));
    }
    Ok(Path::new(VOLUMES_DIR).join(name))
}

/// List the named volumes under the store's volumes directory.
pub fn list() -> Result<Vec<VolumeInfo>> {
    let dir = Path::new(VOLUMES_DIR);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(dir)(e)),
    };
    let mut out = Vec::new();
    for ent in entries.flatten() {
        // A managed dir, OR a symlink to a host-path volume (path().is_dir follows).
        let is_vol = ent.file_type().map(|t| t.is_dir()).unwrap_or(false) || ent.path().is_dir();
        if is_vol {
            if let Ok(name) = ent.file_name().into_string() {
                out.push(VolumeInfo {
                    name,
                    path: std::fs::canonicalize(ent.path()).unwrap_or_else(|_| ent.path()),
                });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Resolve a `-v src:dst[:ro|rw]` spec, creating a named volume's directory if
/// needed.
pub fn resolve(spec: &str) -> Result<VolumeMount> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (src, dst, ro) = match parts.as_slice() {
        [s, d] => (*s, *d, false),
        [s, d, "ro"] => (*s, *d, true),
        [s, d, "rw"] => (*s, *d, false),
        _ => {
            return Err(Error::Other(format!(
                "bad volume spec {spec:?} (want src:dst[:ro])"
            )))
        }
    };
    if !dst.starts_with('/') {
        return Err(Error::Other(format!(
            "volume destination must be absolute: {dst:?}"
        )));
    }
    // A `..` in the destination would let the bind target escape the container
    // rootfs (`rootfs.join(dest)` resolves through the real host tree). This is
    // the crate-level gate — safe even without the panel's validate_path.
    if Path::new(dst)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(Error::Other(format!(
            "volume destination must not contain '..': {dst:?}"
        )));
    }
    let source = if src.contains('/') {
        PathBuf::from(src) // host bind mount (auto-created at create time if absent)
    } else {
        let ok = !src.is_empty()
            && src
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if !ok {
            return Err(Error::Other(format!("bad volume name {src:?}")));
        }
        let p = Path::new(VOLUMES_DIR).join(src);
        std::fs::create_dir_all(&p).map_err(Error::io(&p))?;
        p
    };
    Ok(VolumeMount {
        source,
        dest: dst.to_string(),
        ro,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_and_error_forms() {
        let v = resolve("/host/data:/data").unwrap();
        assert_eq!(v.source, PathBuf::from("/host/data"));
        assert_eq!(v.dest, "/data");
        assert!(!v.ro);

        let v = resolve("/host:/data:ro").unwrap();
        assert!(v.ro);

        assert!(resolve("/host:relative").is_err()); // dest not absolute
        assert!(resolve("only-one-part").is_err());
        assert!(resolve("bad name:/x").is_err()); // bad named-volume chars

        // A `..` in the destination is rejected before any dir creation, so this
        // stays hermetic (host-path source, no named-volume I/O).
        assert!(resolve("/host:/data/../../etc:ro").is_err());
    }
}
