//! Apply image layers (gzip'd tarballs) onto a rootfs directory, in order,
//! honoring OCI whiteouts. P2 uses *merged* extraction — each layer is unpacked
//! over the previous into a single rootfs. Overlayfs layer-sharing (a writable
//! upper over read-only lowers) is a P4 refinement.

use std::fs;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive;

use crate::error::{Error, Result};
use crate::image::store::Store;

/// `.wh.<name>` deletes `<name>`; `.wh..wh..opq` empties the containing dir.
const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

/// Extract the ordered `layers` from the store onto a fresh `rootfs`.
pub fn apply_layers(store: &Store, layers: &[String], rootfs: &Path) -> Result<()> {
    fs::create_dir_all(rootfs).map_err(Error::io(rootfs))?;
    for digest in layers {
        apply_one(store, digest, rootfs)?;
    }
    Ok(())
}

fn apply_one(store: &Store, digest: &str, rootfs: &Path) -> Result<()> {
    let blob = store.open_blob(digest)?;
    let mut ar = Archive::new(GzDecoder::new(blob));
    ar.set_preserve_permissions(true);
    ar.set_preserve_mtime(true);
    ar.set_unpack_xattrs(true);
    ar.set_overwrite(true);

    for entry in ar.entries().map_err(|e| terr(e, digest))? {
        let mut entry = entry.map_err(|e| terr(e, digest))?;
        let raw = entry.path().map_err(|e| terr(e, digest))?.into_owned();
        let rel = sanitize(&raw)?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let name = rel.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let parent = rootfs.join(rel.parent().unwrap_or_else(|| Path::new("")));

        // Opaque whiteout: drop everything currently in the parent directory.
        if name == OPAQUE {
            clear_dir(&parent)?;
            continue;
        }
        // Plain whiteout: remove the single named entry.
        if let Some(target_name) = name.strip_prefix(WHITEOUT) {
            remove_all(&parent.join(target_name))?;
            continue;
        }

        // Normal entry: let tar unpack it within the rootfs (it sanitizes paths
        // and resolves hard/symlinks relative to the root). `false` = skipped as
        // unsafe, which `sanitize` already precludes, so treat it as a no-op.
        entry.unpack_in(rootfs).map_err(|e| terr(e, digest))?;
    }
    Ok(())
}

/// Strip a tar entry path to a safe relative path, rejecting `..` traversal.
fn sanitize(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {} // strip leading '/'
            Component::ParentDir => {
                return Err(Error::Other("layer entry escapes rootfs (..)".into()))
            }
        }
    }
    Ok(out)
}

/// Remove a path whether it's a file, symlink, or directory tree. Absent is OK.
fn remove_all(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(path)(e)),
    };
    let r = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    r.map_err(Error::io(path))
}

/// Empty a directory's contents (for an opaque whiteout), leaving the dir itself.
fn clear_dir(dir: &Path) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(dir)(e)),
    };
    for ent in entries.flatten() {
        remove_all(&ent.path())?;
    }
    Ok(())
}

fn terr(e: std::io::Error, digest: &str) -> Error {
    Error::Other(format!("layer {digest}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_root_and_rejects_traversal() {
        assert_eq!(
            sanitize(Path::new("/etc/hosts")).unwrap(),
            PathBuf::from("etc/hosts")
        );
        assert_eq!(sanitize(Path::new("./a/b")).unwrap(), PathBuf::from("a/b"));
        assert!(sanitize(Path::new("a/../../etc")).is_err());
    }
}
