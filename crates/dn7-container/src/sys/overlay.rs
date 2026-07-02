//! overlayfs assembly. An image's merged rootfs is extracted into the store once
//! (read-only, shared); each container gets a copy-on-write overlay over it — a
//! per-container `upperdir` for writes plus a `workdir`. Container starts become
//! a mount instead of a full rootfs copy, and writes never touch the shared
//! image.
//!
//! (P2's merged-per-container extraction is superseded by this for image runs.
//! Per-*layer* sharing across different images is a later refinement.)

use std::path::Path;

use nix::mount::{mount, umount2, MntFlags, MsFlags};

use crate::error::{Error, Result};

/// Mount a copy-on-write overlay at `target`: `lower` (the shared, read-only
/// image rootfs) under `upper` (this container's writes), with `work` as
/// overlayfs's scratch area. `upper`/`work` must be on the same filesystem.
pub fn mount_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()> {
    for d in [upper, work, target] {
        std::fs::create_dir_all(d).map_err(Error::io(d))?;
    }
    // overlayfs rejects a non-empty workdir from a previous run.
    reset_dir(work)?;

    // A comma in any path would corrupt the comma-separated options string.
    if path_has_comma(lower) || path_has_comma(upper) || path_has_comma(work) {
        return Err(Error::Other("overlay paths must not contain commas".into()));
    }
    let data = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    mount(
        Some("overlay"),
        target,
        Some("overlay"),
        MsFlags::empty(),
        Some(data.as_str()),
    )
    .map_err(Error::sys("mount(overlay)"))
}

/// Unmount the overlay at `target` (lazy detach). A target that isn't mounted is
/// not an error.
pub fn unmount(target: &Path) -> Result<()> {
    match umount2(target, MntFlags::MNT_DETACH) {
        Ok(()) => Ok(()),
        Err(nix::Error::EINVAL) => Ok(()), // not a mount point
        Err(e) => Err(Error::Syscall {
            call: "umount2(overlay)",
            source: e,
        }),
    }
}

fn reset_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(Error::io(dir))?;
    }
    std::fs::create_dir_all(dir).map_err(Error::io(dir))
}

fn path_has_comma(p: &Path) -> bool {
    p.to_string_lossy().contains(',')
}
