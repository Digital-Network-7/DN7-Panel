//! rootfs assembly: the default `/proc`, `/sys`, `/dev` mounts, the standard
//! device nodes, the bundle's configured mounts, and the `pivot_root` that makes
//! the container's rootfs `/`. Runs inside the container's mount + pid namespaces
//! (so a fresh `/proc` reflects the container's PID view).

use std::ffi::CString;
use std::path::Path;

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::stat::{mknod, Mode, SFlag};

use crate::error::{Error, Result};
use crate::oci::spec::{Mount, Spec};

/// Make every mount in this (new) mount namespace private, so the rootfs/dev
/// mounts and the `pivot_root` never propagate back to the host.
pub fn make_private() -> Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(Error::sys("mount(/ private)"))
}

/// Bind `rootfs` onto itself so it becomes a mount point (a `pivot_root`
/// precondition).
fn bind_self(rootfs: &Path) -> Result<()> {
    mount(
        Some(rootfs),
        rootfs,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(Error::sys("mount(rootfs bind self)"))
}

/// Mount the default pseudo-filesystems and create the standard device nodes
/// under `rootfs`, then apply the bundle's own mounts. Paths are still absolute
/// here (we pivot afterwards).
pub fn setup_rootfs(rootfs: &Path, spec: &Spec) -> Result<()> {
    make_private()?;
    bind_self(rootfs)?;

    // /proc — the container's own PID view.
    mount_at(
        rootfs,
        "proc",
        Some("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None,
    )?;
    // /sys — read-only.
    mount_at(
        rootfs,
        "sys",
        Some("sysfs"),
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
        None,
    )?;
    // /sys/fs/cgroup — the container's OWN cgroup, read-only (Docker's
    // cgroupns=private). We're already placed in our target cgroup, so entering a
    // cgroup namespace now roots the view at that subtree; a fresh cgroup2 mount
    // then shows `memory.max`/`cpu.max`/… = this container's limits (so `cat
    // /sys/fs/cgroup/memory.max` and cgroup-aware tools reflect the cap) without
    // leaking the host's tree. Best-effort: skip the mount if the namespace can't
    // be created rather than exposing the whole host hierarchy.
    if nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWCGROUP).is_ok() {
        let _ = mount_at(
            rootfs,
            "sys/fs/cgroup",
            Some("cgroup2"),
            Some("cgroup2"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_RDONLY,
            None,
        );
    }
    // /dev — a small tmpfs we then populate.
    mount_at(
        rootfs,
        "dev",
        Some("tmpfs"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )?;
    // /dev/pts — a private devpts instance for the container's terminals.
    ensure_dir(&rootfs.join("dev/pts"))?;
    mount_at(
        rootfs,
        "dev/pts",
        Some("devpts"),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )?;
    // /dev/shm — POSIX shared memory.
    ensure_dir(&rootfs.join("dev/shm"))?;
    mount_at(
        rootfs,
        "dev/shm",
        Some("tmpfs"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=65536k"),
    )?;

    make_dev_nodes(rootfs)?;
    make_dev_symlinks(rootfs)?;

    for m in &spec.mounts {
        apply_bundle_mount(rootfs, m)?;
    }
    Ok(())
}

/// Mount `fstype` at `<rootfs>/<rel>`.
fn mount_at(
    rootfs: &Path,
    rel: &str,
    source: Option<&str>,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<()> {
    let target = rootfs.join(rel);
    ensure_dir(&target)?;
    mount(source, target.as_path(), fstype, flags, data)
        .map_err(Error::sys("mount(default fs)"))
        .map_err(|e| annotate(e, rel))
}

/// The standard character devices every container expects in `/dev`.
fn make_dev_nodes(rootfs: &Path) -> Result<()> {
    // (name, major, minor)
    const NODES: &[(&str, u64, u64)] = &[
        ("dev/null", 1, 3),
        ("dev/zero", 1, 5),
        ("dev/full", 1, 7),
        ("dev/random", 1, 8),
        ("dev/urandom", 1, 9),
        ("dev/tty", 5, 0),
    ];
    let mode = Mode::from_bits_truncate(0o666);
    for (rel, major, minor) in NODES {
        let path = rootfs.join(rel);
        let dev = libc::makedev(*major as _, *minor as _);
        // Ignore EEXIST: the image may already ship the node.
        match mknod(&path, SFlag::S_IFCHR, mode, dev) {
            Ok(()) => {}
            Err(nix::Error::EEXIST) => {}
            Err(e) => {
                return Err(annotate(
                    Error::Syscall {
                        call: "mknod",
                        source: e,
                    },
                    rel,
                ))
            }
        }
    }
    Ok(())
}

/// `/dev/fd`, `/dev/std{in,out,err}` and `/dev/ptmx` — symlinks the way runc
/// sets them up, pointing into the container's own `/proc`.
fn make_dev_symlinks(rootfs: &Path) -> Result<()> {
    let links: &[(&str, &str)] = &[
        ("/proc/self/fd", "dev/fd"),
        ("/proc/self/fd/0", "dev/stdin"),
        ("/proc/self/fd/1", "dev/stdout"),
        ("/proc/self/fd/2", "dev/stderr"),
        ("pts/ptmx", "dev/ptmx"),
    ];
    for (target, rel) in links {
        let link = rootfs.join(rel);
        match std::os::unix::fs::symlink(target, &link) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Error::Io {
                    path: link,
                    source: e,
                })
            }
        }
    }
    Ok(())
}

/// Apply one bundle-configured mount (P1: `bind`/`rbind` and the simple fs types
/// like `tmpfs`; richer types/idmapped mounts come later).
fn apply_bundle_mount(rootfs: &Path, m: &Mount) -> Result<()> {
    // Skip the pseudo-fs the defaults above already provide, so a stock image
    // config doesn't double-mount them.
    let dest = m.destination.trim_start_matches('/');
    if matches!(dest, "proc" | "sys" | "dev" | "dev/pts" | "dev/shm") {
        return Ok(());
    }

    let (flags, data) = parse_options(&m.options);
    let typ = m.typ.as_deref().unwrap_or("none");
    let target = rootfs.join(dest);

    // The destination is attacker-influenced (a container volume dest), so a `..`
    // that slipped past the upstream validators must still be refused here before
    // any host-side ensure_parent/ensure_dir/write/mount — otherwise
    // `rootfs.join("../../etc/…")` resolves through the real host tree (this runs
    // as host root, pre-pivot). Mirrors image/layer.rs's ParentDir rejection.
    if Path::new(dest)
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(Error::Other(format!(
            "bundle mount destination escapes rootfs (..): {}",
            m.destination
        )));
    }

    // A bind mount's target mirrors its source kind (dir→dir, file→file).
    if flags.contains(MsFlags::MS_BIND) {
        if let Some(src) = &m.source {
            let src_path = Path::new(src);
            if src_path.is_file() {
                ensure_parent(&target)?;
                if !target.exists() {
                    std::fs::write(&target, b"").map_err(Error::io(&target))?;
                }
            } else {
                ensure_dir(&target)?;
            }
            mount(
                Some(src_path),
                target.as_path(),
                None::<&str>,
                flags,
                data.as_deref(),
            )
            .map_err(Error::sys("mount(bind)"))
            .map_err(|e| annotate(e, dest))?;
            // The kernel IGNORES the per-mount flags (MS_RDONLY / nosuid / nodev /
            // noexec / atime) on the initial bind — they only take effect via a
            // follow-up bind+remount. Without this a `:ro` volume is silently
            // mounted read-write. Carry only the lockable flags into the remount.
            let lockable = flags
                & (MsFlags::MS_RDONLY
                    | MsFlags::MS_NOSUID
                    | MsFlags::MS_NODEV
                    | MsFlags::MS_NOEXEC
                    | MsFlags::MS_NOATIME
                    | MsFlags::MS_NODIRATIME
                    | MsFlags::MS_RELATIME);
            if !lockable.is_empty() {
                mount(
                    None::<&str>,
                    target.as_path(),
                    None::<&str>,
                    (flags & MsFlags::MS_REC) | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | lockable,
                    None::<&str>,
                )
                .map_err(Error::sys("mount(bind remount ro)"))
                .map_err(|e| annotate(e, dest))?;
            }
            return Ok(());
        }
        return Err(Error::Config(format!("bind mount {dest} has no source")));
    }

    ensure_dir(&target)?;
    mount(
        m.source.as_deref(),
        target.as_path(),
        Some(typ),
        flags,
        data.as_deref(),
    )
    .map_err(Error::sys("mount(bundle)"))
    .map_err(|e| annotate(e, dest))
}

/// Split OCI mount options into `(MsFlags, data-string)`. Recognised flag
/// keywords become bits; everything else (e.g. `mode=…`, `size=…`) is passed
/// through as comma-joined mount data.
fn parse_options(options: &[String]) -> (MsFlags, Option<String>) {
    let mut flags = MsFlags::empty();
    let mut data: Vec<&str> = Vec::new();
    for opt in options {
        let bit = match opt.as_str() {
            "bind" => Some(MsFlags::MS_BIND),
            "rbind" => Some(MsFlags::MS_BIND | MsFlags::MS_REC),
            "ro" => Some(MsFlags::MS_RDONLY),
            "rw" => Some(MsFlags::empty()),
            "nosuid" => Some(MsFlags::MS_NOSUID),
            "nodev" => Some(MsFlags::MS_NODEV),
            "noexec" => Some(MsFlags::MS_NOEXEC),
            "relatime" => Some(MsFlags::MS_RELATIME),
            "noatime" => Some(MsFlags::MS_NOATIME),
            "strictatime" => Some(MsFlags::MS_STRICTATIME),
            "sync" => Some(MsFlags::MS_SYNCHRONOUS),
            "remount" => Some(MsFlags::MS_REMOUNT),
            _ => None,
        };
        match bit {
            Some(b) => flags |= b,
            None => data.push(opt),
        }
    }
    let data = if data.is_empty() {
        None
    } else {
        Some(data.join(","))
    };
    (flags, data)
}

/// Mask a path from the container: bind `/dev/null` over a file, or mount a
/// read-only empty tmpfs over a directory. An absent path is a no-op (the kernel
/// may not expose it). Called after `pivot`, so `path` is the in-container path
/// (e.g. `/proc/kcore`).
pub fn mask_path(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::io(path)(e)),
    };
    if meta.is_dir() {
        mount(
            Some("tmpfs"),
            path,
            Some("tmpfs"),
            MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(Error::sys("mount(mask dir)"))
    } else {
        mount(
            Some("/dev/null"),
            path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(Error::sys("mount(mask file)"))
    }
}

/// Remount an in-container path read-only (bind onto itself, then remount RO,
/// recursively). Absent paths are skipped.
pub fn readonly_path(path: &Path) -> Result<()> {
    match mount(
        Some(path),
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ) {
        Ok(()) => {}
        // Nothing to bind — path doesn't exist in this container.
        Err(nix::Error::ENOENT) => return Ok(()),
        Err(e) => {
            return Err(Error::Syscall {
                call: "mount(ro bind)",
                source: e,
            })
        }
    }
    mount(
        None::<&str>,
        path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(Error::sys("mount(ro remount)"))
}

/// Remount `/` read-only (after pivot) for a `root.readonly` bundle. The
/// container's `/proc`,`/dev`,… are separate mounts and stay writable; only the
/// rootfs itself becomes read-only.
pub fn set_root_readonly() -> Result<()> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(Error::sys("mount(/ remount ro)"))
}

/// Switch the process root to `rootfs` via the fd-based `pivot_root` dance (the
/// approach runc uses): pivot new over old, then lazily detach the old root so
/// nothing of the host filesystem remains reachable.
pub fn pivot(rootfs: &Path) -> Result<()> {
    let oldroot = open_dir(Path::new("/"))?;
    let newroot = open_dir(rootfs)?;

    fchdir(newroot)?;
    nix::unistd::pivot_root(".", ".").map_err(Error::sys("pivot_root"))?;

    // Step back onto the (now stacked) old root and detach it.
    fchdir(oldroot)?;
    mount(
        None::<&str>,
        ".",
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(Error::sys("mount(old root slave)"))?;
    umount2(".", MntFlags::MNT_DETACH).map_err(Error::sys("umount2(old root)"))?;

    fchdir(newroot)?;
    nix::unistd::chdir("/").map_err(Error::sys("chdir(/)"))?;

    close(oldroot);
    close(newroot);
    Ok(())
}

// --- small fd/path helpers ------------------------------------------------

fn open_dir(path: &Path) -> Result<i32> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::Other(format!("path has NUL: {}", path.display())))?;
    // SAFETY: open with a valid NUL-terminated path; we own the returned fd.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::Io {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(fd)
}

fn fchdir(fd: i32) -> Result<()> {
    // SAFETY: `fd` is an open directory fd we created above.
    if unsafe { libc::fchdir(fd) } < 0 {
        return Err(Error::Io {
            path: format!("<fd {fd}>").into(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn close(fd: i32) {
    // SAFETY: closing an fd we own; ignore the result (nothing to recover).
    unsafe { libc::close(fd) };
}

fn ensure_dir(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(path).map_err(Error::io(path))
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    Ok(())
}

fn annotate(e: Error, what: &str) -> Error {
    Error::Other(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_options_splits_flag_keywords_from_data() {
        let (flags, data) =
            parse_options(&opts(&["bind", "ro", "nosuid", "mode=0755", "size=64k"]));
        assert!(flags.contains(MsFlags::MS_BIND));
        assert!(flags.contains(MsFlags::MS_RDONLY));
        assert!(flags.contains(MsFlags::MS_NOSUID));
        assert_eq!(data.as_deref(), Some("mode=0755,size=64k"));
    }

    #[test]
    fn rbind_is_a_recursive_bind() {
        let (flags, data) = parse_options(&opts(&["rbind"]));
        assert!(flags.contains(MsFlags::MS_BIND));
        assert!(flags.contains(MsFlags::MS_REC));
        assert!(data.is_none());
    }

    #[test]
    fn rw_is_the_absence_of_rdonly() {
        let (flags, _) = parse_options(&opts(&["rw", "noexec"]));
        assert!(!flags.contains(MsFlags::MS_RDONLY));
        assert!(flags.contains(MsFlags::MS_NOEXEC));
    }

    #[test]
    fn bundle_mount_rejects_parent_dir_destination() {
        // A `..` destination is refused before any ensure_dir/write/mount, so this
        // stays hermetic — no root or real mount syscalls are reached.
        let m = Mount {
            destination: "/../escape".to_string(),
            typ: Some("bind".to_string()),
            source: Some("/tmp".to_string()),
            options: opts(&["bind"]),
        };
        assert!(apply_bundle_mount(Path::new("/nonexistent-rootfs"), &m).is_err());
    }
}
