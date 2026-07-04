//! LXCFS-style virtualized procfs/sysfs over a pure-Rust FUSE server, so
//! `free`/`top`/`lscpu` inside a container reflect its cgroup memory and CPU
//! limits instead of the host's.
//!
//! The kernel does NOT namespace `/proc/meminfo`, `/proc/cpuinfo`, `/proc/stat`
//! or `/sys/devices/system/cpu/online`, so a container normally shows host RAM
//! and host core count (the limits are still enforced — only the display is
//! wrong, same as Docker's default). This module mounts one shared FUSE dir and
//! each container bind-mounts its files ([`BINDS`]) over the real ones; every
//! READ resolves the caller's pid → dn7 cgroup → a synthesized file reflecting
//! that container's limits. Non-container callers get the host originals.
//!
//! (Module kept named `meminfo` for its origin; it now serves CPU files too.)
//!
//! Best-effort throughout: if the FUSE mount can't be established, containers
//! keep the host files and start normally.

pub mod abi;
pub mod fuse;
pub mod generate;
pub mod resolve;

use std::path::Path;
use std::sync::OnceLock;

/// Host staging dir for the shared mount (transient `/run`, mirrors the IPAM
/// precedent in `net/ipam.rs`). Fixed path so every container's mount namespace
/// — cloned from the host — inherits it and can bind the files below.
pub const FS_DIR: &str = "/run/dn7-container/meminfo-fs";

/// `(virtual file name, container-relative bind target)`. Each is bound over the
/// container's real procfs/sysfs file in `setup_rootfs`.
pub const BINDS: &[(&str, &str)] = &[
    ("meminfo", "proc/meminfo"),
    ("cpuinfo", "proc/cpuinfo"),
    ("stat", "proc/stat"),
    ("online", "sys/devices/system/cpu/online"),
    ("possible", "sys/devices/system/cpu/possible"),
    ("present", "sys/devices/system/cpu/present"),
];

static STARTED: OnceLock<bool> = OnceLock::new();

/// Idempotent resident-service entry: mount the FUSE fs on a dedicated thread.
/// Returns whether the virtual file is usable. Never panics; on any error
/// returns `false` and callers fall back to the host meminfo.
pub fn ensure_started() -> bool {
    *STARTED.get_or_init(|| match fuse::spawn(Path::new(FS_DIR)) {
        Ok(()) => true,
        Err(_) => false,
    })
}

/// Whether the FUSE fs is mounted — the gate `setup_rootfs` consults before
/// binding it over a container's `/proc/meminfo`.
///
/// This must work from ANY process: `setup_rootfs` runs in the re-exec'd
/// `__dn7init` child, which has its own empty [`STARTED`], so a `OnceLock` check
/// would always say false there. Instead we read the mount table — a pure
/// procfs read that reflects the caller's (inherited) mount namespace and never
/// touches the FUSE file (so no hang even if the server had died).
pub fn available() -> bool {
    std::fs::read_to_string("/proc/self/mounts")
        .map(|s| {
            s.lines().any(|l| {
                let mut f = l.split(' ');
                f.next(); // source ("dn7fuse")
                f.next() == Some(FS_DIR) // mount point
            })
        })
        .unwrap_or(false)
}
