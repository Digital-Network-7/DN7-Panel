//! DN7 self-contained container runtime.
//!
//! P1 scope — the OCI *runtime* core (a runc-equivalent): take an OCI bundle and
//! create / start / kill / delete a container with Linux namespaces, cgroup v2
//! resource limits, and a `pivot_root`'d rootfs. No Docker, no runc, no youki.
//!
//! Layering:
//! - [`oci`] — the runtime-spec types + bundle layout (portable).
//! - [`sys`] — thin, typed wrappers over the Linux syscalls we use (namespaces,
//!   mounts, cgroup v2). Linux-only.
//! - [`container`] — the lifecycle state machine built on `sys`. Linux-only.
//!
//! Everything kernel-touching is gated to `target_os = "linux"`, so the crate
//! still type-checks on a dev mac (only `error` + `oci` compile there); the real
//! build/test target is Linux.

pub mod error;
pub mod image;
pub mod net;
pub mod oci;

#[cfg(target_os = "linux")]
pub mod sys;

#[cfg(target_os = "linux")]
pub mod container;

#[cfg(target_os = "linux")]
pub mod cli;

pub use error::{Error, Result};

/// Whether the in-house runtime is the selected container backend (the panel sets
/// `DN7_RUNTIME=dn7`). Always false off Linux — the runtime is Linux-only, so the
/// panel must use Docker there.
#[cfg(target_os = "linux")]
pub fn selected() -> bool {
    matches!(std::env::var("DN7_RUNTIME").as_deref(), Ok("dn7"))
}
#[cfg(not(target_os = "linux"))]
pub fn selected() -> bool {
    false
}
