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

/// Whether the in-house runtime is the selected container backend. It is the
/// DEFAULT on Linux — the panel's hard invariant is zero external runtime
/// dependencies, so a plain install needs no Docker daemon. `DN7_RUNTIME=docker`
/// opts back into the external Docker daemon (bollard) for operators who want it.
/// Always false off Linux — the runtime is Linux-only, so the panel uses Docker
/// there. This is the single source of truth for backend selection; every other
/// `active()` gate delegates here.
#[cfg(target_os = "linux")]
pub fn selected() -> bool {
    !matches!(std::env::var("DN7_RUNTIME").as_deref(), Ok("docker"))
}
#[cfg(not(target_os = "linux"))]
pub fn selected() -> bool {
    false
}
