//! Container-init re-exec entrypoint.
//!
//! `spawn_init` clones the namespaces and then has the child `execve` the
//! current binary as `__dn7init <bundle> <sync_fd> <gate> <log_fd>` instead of
//! running [`super::init::run`] in-process. That makes the container init run in
//! a FRESH, single-threaded process image rather than on a copy-on-write fork of
//! the (multithreaded) panel — eliminating the classic fork-in-a-multithreaded-
//! process hazard (a child that allocates before `execve` can deadlock on a
//! libc lock another thread held at clone time). This is the runc/youki model.
//!
//! Every binary that can host the runtime (the panel and `dn7crun`) calls
//! [`run_init_if_invoked`] at the very top of `main`, before any threads start.

use std::os::fd::RawFd;

use super::init::{self, Gate, InitCtx};
use crate::oci::Bundle;

/// argv[1] sentinel marking a re-exec'd container init.
pub const INIT_ARG: &str = "__dn7init";

/// If this process was re-exec'd as the container init, reconstruct the
/// [`InitCtx`] from the bundle + inherited fds and run it. NEVER returns when
/// invoked as the init (it `execve`s the user process or `_exit`s); returns
/// normally (a no-op) for an ordinary launch so `main` can continue.
///
/// Must be called FIRST in `main`, before spawning threads or a runtime.
pub fn run_init_if_invoked() {
    let mut args = std::env::args();
    let _exe = args.next();
    if args.next().as_deref() != Some(INIT_ARG) {
        return; // ordinary launch
    }
    // [bundle_dir, sync_fd, gate, log_fd]
    let rest: Vec<String> = args.collect();
    let fail = |msg: &str| -> ! {
        eprintln!("dn7-container init: {msg}");
        // SAFETY: _exit terminates immediately without running destructors —
        // correct in a re-exec'd init that must not unwind back into main.
        unsafe { libc::_exit(127) }
    };

    let bundle_dir = rest.first().map(String::as_str).unwrap_or("");
    let sync_rfd: RawFd = match rest.get(1).and_then(|s| s.parse().ok()) {
        Some(fd) => fd,
        None => fail("missing/invalid sync fd"),
    };
    let gate = match rest.get(2).map(String::as_str) {
        Some("immediate") => Gate::Immediate,
        Some(s) => match s.parse::<RawFd>() {
            Ok(fd) => Gate::Fifo(fd),
            Err(_) => fail("invalid gate"),
        },
        None => fail("missing gate"),
    };
    let log_fd: RawFd = rest.get(3).and_then(|s| s.parse().ok()).unwrap_or(-1);

    let bundle = match Bundle::load(bundle_dir) {
        Ok(b) => b,
        Err(e) => fail(&format!("load bundle: {e}")),
    };
    let ctx = InitCtx {
        rootfs: bundle.rootfs(),
        hostname: bundle.spec.hostname.clone(),
        spec: bundle.spec,
        sync_rfd,
        gate,
        log_fd: if log_fd >= 0 { Some(log_fd) } else { None },
    };
    // Runs the full in-namespace setup then execve's the user process; on any
    // failure it writes a diagnostic and _exits. Never returns to us.
    init::run(ctx);
    // SAFETY: defensive — init::run does not return on success.
    unsafe { libc::_exit(127) }
}
