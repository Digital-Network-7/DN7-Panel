//! The container init — the code that runs in the freshly-cloned child (PID 1 of
//! the new pid namespace). It finishes isolation setup, optionally parks on the
//! exec FIFO, then `execve`s the user process. It must not unwind past the clone
//! boundary: every failure path logs and `_exit`s rather than returning.

use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::PathBuf;

use nix::unistd::{Gid, Uid};

use crate::oci::spec::Spec;
use crate::sys::mount;

/// How the init reaches its final `execve`.
pub enum Gate {
    /// `run`: exec as soon as setup is done.
    Immediate,
    /// `create`/`start`: park writing to this (already-open, O_PATH) FIFO fd
    /// until `start` opens the read end, then exec.
    Fifo(RawFd),
}

/// Everything the child needs, captured by value so it survives the clone (the
/// child runs on a copy-on-write image of the parent).
pub struct InitCtx {
    pub rootfs: PathBuf,
    pub spec: Spec,
    pub hostname: String,
    /// Read end of the parent→child sync pipe: the parent writes one byte once it
    /// has placed us in the cgroup, gating all container work on accounting.
    pub sync_rfd: RawFd,
    pub gate: Gate,
    /// Inherited fd to the container log file; the user process's stdout+stderr
    /// are redirected to it (detached containers). `None` = inherit the caller's
    /// stdio (foreground `run`).
    pub log_fd: Option<RawFd>,
}

/// Run the init. Never returns on success (it `execve`s); on failure it writes a
/// diagnostic and `_exit`s with a non-zero code, so the parent's `waitpid` sees
/// the failure.
pub fn run(ctx: InitCtx) -> isize {
    match try_run(&ctx) {
        Ok(()) => unreachable!("execve does not return on success"),
        Err(msg) => {
            // Best-effort stderr; the parent reports the wait status regardless.
            eprintln!("dn7-container init: {msg}");
            unsafe { libc::_exit(127) };
        }
    }
}

fn try_run(ctx: &InitCtx) -> std::result::Result<(), String> {
    // 1. Wait for the parent to move us into the cgroup before we spawn anything.
    wait_for_cgroup(ctx.sync_rfd)?;

    // 2. UTS: name the container.
    if !ctx.hostname.is_empty() {
        nix::unistd::sethostname(&ctx.hostname).map_err(|e| format!("sethostname: {e}"))?;
    }

    // 3. Mounts + pivot into the rootfs.
    mount::setup_rootfs(&ctx.rootfs, &ctx.spec).map_err(|e| format!("rootfs: {e}"))?;
    mount::pivot(&ctx.rootfs).map_err(|e| format!("pivot_root: {e}"))?;

    // 3b. Mask + read-only kernel paths (e.g. /proc/kcore, /proc/sys), while we
    //     still hold the mount privilege and before the rootfs goes read-only.
    if let Some(linux) = ctx.spec.linux.as_ref() {
        for p in &linux.masked_paths {
            mount::mask_path(std::path::Path::new(p)).map_err(|e| format!("mask {p}: {e}"))?;
        }
        for p in &linux.readonly_paths {
            mount::readonly_path(std::path::Path::new(p))
                .map_err(|e| format!("readonly {p}: {e}"))?;
        }
    }

    // 3c. Read-only rootfs, if the bundle asks for it.
    if ctx.spec.root.as_ref().is_some_and(|r| r.readonly) {
        mount::set_root_readonly().map_err(|e| format!("readonly rootfs: {e}"))?;
    }

    let process = ctx
        .spec
        .process
        .as_ref()
        .ok_or_else(|| "missing process".to_string())?;

    // 4. Working directory (now relative to the new root).
    nix::unistd::chdir(process.cwd.as_str()).map_err(|e| format!("chdir {}: {e}", process.cwd))?;

    // 5. Apply the requested environment to our own process so the exec'd binary
    //    inherits it and PATH search uses the container's PATH.
    apply_env(&process.env);

    // 6. Resource limits, while still privileged enough to raise hard limits.
    apply_rlimits(&process.rlimits)?;

    // 7. Capabilities: drop the bounding set and confine the others. Applied as
    //    root (before the uid drop) so it fully confines a root container; a
    //    non-root container carries any caps across the uid change via `ambient`.
    if let Some(caps) = process.capabilities.as_ref() {
        apply_capabilities(caps)?;
    }

    // 8. Drop to the requested user. gid first, then supplementary groups, then
    //    uid — order matters, can't set groups after dropping uid.
    set_credentials(
        process.user.gid,
        &process.user.additional_gids,
        process.user.uid,
    )?;

    // 9. no_new_privileges. Forced on when a seccomp filter is present: with our
    //    capabilities dropped, installing a filter needs NNP (no CAP_SYS_ADMIN).
    let seccomp = ctx.spec.linux.as_ref().and_then(|l| l.seccomp.as_ref());
    if process.no_new_privileges || seccomp.is_some() {
        set_no_new_privs()?;
    }

    // 10. The create/start rendezvous, if any — before seccomp, so the FIFO
    //     syscalls aren't subject to the filter.
    if let Gate::Fifo(fd) = ctx.gate {
        wait_on_exec_fifo(fd)?;
    }

    // 11. Wire the container's console. For a tty container (`process.terminal`)
    //     the inherited fd is a PTY *slave*: make it the controlling terminal on
    //     stdin/stdout/stderr so the main process (e.g. an interactive shell)
    //     blocks for input instead of hitting EOF and exiting immediately. For a
    //     plain detached container it is the log file → stdout/stderr only. `None`
    //     inherits the caller's stdio (foreground `run`).
    if let Some(fd) = ctx.log_fd {
        let want_tty = ctx
            .spec
            .process
            .as_ref()
            .map(|p| p.terminal)
            .unwrap_or(false);
        if want_tty {
            setup_tty(fd)?;
        } else {
            redirect_stdio(fd)?;
        }
    }

    // 12. Seccomp — installed last, so only the user process (and the execve
    //     itself) run under the filter.
    if let Some(sc) = seccomp {
        crate::sys::seccomp::apply(sc).map_err(|e| format!("seccomp: {e}"))?;
    }

    // 13. Hand off to the user process. Never returns on success.
    exec(&process.args)
}

/// Block until the parent signals (one byte) that we're in the cgroup. EOF means
/// the parent died before signalling — abort.
fn wait_for_cgroup(rfd: RawFd) -> std::result::Result<(), String> {
    let mut buf = [0u8; 1];
    loop {
        // SAFETY: `rfd` is the inherited read end of the sync pipe.
        let n = unsafe { libc::read(rfd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            unsafe { libc::close(rfd) };
            return Ok(());
        }
        if n == 0 {
            return Err("parent closed sync pipe before cgroup placement".into());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(format!("sync pipe read: {err}"));
    }
}

/// Replace the environment with the spec's. (Single-threaded child, so the
/// `set_var`/`remove_var` calls are safe here.)
fn apply_env(env: &[String]) {
    for (key, _) in std::env::vars() {
        std::env::remove_var(key);
    }
    for entry in env {
        match entry.split_once('=') {
            Some((k, v)) => std::env::set_var(k, v),
            None => std::env::set_var(entry, ""),
        }
    }
}

fn set_credentials(gid: u32, extra: &[u32], uid: u32) -> std::result::Result<(), String> {
    nix::unistd::setresgid(Gid::from_raw(gid), Gid::from_raw(gid), Gid::from_raw(gid))
        .map_err(|e| format!("setresgid({gid}): {e}"))?;
    let groups: Vec<Gid> = extra.iter().map(|g| Gid::from_raw(*g)).collect();
    // setgroups requires CAP_SETGID; we still have it here (pre-uid-drop, no
    // user-ns). Tolerate failure only when there are no extra groups to set.
    if let Err(e) = nix::unistd::setgroups(&groups) {
        if !groups.is_empty() {
            return Err(format!("setgroups: {e}"));
        }
    }
    nix::unistd::setresuid(Uid::from_raw(uid), Uid::from_raw(uid), Uid::from_raw(uid))
        .map_err(|e| format!("setresuid({uid}): {e}"))?;
    Ok(())
}

/// Confine the process to the spec's capability sets. Drops every bounding
/// capability not in `bounding` (so it can never be regained, even across
/// `execve` or a setuid binary), then sets inheritable/permitted/effective and
/// the ambient set. Run as root before the uid drop.
fn apply_capabilities(c: &crate::oci::spec::Capabilities) -> std::result::Result<(), String> {
    use caps::CapSet;

    let bounding = parse_caps(&c.bounding)?;
    let permitted = parse_caps(&c.permitted)?;
    let effective = parse_caps(&c.effective)?;
    let inheritable = parse_caps(&c.inheritable)?;
    let ambient = parse_caps(&c.ambient)?;

    // Drop bounding caps not in the allowed set (PR_CAPBSET_DROP each). Done
    // first, while effective still holds CAP_SETPCAP.
    let current = caps::read(None, CapSet::Bounding).map_err(|e| format!("read bounding: {e}"))?;
    for cap in current.difference(&bounding) {
        caps::drop(None, CapSet::Bounding, *cap)
            .map_err(|e| format!("drop bounding {cap}: {e}"))?;
    }

    // Order matters: each `capset` must keep effective ⊆ permitted. Shrink
    // effective *before* permitted (effective stays a subset of the still-full
    // permitted), then permitted, then inheritable.
    caps::set(None, CapSet::Effective, &effective).map_err(|e| format!("set effective: {e}"))?;
    caps::set(None, CapSet::Permitted, &permitted).map_err(|e| format!("set permitted: {e}"))?;
    caps::set(None, CapSet::Inheritable, &inheritable)
        .map_err(|e| format!("set inheritable: {e}"))?;

    // Ambient: caps a non-root process keeps across setuid + execve.
    caps::clear(None, CapSet::Ambient).map_err(|e| format!("clear ambient: {e}"))?;
    for cap in &ambient {
        caps::raise(None, CapSet::Ambient, *cap)
            .map_err(|e| format!("raise ambient {cap}: {e}"))?;
    }
    Ok(())
}

/// Parse `CAP_*` names into a capability set.
fn parse_caps(names: &[String]) -> std::result::Result<caps::CapsHashSet, String> {
    let mut set = caps::CapsHashSet::new();
    for n in names {
        let cap = n
            .parse::<caps::Capability>()
            .map_err(|e| format!("invalid capability {n}: {e}"))?;
        set.insert(cap);
    }
    Ok(set)
}

/// Apply `setrlimit` for each spec rlimit (while still privileged enough to
/// raise hard limits).
fn apply_rlimits(rlimits: &[crate::oci::spec::Rlimit]) -> std::result::Result<(), String> {
    for rl in rlimits {
        // The `RLIMIT_*` constants carry the platform's own resource type
        // (`__rlimit_resource_t` on glibc, `c_int` on musl) — let it infer, and
        // cast at the call so this compiles on both libc flavors (musl release).
        let res = match rl.typ.as_str() {
            "RLIMIT_NOFILE" => libc::RLIMIT_NOFILE,
            "RLIMIT_NPROC" => libc::RLIMIT_NPROC,
            "RLIMIT_CORE" => libc::RLIMIT_CORE,
            "RLIMIT_CPU" => libc::RLIMIT_CPU,
            "RLIMIT_FSIZE" => libc::RLIMIT_FSIZE,
            "RLIMIT_STACK" => libc::RLIMIT_STACK,
            "RLIMIT_AS" => libc::RLIMIT_AS,
            "RLIMIT_MEMLOCK" => libc::RLIMIT_MEMLOCK,
            "RLIMIT_DATA" => libc::RLIMIT_DATA,
            "RLIMIT_NICE" => libc::RLIMIT_NICE,
            other => return Err(format!("unsupported rlimit: {other}")),
        };
        let lim = libc::rlimit {
            rlim_cur: rl.soft,
            rlim_max: rl.hard,
        };
        // SAFETY: `res` is a valid resource constant; `lim` is a live rlimit.
        if unsafe { libc::setrlimit(res as _, &lim) } != 0 {
            return Err(format!(
                "setrlimit {}: {}",
                rl.typ,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Make an inherited PTY *slave* fd the controlling terminal on stdin/stdout/
/// stderr (a tty container). The shell then reads from the tty and blocks for
/// input — the parent holds the master open for the container's lifetime, so the
/// shell never sees EOF and stays alive (docker `-t` semantics). Mirrors the exec
/// pty path; async-signal-safe (raw libc only). `setsid`/`TIOCSCTTY` are
/// best-effort — the `dup2` of the slave onto stdin is what keeps the process
/// alive; the session/controlling-tty bits only add full job-control semantics.
fn setup_tty(slave: RawFd) -> std::result::Result<(), String> {
    // SAFETY: post-fork/pre-exec, single-threaded; only async-signal-safe libc.
    unsafe {
        libc::setsid();
        for target in [0, 1, 2] {
            if libc::dup2(slave, target) < 0 {
                return Err(format!(
                    "dup2(pty → {target}): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        libc::ioctl(0, libc::TIOCSCTTY as _, 0);
        if slave > 2 {
            libc::close(slave);
        }
    }
    Ok(())
}

/// Point stdout (fd 1) and stderr (fd 2) at the container log fd.
fn redirect_stdio(log_fd: RawFd) -> std::result::Result<(), String> {
    for target in [1, 2] {
        // SAFETY: dup2 of an inherited, valid log fd onto a standard fd.
        if unsafe { libc::dup2(log_fd, target) } < 0 {
            return Err(format!(
                "dup2(log → {target}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn set_no_new_privs() -> std::result::Result<(), String> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS and the documented constant args.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!(
            "prctl(NO_NEW_PRIVS): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Re-open the exec FIFO (held as an O_PATH fd inherited from the parent) for
/// writing via `/proc/self/fd`, write a byte — which blocks until `start` opens
/// the read end — then exec proceeds. This is the create→start gate.
fn wait_on_exec_fifo(path_fd: RawFd) -> std::result::Result<(), String> {
    let proc_path = format!("/proc/self/fd/{path_fd}");
    let c = CString::new(proc_path).map_err(|e| format!("fifo path: {e}"))?;
    // SAFETY: re-open the FIFO inode the O_PATH fd refers to, for writing.
    let wfd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if wfd < 0 {
        return Err(format!(
            "open exec.fifo for write: {}",
            std::io::Error::last_os_error()
        ));
    }
    let byte = [0u8; 1];
    // SAFETY: writing one byte to the FIFO; blocks until the reader (`start`)
    // appears.
    let n = unsafe { libc::write(wfd, byte.as_ptr() as *const libc::c_void, 1) };
    unsafe { libc::close(wfd) };
    unsafe { libc::close(path_fd) };
    if n != 1 {
        return Err(format!(
            "write exec.fifo: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `execvpe` the user process; PATH search uses the env we just applied. Returns
/// only on failure.
fn exec(args: &[String]) -> std::result::Result<(), String> {
    if args.is_empty() {
        return Err("process.args is empty".into());
    }
    let prog = CString::new(args[0].as_str()).map_err(|e| format!("arg0: {e}"))?;
    let argv: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| format!("argv: {e}"))?;

    // Build envp from the (now container) environment.
    let envp: Vec<CString> = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();

    // execvpe searches PATH when arg0 has no slash.
    let _ = nix::unistd::execvpe(&prog, &argv, &envp);
    Err(format!(
        "execvpe {}: {}",
        args[0],
        std::io::Error::last_os_error()
    ))
}
