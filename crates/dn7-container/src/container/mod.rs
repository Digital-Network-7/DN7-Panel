//! The container lifecycle — the parent side. Orchestrates cgroup setup, the
//! namespaced `clone`, the cgroup-placement handshake, and the create→start exec
//! gate, then persists `state.json` so the lifecycle verbs can be driven by
//! separate processes.

mod init;
pub mod pty;
pub mod reexec;
pub mod state;

pub use pty::{exec_pty, ExecPty};

use std::os::fd::RawFd;
use std::path::Path;

use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use crate::error::{Error, Result};
use crate::net::NetworkManager;
use crate::oci::Bundle;
use crate::sys::namespaces;
use crate::sys::Cgroup;

use self::init::{Gate, InitCtx};
use self::state::{State, StateMeta, Status};

/// Child stack for `clone`. 8 MiB matches a default thread stack — generous for
/// the small amount the init does before `execve`.
const INIT_STACK: usize = 8 * 1024 * 1024;

/// Where pulled images are assembled into runnable (overlay) bundles.
pub const BUNDLES_DIR: &str = "/var/lib/dn7-container/bundles";

/// The bundle directory for a container assembled from an image.
pub fn bundle_dir(id: &str) -> std::path::PathBuf {
    Path::new(BUNDLES_DIR).join(id)
}

/// Everything needed to assemble + run/create a container from an image: the
/// translated create options the panel (or `dn7crun run-image`) supplies.
pub struct ImageRunSpec {
    pub id: String,
    pub reference: String,
    /// Command override (empty = image Entrypoint+Cmd).
    pub cmd: Vec<String>,
    /// `bridge` | `none` | `host`.
    pub net_mode: String,
    /// Published-port string (`[hostip:]hp:cp[/proto]` joined by `,`).
    pub ports: String,
    pub volumes: Vec<crate::image::volume::VolumeMount>,
    /// Extra `KEY=VALUE` env entries.
    pub env_extra: Vec<String>,
    /// Custom DNS servers (empty = host upstreams).
    pub dns: Vec<String>,
    /// Container hostname (None = the container id).
    pub hostname: Option<String>,
    pub mem_limit: Option<i64>,
    pub cpu_quota: Option<(i64, u64)>,
    pub cpu_shares: Option<u64>,
    pub pids_limit: Option<i64>,
}

/// `run`: create + start + wait, all in one process. The simplest end-to-end
/// path and the one that exercises every primitive. Returns the process exit
/// code. The container leaves no persisted state (it's gone when we return).
pub fn run(id: &str, bundle_dir: &Path) -> Result<i32> {
    let bundle = Bundle::load(bundle_dir)?;
    let cgroup_rel = default_cgroup(id);
    let cg = Cgroup::create(&cgroup_rel, resources(&bundle))?;

    let (rfd, wfd) = sync_pipe()?;
    let ctx = InitCtx {
        rootfs: bundle.rootfs(),
        spec: bundle.spec.clone(),
        hostname: bundle.spec.hostname.clone(),
        sync_rfd: rfd,
        gate: Gate::Immediate,
        log_fd: None, // foreground run inherits the caller's stdio
    };

    let mut stack = vec![0u8; INIT_STACK];
    let pid = spawn_init(ctx, &mut stack, &bundle)?;

    // Parent: close the read end, place the child in the cgroup, then release it.
    close_fd(rfd);
    if let Err(e) = cg.add_pid(pid.as_raw()) {
        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        let _ = waitpid(pid, None);
        let _ = cg.delete();
        return Err(e);
    }
    // Wire networking while the init is still parked on the cgroup-sync pipe, so
    // it sees a fully-configured eth0 the moment it's released.
    let net = match NetworkManager::new().apply(id, pid.as_raw(), &bundle.spec) {
        Ok(n) => n,
        Err(e) => {
            let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None);
            let _ = cg.delete();
            return Err(e);
        }
    };
    release(wfd)?;

    let code = wait_exit(pid)?;
    if let Some(ns) = &net {
        NetworkManager::new().teardown(id, ns);
    }
    let _ = cg.delete();
    drop(stack);
    Ok(code)
}

/// Assemble a runnable (overlay-mounted) bundle for `spec` from a local-or-pulled
/// image: resolve the image, extract the shared read-only rootfs (overlay lower),
/// write `config.json` + `parent.json`, drop a `resolv.conf`, and mount the COW
/// overlay. Returns the bundle path; the caller then `run`s or `create`s on it and
/// is responsible for unmounting `<bundle>/rootfs`.
fn assemble_image_bundle(spec: &ImageRunSpec) -> Result<std::path::PathBuf> {
    use crate::image;
    let store = image::Store::open()?;
    let r = image::Reference::parse(&spec.reference)?;
    // Docker if-not-present: reuse a pulled/loaded image, else pull.
    let rec = match image::ImageRecord::load(&store, &r.store_key()) {
        Ok(rec) => rec,
        Err(_) => image::pull(&spec.reference, &store)?,
    };
    let lower = image::ensure_image_rootfs(&store, &rec)?;
    let cfg = rec.config(&store)?;

    let bundle = bundle_dir(&spec.id);
    let _ = std::fs::remove_dir_all(&bundle);
    std::fs::create_dir_all(&bundle).map_err(Error::io(&bundle))?;

    let hostname = spec.hostname.clone().unwrap_or_else(|| spec.id.clone());
    let opts = image::spec_gen::CreateOpts {
        hostname: &hostname,
        cmd_override: &spec.cmd,
        net_mode: &spec.net_mode,
        ports: &spec.ports,
        volumes: &spec.volumes,
        env_extra: &spec.env_extra,
        mem_limit: spec.mem_limit,
        cpu_quota: spec.cpu_quota,
        cpu_shares: spec.cpu_shares,
        pids_limit: spec.pids_limit,
    };
    image::spec_gen::write_config(&bundle, &cfg, &opts)?;

    // Record the source image so `commit` can layer changes on top.
    let parent_json = bundle.join("parent.json");
    std::fs::write(&parent_json, serde_json::to_vec(&rec)?).map_err(Error::io(&parent_json))?;

    let rootfs = bundle.join("rootfs");
    let upper = bundle.join("upper");
    let work = bundle.join("work");
    if spec.net_mode == "bridge" {
        crate::net::dns::write_resolv_conf_with(&upper.join("etc"), &spec.dns)?;
    }
    crate::sys::overlay::mount_overlay(&lower, &upper, &work, &rootfs)?;
    Ok(bundle)
}

/// `run-image`: assemble a bundle from an image and run it foreground (create +
/// start + wait), then unmount the overlay. Leaves the bundle (with its upper)
/// behind for `commit`.
pub fn run_image(spec: &ImageRunSpec) -> Result<i32> {
    let bundle = assemble_image_bundle(spec)?;
    let result = run(&spec.id, &bundle);
    let _ = crate::sys::overlay::unmount(&bundle.join("rootfs"));
    result
}

/// Assemble a bundle from an image and `create` it detached (parked on the exec
/// FIFO), stamping `meta` into the persisted state for inspect/recreate. The
/// overlay stays mounted for the container's life; `delete` tears it down.
pub fn create_from_image(spec: &ImageRunSpec, meta: StateMeta) -> Result<String> {
    let bundle = assemble_image_bundle(spec)?;
    match create_with_meta(&spec.id, &bundle, meta) {
        Ok(()) => Ok(spec.id.clone()),
        Err(e) => {
            // create failed → roll back the overlay + bundle we just assembled.
            let _ = crate::sys::overlay::unmount(&bundle.join("rootfs"));
            let _ = std::fs::remove_dir_all(&bundle);
            Err(e)
        }
    }
}

/// `create`: set up the container and park its init on the exec FIFO. The
/// container is left in `created`; `start` releases it.
pub fn create(id: &str, bundle_dir: &Path) -> Result<()> {
    create_with_meta(id, bundle_dir, StateMeta::default())
}

/// Like [`create`] but stamps `meta` (image/name/limits/recreate-spec) into the
/// persisted state, atomically with the first save.
pub fn create_with_meta(id: &str, bundle_dir: &Path, meta: StateMeta) -> Result<()> {
    if State::exists(id) {
        return Err(Error::Exists(id.into()));
    }
    let bundle = Bundle::load(bundle_dir)?;
    State::make_dir(id)?;

    // Roll back the state dir on any error past this point (networking is rolled
    // back inside create_inner, where the receipt is known).
    let result = create_inner(id, bundle_dir, &bundle, meta);
    if result.is_err() {
        let _ = State::remove_dir(id);
        let _ = Cgroup::at(&default_cgroup(id)).delete();
    }
    result
}

fn create_inner(id: &str, bundle_dir: &Path, bundle: &Bundle, meta: StateMeta) -> Result<()> {
    let cgroup_rel = default_cgroup(id);
    let cg = Cgroup::create(&cgroup_rel, resources(bundle))?;

    // The exec FIFO: created on the host, handed to the init as an inherited
    // O_PATH fd it re-opens (writable) after pivot to block on.
    let fifo = State::fifo_path(id);
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600))
        .map_err(Error::sys("mkfifo(exec.fifo)"))?;
    let fifo_fd = open_path(&fifo)?;

    // Capture the detached container's stdout/stderr to console.log.
    let log_fd = open_log(&State::log_path(id))?;

    let (rfd, wfd) = sync_pipe()?;
    let ctx = InitCtx {
        rootfs: bundle.rootfs(),
        spec: bundle.spec.clone(),
        hostname: bundle.spec.hostname.clone(),
        sync_rfd: rfd,
        gate: Gate::Fifo(fifo_fd),
        log_fd: Some(log_fd),
    };

    let mut stack = vec![0u8; INIT_STACK];
    let pid = spawn_init(ctx, &mut stack, bundle)?;

    close_fd(rfd);
    close_fd(fifo_fd); // the init holds its own inherited copy
    close_fd(log_fd); // ditto
    if let Err(e) = cg.add_pid(pid.as_raw()) {
        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        let _ = waitpid(pid, None);
        return Err(e);
    }

    // Wire networking while the init is parked on the exec FIFO.
    let net = match NetworkManager::new().apply(id, pid.as_raw(), &bundle.spec) {
        Ok(n) => n,
        Err(e) => {
            let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None);
            let _ = cg.delete();
            return Err(e);
        }
    };
    release(wfd)?;

    let now = unix_now();
    let mut state = State::new(id, pid.as_raw(), bundle_dir, &cgroup_rel, now);
    state.net = net.clone();
    state.meta = meta;
    if let Err(e) = state.save() {
        // Persisting failed after the container + network are up: tear both down.
        if let Some(ns) = &net {
            NetworkManager::new().teardown(id, ns);
        }
        let _ = nix::sys::signal::kill(pid, Signal::SIGKILL);
        let _ = waitpid(pid, None);
        let _ = cg.delete();
        return Err(e);
    }
    drop(stack);
    Ok(())
}

/// `start`: open the exec FIFO's read end, which unblocks the parked init and
/// lets it `execve` the user process.
pub fn start(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    let mut state = State::load(id)?;
    if state.status != Status::Created {
        return Err(Error::BadState {
            id: id.into(),
            state: state.status.as_str(),
            action: "start",
        });
    }
    // Opening O_RDONLY rendezvouses with the init's blocked O_WRONLY open; read
    // the byte it writes to confirm the handoff.
    let fifo = State::fifo_path(id);
    let bytes = std::fs::read(&fifo).map_err(Error::io(&fifo))?;
    if bytes.is_empty() {
        return Err(Error::Other("exec.fifo closed without handoff".into()));
    }
    state.status = Status::Running;
    state.save()
}

/// `stop`: graceful SIGTERM, then SIGKILL (via `cgroup.kill`) if still alive
/// after `timeout`. The bundle/overlay are kept, so a stopped container can be
/// `rerun`. A non-running container is a no-op.
pub fn stop(id: &str, timeout: std::time::Duration) -> Result<()> {
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Ok(());
    }
    let _ = nix::sys::signal::kill(Pid::from_raw(s.pid), Signal::SIGTERM);
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline && state::pid_alive(s.pid) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if state::pid_alive(s.pid) {
        let cg = Cgroup::at(&s.cgroup);
        let _ = cg.kill_all();
        wait_drained(&cg);
    }
    s.status = Status::Stopped;
    s.meta.paused = false;
    s.save()
}

/// `kill`: SIGKILL the whole cgroup at once and mark the container stopped
/// (Docker's `kill` semantics — the container stays, ready to be `rerun`).
pub fn kill_now(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    if s.refresh_status() == Status::Running {
        let cg = Cgroup::at(&s.cgroup);
        let _ = cg.kill_all();
        wait_drained(&cg);
    }
    s.status = Status::Stopped;
    s.meta.paused = false;
    s.save()
}

/// `pause`: freeze the container's cgroup (the process is suspended but alive).
pub fn pause(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "pause",
        });
    }
    Cgroup::at(&s.cgroup).freeze(true)?;
    s.meta.paused = true;
    s.save()
}

/// `unpause`: thaw a frozen container.
pub fn unpause(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    s.refresh_status();
    Cgroup::at(&s.cgroup).freeze(false)?;
    s.meta.paused = false;
    s.save()
}

/// `rerun`: re-execute a stopped container on its existing (still-mounted)
/// bundle, keeping the overlay upper so its filesystem changes persist (Docker
/// restart semantics). Tears down the dead init's networking + empty cgroup
/// first, then re-creates + starts a fresh init. Bumps `restart_count`.
pub fn rerun(id: &str) -> Result<()> {
    let mut s = State::load(id)?;
    if s.refresh_status() == Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: "running",
            action: "rerun",
        });
    }
    if let Some(net) = &s.net {
        NetworkManager::new().teardown(id, net);
    }
    let _ = Cgroup::at(&s.cgroup).delete();
    let bundle = s.bundle.clone();
    let mut meta = s.meta.clone();
    meta.paused = false;
    meta.restart_count = meta.restart_count.saturating_add(1);
    State::remove_dir(id)?;
    create_with_meta(id, &bundle, meta)?;
    start(id)
}

/// `start` for the lifecycle UI: release a freshly-`created` container, or
/// re-execute a stopped one. A running container is a no-op.
pub fn start_or_rerun(id: &str) -> Result<()> {
    let mut s = State::load(id)?;
    match s.refresh_status() {
        Status::Created => start(id),
        Status::Stopped => rerun(id),
        Status::Running => Ok(()),
    }
}

/// `restart`: stop (if running) then re-execute; a never-started container is
/// simply started.
pub fn restart(id: &str) -> Result<()> {
    let mut s = State::load(id)?;
    match s.refresh_status() {
        Status::Created => start(id),
        Status::Running => {
            stop(id, std::time::Duration::from_secs(10))?;
            rerun(id)
        }
        Status::Stopped => rerun(id),
    }
}

/// `state`: the current record, with `status` reconciled against the live pid.
pub fn state(id: &str) -> Result<State> {
    let mut s = State::load(id)?;
    s.refresh_status();
    Ok(s)
}

/// `kill`: send `signal` to the container init (and thus, by pid-ns semantics,
/// the container's process tree when it's a fatal signal).
pub fn kill(id: &str, signal: Signal) -> Result<()> {
    let s = State::load(id)?;
    nix::sys::signal::kill(Pid::from_raw(s.pid), signal).map_err(Error::sys("kill"))
}

/// Every known container, status reconciled.
pub fn list() -> Result<Vec<State>> {
    State::all()
}

/// Resolve a full id/name or a short-id prefix to the full container id (Docker's
/// id-prefix resolution).
pub fn resolve(r: &str) -> Result<String> {
    if State::exists(r) {
        return Ok(r.to_string());
    }
    State::all()?
        .into_iter()
        .find(|s| s.id.starts_with(r))
        .map(|s| s.id)
        .ok_or_else(|| Error::NotFound(r.into()))
}

/// The host path of a container's (overlay) rootfs — file operations read/write
/// here directly (the merged view; writes land in the overlay upper).
pub fn rootfs_of(id: &str) -> Result<std::path::PathBuf> {
    Ok(State::load(id)?.bundle.join("rootfs"))
}

/// A resource-usage snapshot for a container (cgroup v2 counters).
pub fn stats(id: &str) -> Result<crate::sys::cgroup::CgroupStats> {
    let s = State::load(id)?;
    Ok(Cgroup::at(&s.cgroup).stats())
}

/// Run `args` inside a running container's namespaces (mnt/uts/ipc/net/pid),
/// inheriting the caller's stdio. Pure-Rust `setns(2)` (no `nsenter` binary) — see
/// [`enter_namespaces`].
pub fn exec(id: &str, args: &[String]) -> Result<i32> {
    if args.is_empty() {
        return Err(Error::Other("exec needs a command".into()));
    }
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "exec",
        });
    }
    let ns = open_ns_fds(s.pid)?;
    let mut cmd = std::process::Command::new(&args[0]);
    cmd.args(&args[1..]);
    enter_namespaces(&mut cmd, ns, open_cgroup_procs(&s.cgroup));
    let status = cmd
        .status()
        .map_err(|e| Error::Other(format!("exec: {e}")))?;
    Ok(exit_code_of(status))
}

/// Open the container init's namespace fds (`/proc/<pid>/ns/*`) for a `setns`-based
/// exec — the in-process replacement for `nsenter`. `mnt` is LAST so the others
/// still resolve while joining (the fds are pre-opened, so order is robust).
pub(crate) fn open_ns_fds(pid: i32) -> Result<Vec<std::os::fd::OwnedFd>> {
    let mut fds = Vec::new();
    for ns in ["net", "uts", "ipc", "pid", "mnt"] {
        let p = format!("/proc/{pid}/ns/{ns}");
        let f = std::fs::File::open(&p).map_err(Error::io(&p))?;
        fds.push(std::os::fd::OwnedFd::from(f));
    }
    Ok(fds)
}

/// Format a (non-negative) pid as decimal ASCII + trailing `\n` into `buf`,
/// returning the number of bytes written. Allocation-free, so it is safe to call
/// in a post-fork / pre-exec closure. `buf` must hold ≥ 12 bytes (i32 max is 10
/// digits + newline); the exec pids we pass always fit.
fn fmt_pid(pid: libc::pid_t, buf: &mut [u8; 24]) -> usize {
    let mut digits = [0u8; 20];
    let mut n = if pid <= 0 { 0i64 } else { pid as i64 };
    let mut i = digits.len();
    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = digits.len() - i;
    buf[..len].copy_from_slice(&digits[i..]);
    buf[len] = b'\n';
    len + 1
}

/// Open the container cgroup's `cgroup.procs` (write-only) in the *host* mount
/// namespace, BEFORE the exec child joins the container's namespaces. Writing the
/// child pid to this already-open fd inside `pre_exec` works even after the child
/// `setns`'d into the container's mount namespace (where `/sys/fs/cgroup` may be
/// absent or a different view). Best-effort: `None` if the cgroup is gone.
pub(crate) fn open_cgroup_procs(cgroup_rel: &str) -> Option<std::os::fd::OwnedFd> {
    let p = std::path::Path::new("/sys/fs/cgroup")
        .join(cgroup_rel.trim_matches('/'))
        .join("cgroup.procs");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&p)
        .ok()
        .map(std::os::fd::OwnedFd::from)
}

/// Make `cmd` `setns(2)` into the container's namespaces right before `execve`
/// (no `nsenter` binary). The exec'd program is resolved + run inside the
/// container's mount namespace. NOTE: `setns` of a PID namespace places the
/// process's *children* in it (the exec'd process itself stays), which is the
/// nsenter `-p` behavior the use cases need (e.g. `ps` run from a shell).
///
/// `cgroup_procs` (when present) is a write-only fd on the container cgroup's
/// `cgroup.procs`, opened pre-fork in the host mount namespace. After joining the
/// namespaces, the child writes its own pid there so the exec'd process is
/// accounted + limited by the container's cgroup (a tenant shell must not escape
/// the memory limit). Best-effort: a write failure leaves the exec unaccounted but
/// still running.
pub(crate) fn enter_namespaces(
    cmd: &mut std::process::Command,
    ns_fds: Vec<std::os::fd::OwnedFd>,
    cgroup_procs: Option<std::os::fd::OwnedFd>,
) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    // SAFETY: runs in the forked child before exec; `setns`/`as_raw_fd`/`write`/
    // `getpid` are async-signal-safe and allocate nothing (the fd vec is built
    // pre-fork; the pid is formatted into a stack buffer).
    unsafe {
        cmd.pre_exec(move || {
            for fd in &ns_fds {
                if libc::setns(fd.as_raw_fd(), 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Join the container cgroup: write our own pid to the pre-opened
            // cgroup.procs fd (valid regardless of the container's mount ns). Done
            // AFTER setns so we're accounted against the right hierarchy.
            if let Some(procs) = &cgroup_procs {
                let mut buf = [0u8; 24];
                let n = fmt_pid(libc::getpid(), &mut buf);
                let _ = libc::write(procs.as_raw_fd(), buf.as_ptr() as *const libc::c_void, n);
            }
            Ok(())
        });
    }
}

/// Like [`exec`] but captures output (instead of inheriting stdio) and injects
/// `env` vars. Returns (exit code, combined stdout+stderr). Used for in-container
/// tooling that needs its output collected (e.g. the mysql client).
pub fn exec_capture(id: &str, argv: &[String], env: &[(String, String)]) -> Result<(i32, String)> {
    if argv.is_empty() {
        return Err(Error::Other("exec needs a command".into()));
    }
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "exec",
        });
    }
    let ns = open_ns_fds(s.pid)?;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    enter_namespaces(&mut cmd, ns, open_cgroup_procs(&s.cgroup));
    let out = cmd
        .output()
        .map_err(|e| Error::Other(format!("exec: {e}")))?;
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((exit_code_of(out.status), combined))
}

/// Map a process exit status to a conventional code (`128 + signal` if killed).
fn exit_code_of(st: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
}

/// The captured stdout/stderr of a (detached) container. Empty if it hasn't
/// written anything; errors only if the container is unknown.
pub fn logs(id: &str) -> Result<Vec<u8>> {
    if !State::exists(id) {
        return Err(Error::NotFound(id.into()));
    }
    let p = State::log_path(id);
    match std::fs::read(&p) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::Io { path: p, source: e }),
    }
}

/// `delete`: tear down a container's cgroup and state. A container whose init is
/// still alive (created *or* running) is refused unless `force`, which kills the
/// whole cgroup atomically (`cgroup.kill`) and waits for it to drain first.
pub fn delete(id: &str, force: bool) -> Result<()> {
    let mut s = State::load(id)?;
    s.refresh_status();
    let cg = Cgroup::at(&s.cgroup);

    if state::pid_alive(s.pid) {
        if !force {
            return Err(Error::BadState {
                id: id.into(),
                state: s.status.as_str(),
                action: "delete (still alive; use --force)",
            });
        }
        cg.kill_all()?;
        wait_drained(&cg);
    }
    if let Some(net) = &s.net {
        NetworkManager::new().teardown(id, net);
    }
    cg.delete()?;
    // Tear down an overlay bundle we assembled (create_from_image leaves it
    // mounted); never touch a user-provided bundle from a plain `create`.
    if s.bundle.starts_with(BUNDLES_DIR) {
        let _ = crate::sys::overlay::unmount(&s.bundle.join("rootfs"));
        let _ = std::fs::remove_dir_all(&s.bundle);
    }
    State::remove_dir(id)
}

/// Poll the cgroup until it holds no processes (or a short deadline elapses), so
/// the subsequent `rmdir` doesn't race the kernel reaping the killed procs.
fn wait_drained(cg: &Cgroup) {
    for _ in 0..200 {
        if !cg.has_procs() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

// --- internals ------------------------------------------------------------

/// `clone(2)` into the namespaces the spec requests, then have the child
/// `execve` a fresh copy of this binary as the container init (see
/// [`reexec`](super::reexec)). Returns the init's host pid; `signal = SIGCHLD`
/// so the parent can `waitpid` it like any child.
///
/// The child does ONLY async-signal-safe work before `execve` (clear `CLOEXEC`
/// on the fds the init inherits, then `execve`), so although this is a fork of
/// the multithreaded panel, the child never runs allocating Rust code on the
/// copy-on-write image — no fork-in-a-multithreaded-process deadlock. All the
/// real init setup runs in the pristine, single-threaded re-exec'd process.
fn spawn_init(ctx: InitCtx, stack: &mut [u8], bundle: &Bundle) -> Result<Pid> {
    use std::ffi::CString;

    let flags = bundle
        .spec
        .linux
        .as_ref()
        .map(|l| namespaces::create_flags(&l.namespaces))
        .unwrap_or_else(nix::sched::CloneFlags::empty);

    // Build the re-exec argv + envp as C strings BEFORE the clone, so the child
    // allocates nothing. argv: [exe, "__dn7init", bundle_dir, sync_fd, gate, log_fd].
    let exe = std::fs::read_link("/proc/self/exe")
        .map_err(|e| Error::Other(format!("read /proc/self/exe: {e}")))?;
    let (gate_arg, fifo_fd) = match ctx.gate {
        Gate::Immediate => ("immediate".to_string(), -1),
        Gate::Fifo(fd) => (fd.to_string(), fd),
    };
    let sync_rfd = ctx.sync_rfd;
    let log_fd = ctx.log_fd.unwrap_or(-1);

    let cstr = |b: Vec<u8>| CString::new(b).map_err(|_| Error::Other("argv has NUL".into()));
    let argv_owned: Vec<CString> = [
        exe.as_os_str().as_encoded_bytes().to_vec(),
        reexec::INIT_ARG.as_bytes().to_vec(),
        bundle.dir.as_os_str().as_encoded_bytes().to_vec(),
        sync_rfd.to_string().into_bytes(),
        gate_arg.into_bytes(),
        log_fd.to_string().into_bytes(),
    ]
    .into_iter()
    .map(cstr)
    .collect::<Result<_>>()?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_owned.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // Pass the current environment through verbatim (init reads little of it; the
    // user process gets its env from the spec inside init::run).
    let envp_owned: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let mut kv = k.as_encoded_bytes().to_vec();
            kv.push(b'=');
            kv.extend_from_slice(v.as_encoded_bytes());
            CString::new(kv).ok()
        })
        .collect();
    let mut envp_ptrs: Vec<*const libc::c_char> = envp_owned.iter().map(|c| c.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    // The child keeps the owning Vecs alive (the raw ptrs reference them) and runs
    // only async-signal-safe calls. The whole address space is COW-copied at
    // clone, so these survive even after the parent returns and drops its copy.
    let cb = Box::new(move || {
        // Own the C-string backing storage for the closure's whole lifetime (the
        // raw argv/envp ptrs reference it), until execve replaces the image. The
        // `.len()` reads keep these captured (and thus alive) past the ptr build.
        let _alive = (argv_owned.len(), envp_owned.len());
        // SAFETY: fcntl/execve/_exit are async-signal-safe. We clear FD_CLOEXEC on
        // the fds the init must inherit (sync pipe, exec FIFO, log), then replace
        // the image. _exit only on execve failure.
        unsafe {
            libc::fcntl(sync_rfd, libc::F_SETFD, 0);
            if fifo_fd >= 0 {
                libc::fcntl(fifo_fd, libc::F_SETFD, 0);
            }
            if log_fd >= 0 {
                libc::fcntl(log_fd, libc::F_SETFD, 0);
            }
            libc::execve(argv_ptrs[0], argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            libc::_exit(127);
        }
        #[allow(unreachable_code)]
        0
    });

    // SAFETY: `stack` is a live, sufficiently-large, writable buffer; the child
    // body is async-signal-safe up to `execve` (no CLONE_VM, COW image).
    let pid = unsafe { nix::sched::clone(cb, stack, flags, Some(libc::SIGCHLD)) }
        .map_err(Error::sys("clone"))?;
    Ok(pid)
}

/// `dn7/<id>` — the container's cgroup path under the v2 root.
fn default_cgroup(id: &str) -> String {
    format!("dn7/{id}")
}

fn resources(bundle: &Bundle) -> Option<&crate::oci::spec::Resources> {
    bundle
        .spec
        .linux
        .as_ref()
        .and_then(|l| l.resources.as_ref())
}

/// A close-on-exec pipe for the cgroup-placement handshake.
fn sync_pipe() -> Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` is a 2-element array as pipe2 expects.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(Error::Io {
            path: "<pipe2>".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok((fds[0], fds[1]))
}

/// Signal the child to proceed (one byte), then close the write end.
fn release(wfd: RawFd) -> Result<()> {
    let byte = [1u8; 1];
    // SAFETY: writing one byte to the pipe write end we own.
    let n = unsafe { libc::write(wfd, byte.as_ptr() as *const libc::c_void, 1) };
    close_fd(wfd);
    if n != 1 {
        return Err(Error::Io {
            path: "<sync pipe>".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn open_path(path: &Path) -> Result<RawFd> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::Other("fifo path has NUL".into()))?;
    // SAFETY: O_PATH handle to the FIFO; only used as an inherited fd reference.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::io(path)(std::io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Open (creating + truncating) the container log file for the init to inherit.
fn open_log(path: &Path) -> Result<RawFd> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::Other("log path has NUL".into()))?;
    // SAFETY: open a regular file for writing; the returned fd is inherited by
    // the init (so NOT cloexec) and dup2'd onto its stdout/stderr.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(Error::io(path)(std::io::Error::last_os_error()));
    }
    Ok(fd)
}

fn close_fd(fd: RawFd) {
    // SAFETY: closing an fd we own.
    unsafe { libc::close(fd) };
}

/// Reap the init and translate its wait status to a conventional exit code
/// (`128 + signal` for a signalled exit).
fn wait_exit(pid: Pid) -> Result<i32> {
    match waitpid(pid, None).map_err(Error::sys("waitpid"))? {
        WaitStatus::Exited(_, code) => Ok(code),
        WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
        other => Err(Error::Other(format!("unexpected wait status: {other:?}"))),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
