//! The container lifecycle — the parent side. Orchestrates cgroup setup, the
//! namespaced `clone`, the cgroup-placement handshake, and the create→start exec
//! gate, then persists `state.json` so the lifecycle verbs can be driven by
//! separate processes.

mod init;
pub mod pty;
pub mod reexec;
pub mod state;

pub use pty::{exec_pty, ExecPty};

use std::os::fd::{IntoRawFd, RawFd};
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
    /// Allocate a controlling PTY for the main process (docker `-t`) so an
    /// interactive shell (or the image's default command) stays alive.
    pub tty: bool,
    /// Static IPv4 on the primary network (docker `--ip`); `None` = auto-assign.
    pub static_ip: Option<String>,
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
        tty: spec.tty,
        static_ip: spec.static_ip.as_deref(),
    };
    image::spec_gen::write_config(&bundle, &cfg, &opts)?;

    // Record the source image so `commit` can layer changes on top.
    let parent_json = bundle.join("parent.json");
    std::fs::write(&parent_json, serde_json::to_vec(&rec)?).map_err(Error::io(&parent_json))?;

    let rootfs = bundle.join("rootfs");
    let upper = bundle.join("upper");
    let work = bundle.join("work");
    // Docker provides /etc/resolv.conf AND /etc/hosts in every net mode (host
    // mode mirrors the host's resolvers; none still gets the standard files). On a
    // bridge network point the container at the embedded resolver (its gateway) so
    // peer names resolve, with the host upstreams as a fallback if it's down.
    let etc = upper.join("etc");
    let servers: Vec<String> = match spec.net_mode.as_str() {
        "host" | "none" => spec.dns.clone(),
        net => match crate::net::registry::resolve(net) {
            Ok(cfg) => {
                let mut v = vec![cfg.gateway.to_string()];
                v.extend(if spec.dns.is_empty() {
                    crate::net::dns::host_upstreams()
                } else {
                    spec.dns.clone()
                });
                v
            }
            Err(_) => spec.dns.clone(),
        },
    };
    crate::net::dns::write_resolv_conf_with(&etc, &servers)?;
    crate::net::dns::write_hosts(&etc, &hostname, spec.static_ip.as_deref())?;
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
    // Serialize same-id creates for the WHOLE assemble→create: two concurrent
    // "create c1" requests (a double-click / retry storm) would otherwise stomp on
    // one another's overlay bundle + exec FIFO, and the loser's rollback would
    // delete the winner's cgroup — leaving nothing alive and a leaked cgroup. Under
    // the lock the winner builds it and every loser sees `exists` and bails cleanly,
    // BEFORE re-mounting the overlay onto the winner's bundle dir.
    let _guard = State::lock(&spec.id)?;
    if State::exists(&spec.id) {
        return Err(Error::Exists(spec.id.clone()));
    }
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
    // Serialize same-id creates (see `create_from_image`). `create_with_meta` is a
    // lock-free leaf — `rerun_locked` calls it while already holding this lock — so
    // the top-level entry point is the right place to take it.
    let _guard = State::lock(id)?;
    create_with_meta(id, bundle_dir, StateMeta::default())
}

/// Like [`create`] but stamps `meta` (image/name/limits/recreate-spec) into the
/// persisted state, atomically with the first save.
///
/// **Lock-free leaf.** This does NOT take [`State::lock`] — callers that mutate
/// the container concurrently (`create`, `create_from_image`, `rerun_locked`)
/// hold it around the whole sequence. Adding the lock here would self-deadlock
/// `rerun_locked`, which already owns it.
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

    // The container's console fd handed to the init:
    //   - tty container (`process.terminal`): a fresh PTY *slave* — the init makes
    //     it its controlling terminal, and we keep the master here (draining it to
    //     console.log) so the shell blocks for input instead of exiting on EOF.
    //   - plain container: the append-only console.log file (stdout/stderr).
    let tty = bundle
        .spec
        .process
        .as_ref()
        .map(|p| p.terminal)
        .unwrap_or(false);
    let (console_fd, pty_master) = if tty {
        let pty = nix::pty::openpty(None, None).map_err(Error::sys("openpty"))?;
        (pty.slave.into_raw_fd(), Some(pty.master))
    } else {
        (open_log(&State::log_path(id))?, None)
    };

    let (rfd, wfd) = sync_pipe()?;
    let ctx = InitCtx {
        rootfs: bundle.rootfs(),
        spec: bundle.spec.clone(),
        hostname: bundle.spec.hostname.clone(),
        sync_rfd: rfd,
        gate: Gate::Fifo(fifo_fd),
        log_fd: Some(console_fd),
    };

    let mut stack = vec![0u8; INIT_STACK];
    let pid = spawn_init(ctx, &mut stack, bundle)?;

    close_fd(rfd);
    close_fd(fifo_fd); // the init holds its own inherited copy
    close_fd(console_fd); // ditto (the init dup'd the pty slave / log fd)
                          // For a tty container, drain the PTY master to console.log on a dedicated
                          // thread and — crucially — hold the master open for the container's lifetime,
                          // so its slave (the shell's stdin/stdout) never sees EOF. The read returns 0
                          // when the container process exits (all slave fds closed), ending the thread.
    if let Some(master) = pty_master {
        spawn_console_pump(master, State::log_path(id));
    }
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
    // The init is a direct child of this (resident) process — reap it so an exited
    // container flips to Stopped with a real exit code instead of lingering as a
    // Running zombie. Spawn AFTER the state is persisted so the reaper's later
    // load→update→save sees a record to update.
    spawn_reaper(id.to_string(), pid.as_raw());
    drop(stack);
    Ok(())
}

/// Drain a tty container's PTY master into its `console.log` and hold the master
/// open for the container's lifetime — so the slave (the shell's stdin/stdout)
/// never sees EOF and an interactive shell stays alive. The `read` returns 0 when
/// the container process exits (all slave fds close), ending the thread. One
/// parked thread per running tty container, like the reaper.
fn spawn_console_pump(master: std::os::fd::OwnedFd, log_path: std::path::PathBuf) {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    std::thread::spawn(move || {
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: read into a valid local buffer from our own master fd.
            let n = unsafe {
                libc::read(
                    master.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                break; // EOF: the container process exited.
            }
            if let Some(f) = log.as_mut() {
                let _ = f.write_all(&buf[..n as usize]);
            }
        }
        // `master` drops here → the fd is closed.
    });
}

/// Spawn a dedicated thread that blocking-`waitpid`s ONLY the given container
/// init pid (never `-1` — a global reaper would steal the exit status of the
/// panel's other children: CLI shell-outs, fshelper, tokio `Command`). When the
/// init exits, record its real exit code and mark the container `Stopped`, under
/// the per-container [`State::lock`] so it doesn't race a concurrent lifecycle
/// verb. One parked thread per running container, like other runtimes.
///
/// Best-effort throughout: if the caller is not the init's parent (e.g. `start`
/// ran in a different process than `create`), `waitpid` returns ECHILD and the
/// thread simply exits — [`state::pid_alive`]'s zombie check still downgrades the
/// status, only without the precise exit code.
fn spawn_reaper(id: String, init_pid: i32) {
    std::thread::spawn(move || {
        let code = match waitpid(Pid::from_raw(init_pid), None) {
            Ok(WaitStatus::Exited(_, code)) => code,
            Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
            // Any other status (or ECHILD — not our child) leaves the record to
            // pid_alive's zombie downgrade; nothing to write.
            _ => return,
        };
        let _guard = match State::lock(&id) {
            Ok(g) => g,
            Err(_) => return,
        };
        // The record may already be gone (delete raced us) — that's fine.
        let Ok(mut s) = State::load(&id) else { return };
        // Don't clobber a fresh init: a rerun replaces the state dir + pid, so only
        // record against the record still bearing THIS pid.
        if s.pid != init_pid {
            return;
        }
        s.status = Status::Stopped;
        s.meta.exit_code = code;
        s.meta.paused = false;
        let _ = s.save();

        // Restart-policy supervisor: if the init exited on its own (not a user
        // stop) and the policy calls for it, auto-restart after a backoff. Release
        // the lock first — `rerun` re-takes it.
        let policy = s.meta.restart_policy.clone().unwrap_or_default();
        let (rc, user_stopped) = (s.meta.restart_count, s.meta.stopped_by_user);
        drop(_guard);
        if should_restart(&policy, code, rc, user_stopped) {
            std::thread::sleep(restart_backoff(rc));
            // Re-check under the lock that nothing restarted/removed it meanwhile,
            // then count this automatic restart and rerun (which re-takes the lock).
            {
                let Ok(_g) = State::lock(&id) else { return };
                let Ok(mut cur) = State::load(&id) else {
                    return;
                };
                if cur.refresh_status() != Status::Stopped || cur.meta.stopped_by_user {
                    return; // gone, running again, or user-stopped in the window
                }
                cur.meta.restart_count = cur.meta.restart_count.saturating_add(1);
                let _ = cur.save();
            }
            let _ = rerun(&id);
        }
    });
}

/// Whether the restart-policy supervisor should auto-restart a container that
/// just exited with `exit_code`, given its `policy`, prior automatic
/// `restart_count`, and whether the stop was user-initiated. Mirrors Docker:
/// `always` always; `unless-stopped` unless the user stopped it; `on-failure[:N]`
/// only on a non-zero exit, up to N automatic restarts (0/absent = unlimited);
/// `no`/empty never.
fn should_restart(policy: &str, exit_code: i32, restart_count: u32, user_stopped: bool) -> bool {
    let (kind, max) = match policy.split_once(':') {
        Some((k, n)) => (k.trim(), n.trim().parse::<u32>().ok()),
        None => (policy.trim(), None),
    };
    match kind {
        "always" => true,
        "unless-stopped" => !user_stopped,
        "on-failure" => exit_code != 0 && max.is_none_or(|m| m == 0 || restart_count < m),
        _ => false,
    }
}

/// Exponential restart backoff (Docker-style): 100ms doubling, capped at 60s.
fn restart_backoff(restart_count: u32) -> std::time::Duration {
    let ms = 100u64.saturating_mul(1u64 << restart_count.min(9)); // cap the shift
    std::time::Duration::from_millis(ms.min(60_000))
}

/// `start`: open the exec FIFO's read end, which unblocks the parked init and
/// lets it `execve` the user process.
pub fn start(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    start_locked(id)
}

/// `start` without taking the per-container lock — the caller already holds it
/// (e.g. [`rerun`], which owns the lock across its whole load→teardown→create→
/// start sequence). Taking [`State::lock`] here too would self-deadlock (flock is
/// per-open-fd, not recursive).
fn start_locked(id: &str) -> Result<()> {
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
    // Release the container's firewall (DNAT) + IP lease now the init is dead:
    // otherwise the dn7:<id> prerouting rule stays live pointing at a now-free IP,
    // and — because the port-conflict check only counts *Running* containers — a
    // new container could publish the same host port yet be shadowed by this stale
    // rule. `teardown` is idempotent, so a later `rerun`/`delete` is unaffected.
    if let Some(net) = &s.net {
        NetworkManager::new().teardown(id, net);
    }
    s.status = Status::Stopped;
    s.meta.paused = false;
    s.meta.stopped_by_user = true; // an explicit stop/kill — don't auto-restart
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
    // Tear down networking (same rationale as `stop`): drop the stale DNAT + lease
    // so a reused host port isn't shadowed by a rule pointing at the dead IP.
    if let Some(net) = &s.net {
        NetworkManager::new().teardown(id, net);
    }
    s.status = Status::Stopped;
    s.meta.paused = false;
    s.meta.stopped_by_user = true; // an explicit stop/kill — don't auto-restart
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
///
/// Holds the per-container lock across the WHOLE destructive load→teardown→
/// remove→create→start sequence: without it two concurrent restart clicks race,
/// and the loser's rollback (`remove_dir`) would delete the winner's freshly
/// written `state.json`, orphaning a live init. The lock file now lives outside
/// the state dir (see [`state`]), so `remove_dir` can't unlink the lock we hold.
pub fn rerun(id: &str) -> Result<()> {
    let _guard = State::lock(id)?;
    rerun_locked(id)
}

/// `rerun` body, run with the per-container lock already held. Calls the
/// lock-free create/start internals so it never re-takes (and self-deadlocks on)
/// the lock it owns.
fn rerun_locked(id: &str) -> Result<()> {
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
    meta.stopped_by_user = false; // a (re)start clears the user-stop latch
                                  // Docker does NOT bump RestartCount on a manual restart/start — it's a
                                  // crash-loop diagnostic reserved for the restart-policy supervisor's
                                  // automatic restarts. Keep manual rerun count-neutral.
    State::remove_dir(id)?;
    // `create_with_meta` does not take the lock (it's a create-path leaf), so it's
    // safe to call while we hold it; `start_locked` likewise skips the lock.
    create_with_meta(id, &bundle, meta)?;
    start_locked(id)
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

/// Boot reconcile: after a panel/host restart the container inits are gone, so
/// bring back the ones whose restart policy asks for it — Docker's daemon does
/// the same at start. `always` restarts anything that had been started (even if
/// the user stopped it); `unless-stopped` restarts it UNLESS the user stopped it.
/// A never-started (`Created`) container is left alone. Returns the count restarted.
pub fn reconcile_restart_policies() -> usize {
    let Ok(states) = list() else { return 0 };
    let mut n = 0;
    for mut s in states {
        // Never-started containers aren't auto-booted (they were never running).
        if s.status == Status::Created {
            continue;
        }
        let policy = s.meta.restart_policy.clone().unwrap_or_default();
        let kind = policy
            .split_once(':')
            .map(|(k, _)| k)
            .unwrap_or(&policy)
            .trim();
        let want = match kind {
            "always" => true,
            "unless-stopped" => !s.meta.stopped_by_user,
            _ => false,
        };
        if !want || s.refresh_status() == Status::Running {
            continue;
        }
        if rerun(&s.id).is_ok() {
            n += 1;
        }
    }
    n
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
    let sec = load_bundle_spec(&s.bundle).and_then(|spec| sec_downgrade_for(&spec));
    let (env, cwd) = container_env_cwd(&s.bundle);
    let mut cmd = std::process::Command::new(&args[0]);
    cmd.args(&args[1..]);
    apply_image_env(&mut cmd, &env);
    enter_namespaces(&mut cmd, ns, open_cgroup_procs(&s.cgroup), sec, cwd);
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

/// The security downgrade an exec must re-apply after joining the container's
/// namespaces, so an exec'd shell is no more privileged than the container's
/// PID 1 (which `init` confined at start). All fields are pre-computed BEFORE the
/// fork so applying them inside `pre_exec` is allocation-free / async-signal-safe.
///
/// Conservative subset of the init's setup: match PID 1's uid/gid(+groups) and
/// cap the bounding/effective/permitted/inheritable sets to the spec's `bounding`
/// list, then `NO_NEW_PRIVS`. We do NOT re-raise ambient caps or install seccomp
/// (see [`sec_downgrade_for`] notes) — those only *reduce or match* privilege, so
/// omitting them keeps exec strictly ≤ PID 1 and never breaks a working shell.
#[derive(Clone)]
pub(crate) struct SecDowngrade {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    /// Bit i set ⇒ keep capability i (in every base set + bounding).
    keep_caps: u64,
    no_new_privs: bool,
}

/// Build the [`SecDowngrade`] for container `id` from its persisted bundle spec —
/// the same `config.json` the init read. `None` if the bundle/spec/process is
/// unreadable (exec then runs without the extra downgrade, as before — no worse
/// than the pre-existing behavior, and the container's uid/caps still apply to
/// PID 1; a shell is a super-admin-initiated action).
///
/// Deferred vs. the init: (1) ambient caps — re-raising them would *add* back
/// privilege a non-root exec dropped, so we skip it (net effect: exec keeps no
/// ambient caps, ≤ PID 1). (2) seccomp — the init installs it last; re-deriving
/// the BPF here is heavier and only ever narrows the syscall surface, so it is
/// left for a follow-up. Capabilities + uid/gid (the primary escalation vector)
/// are applied.
pub(crate) fn sec_downgrade_for(spec: &crate::oci::spec::Spec) -> Option<SecDowngrade> {
    use caps::CapSet;
    let process = spec.process.as_ref()?;

    // Keep-mask: the spec's bounding set (what PID 1 was confined to). An absent
    // capabilities block ⇒ keep nothing (drop all) — the safe default for a
    // downgrade. Cap indices > 63 are ignored (the u64 mask covers CAP_LAST_CAP on
    // every current kernel).
    let mut keep_caps: u64 = 0;
    if let Some(c) = process.capabilities.as_ref() {
        for name in &c.bounding {
            if let Ok(cap) = name.parse::<caps::Capability>() {
                keep_caps |= 1u64 << cap.index();
            }
        }
    }
    // If the container runs as root (uid 0) with no explicit capability block,
    // fall back to the current bounding set so we don't accidentally strip a
    // legitimately-privileged (but non-`--privileged`, since those are rejected)
    // container's caps from its own shell.
    if process.capabilities.is_none() && process.user.uid == 0 {
        if let Ok(cur) = caps::read(None, CapSet::Bounding) {
            for cap in cur {
                keep_caps |= 1u64 << cap.index();
            }
        }
    }

    Some(SecDowngrade {
        uid: process.user.uid,
        gid: process.user.gid,
        groups: process.user.additional_gids.clone(),
        keep_caps,
        // Force NNP when the container had a seccomp filter or asked for it — an
        // exec must not be able to regain privilege via a setuid binary either.
        no_new_privs: process.no_new_privileges
            || spec.linux.as_ref().is_some_and(|l| l.seccomp.is_some()),
    })
}

/// The container's image environment (as `(K,V)` pairs) + working dir (as a C
/// string for a post-`setns` `chdir`), read from its bundle spec. So an exec /
/// web-terminal runs with the image's PATH/env and starts in its WorkingDir,
/// like `docker exec`, instead of inheriting the panel's env + landing in `/`.
pub(crate) fn container_env_cwd(
    id_bundle: &Path,
) -> (Vec<(String, String)>, Option<std::ffi::CString>) {
    let mut env = Vec::new();
    let mut cwd = None;
    if let Some(spec) = load_bundle_spec(id_bundle) {
        if let Some(p) = spec.process.as_ref() {
            for e in &p.env {
                if let Some((k, v)) = e.split_once('=') {
                    env.push((k.to_string(), v.to_string()));
                }
            }
            if !p.cwd.is_empty() && p.cwd != "/" {
                cwd = std::ffi::CString::new(p.cwd.clone()).ok();
            }
        }
    }
    (env, cwd)
}

/// Apply the image env to `cmd` as the base environment (Docker semantics),
/// preserving the caller's `TERM` so a web terminal still renders correctly.
pub(crate) fn apply_image_env(cmd: &mut std::process::Command, env: &[(String, String)]) {
    let term = std::env::var("TERM").ok();
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(t) = term {
        cmd.env("TERM", t);
    }
}

/// Load the container's bundle spec (for [`sec_downgrade_for`]). Separate from the
/// state load so callers can build the downgrade pre-fork.
fn load_bundle_spec(bundle: &Path) -> Option<crate::oci::spec::Spec> {
    Bundle::load(bundle).ok().map(|b| b.spec)
}

/// The `capset(2)` header/data structs (Linux `_LINUX_CAPABILITY_VERSION_3`),
/// mirrored here so the downgrade can call the raw syscall inside `pre_exec`
/// without the `caps` crate's allocating wrappers. The fields are read by the
/// *kernel* through the raw pointer we pass, not by Rust — hence `dead_code`.
#[repr(C)]
#[allow(dead_code)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

impl SecDowngrade {
    /// Apply the downgrade in the forked child, pre-`execve`. Async-signal-safe:
    /// only raw syscalls, no allocation (the groups vec is read, not built here).
    /// On any failure returns the errno so the parent sees the exec fail rather
    /// than silently running an over-privileged shell.
    ///
    /// # Safety
    /// Must run post-fork / pre-exec in a context where these syscalls are valid
    /// (after the namespaces are joined).
    unsafe fn apply(&self) -> std::io::Result<()> {
        // 1. Drop every bounding capability we are NOT keeping, so it can't be
        //    regained across execve/setuid. Ignore EINVAL for indices past the
        //    kernel's CAP_LAST_CAP (the kernel rejects unknown ones harmlessly).
        for i in 0..64u32 {
            if self.keep_caps & (1u64 << i) == 0 {
                libc::prctl(libc::PR_CAPBSET_DROP, i as libc::c_ulong, 0, 0, 0);
            }
        }

        // 2. Set the three base capability sets to the keep-mask (done while still
        //    privileged, before the uid drop). capset takes two 32-bit words.
        let hdr = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0, // 0 = the calling thread
        };
        let lo = (self.keep_caps & 0xffff_ffff) as u32;
        let hi = (self.keep_caps >> 32) as u32;
        let data = [
            CapData {
                effective: lo,
                permitted: lo,
                inheritable: lo,
            },
            CapData {
                effective: hi,
                permitted: hi,
                inheritable: hi,
            },
        ];
        if libc::syscall(
            libc::SYS_capset as libc::c_long,
            &hdr as *const CapHeader,
            data.as_ptr(),
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }

        // 3. gid, supplementary groups, then uid — same order the init uses (can't
        //    setgroups after dropping uid). setgroups is best-effort when empty.
        if libc::setgroups(
            self.groups.len(),
            self.groups.as_ptr() as *const libc::gid_t,
        ) < 0
            && !self.groups.is_empty()
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setresgid(self.gid, self.gid, self.gid) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setresuid(self.uid, self.uid, self.uid) < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // 4. no_new_privileges last, mirroring the init.
        if self.no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
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
///
/// `sec` (when present) re-applies the container's uid/gid/capability downgrade
/// AFTER joining the namespaces, so an exec shell is not more privileged than the
/// container's PID 1 (see [`SecDowngrade`]). A downgrade failure aborts the exec.
pub(crate) fn enter_namespaces(
    cmd: &mut std::process::Command,
    ns_fds: Vec<std::os::fd::OwnedFd>,
    cgroup_procs: Option<std::os::fd::OwnedFd>,
    sec: Option<SecDowngrade>,
    cwd: Option<std::ffi::CString>,
) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    // SAFETY: runs in the forked child before exec; `setns`/`as_raw_fd`/`write`/
    // `getpid`/`capset`/`setres*id`/`prctl`/`chdir` are async-signal-safe and
    // allocate nothing (the fd vec + groups vec + cwd CString are built pre-fork).
    unsafe {
        cmd.pre_exec(move || {
            for fd in &ns_fds {
                if libc::setns(fd.as_raw_fd(), 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // chdir into the image WorkingDir AFTER setns(mnt) so it resolves in the
            // container's filesystem, matching `docker exec`'s cwd. Best-effort: a
            // missing WorkingDir shouldn't sink the exec (falls back to the mnt root).
            if let Some(cwd) = &cwd {
                libc::chdir(cwd.as_ptr());
            }
            // Join the container cgroup: write our own pid to the pre-opened
            // cgroup.procs fd (valid regardless of the container's mount ns). Done
            // AFTER setns so we're accounted against the right hierarchy.
            if let Some(procs) = &cgroup_procs {
                let mut buf = [0u8; 24];
                let n = fmt_pid(libc::getpid(), &mut buf);
                let _ = libc::write(procs.as_raw_fd(), buf.as_ptr() as *const libc::c_void, n);
            }
            // Re-apply PID 1's security downgrade (caps + uid/gid), so the exec is
            // no more privileged than the container itself. Done AFTER setns +
            // cgroup-join, while we still hold enough privilege to capset/setuid.
            if let Some(sec) = &sec {
                sec.apply()?;
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
    let sec = load_bundle_spec(&s.bundle).and_then(|spec| sec_downgrade_for(&spec));
    let (img_env, cwd) = container_env_cwd(&s.bundle);
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    apply_image_env(&mut cmd, &img_env); // image env base…
    for (k, v) in env {
        cmd.env(k, v); // …caller-injected vars override
    }
    enter_namespaces(&mut cmd, ns, open_cgroup_procs(&s.cgroup), sec, cwd);
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

    // A running container needs `--force` to delete. Once past that check, ALWAYS
    // clear the cgroup (best-effort `cgroup.kill`), not just when the recorded
    // init is alive: a force-delete must also reap any ORPHANED straggler still in
    // the cgroup — e.g. a process left behind by a crashed/restarted panel, or by
    // an earlier `delete` that raced — whose pid isn't the recorded init and which
    // would otherwise keep the cgroup non-removable (EBUSY) forever.
    if state::pid_alive(s.pid) && !force {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "delete (still alive; use --force)",
        });
    }
    let _ = cg.kill_all();
    // Wait for the cgroup to drain before the rmdir — even a container that was
    // `stop`ped first can reach here with its init still lingering as an unreaped
    // zombie (the panel reaps container inits ASYNCHRONOUSLY on a dedicated
    // thread), which keeps the cgroup non-removable for a beat and made an
    // edit/recreate (`stop`→`delete`→re-create) intermittently fail with EBUSY,
    // leaving the new resource limits unapplied. `Cgroup::delete` also retries the
    // rmdir as a final backstop.
    wait_drained(&cg);
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

/// Connect a RUNNING container to an ADDITIONAL network (docker `network
/// connect`): allocate a lease on `network`, wire a new veth as the next free
/// `ethN`, and record the attachment. Returns `(ip, ifname)`. Fail-closed: any
/// wiring error tears the partial attachment back down.
pub fn net_connect(id: &str, network: &str, static_ip: Option<&str>) -> Result<(String, String)> {
    use crate::net::{backend, config, ipam::Ipam, registry};
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "network connect",
        });
    }
    let pid = s.pid;
    let net = s
        .net
        .as_ref()
        .ok_or_else(|| Error::Other("container has no managed network".into()))?;
    if net.mode != "bridge" {
        return Err(Error::Other(
            "container is not on a bridge network; connect is not applicable".into(),
        ));
    }
    let cfg = registry::resolve(network).map_err(|e| Error::Other(e.to_string()))?;
    if net.network == cfg.name || net.extra.iter().any(|a| a.network == cfg.name) {
        return Err(Error::Other(format!(
            "container is already connected to network {}",
            cfg.name
        )));
    }
    let ifname = format!("eth{}", 1 + net.extra.len());
    let ipam = Ipam::new();
    let lease = match static_ip {
        Some(ip) => {
            let want: std::net::Ipv4Addr = ip
                .trim()
                .parse()
                .map_err(|_| Error::Other(format!("invalid ipv4: {ip}")))?;
            ipam.allocate_static(&cfg, id, pid, want)?
        }
        None => ipam.allocate(&cfg, id, pid)?,
    };
    let host = config::veth_host_name_for(id, &cfg.name);
    let peer = config::veth_peer_name_for(id, &cfg.name);
    let wire = (|| -> Result<()> {
        backend::ensure_bridge(&cfg)?;
        backend::make_veth(&host, &peer)?;
        backend::attach_to_bridge(&host, &cfg.bridge)?;
        backend::move_peer(&peer, pid)?;
        backend::config_attachment(
            pid,
            &peer,
            &ifname,
            lease.ip,
            cfg.subnet.prefix_len(),
            &lease.mac,
        )?;
        if crate::net::firewall::have_nft() {
            let _ = crate::net::firewall::ensure_base(&cfg);
        }
        Ok(())
    })();
    if let Err(e) = wire {
        let _ = backend::teardown_veth(&host);
        let _ = ipam.free(&cfg.name, id);
        return Err(e);
    }
    let att = config::Attachment {
        network: cfg.name.clone(),
        bridge: cfg.bridge.clone(),
        veth_host: host,
        ifname: ifname.clone(),
        ip: lease.ip,
        mac: lease.mac.clone(),
    };
    s.net.as_mut().unwrap().extra.push(att);
    s.save()?;
    Ok((lease.ip.to_string(), ifname))
}

/// Disconnect a container from a SECONDARY network (docker `network
/// disconnect`). The primary network can't be disconnected — remove the
/// container instead.
pub fn net_disconnect(id: &str, network: &str) -> Result<()> {
    use crate::net::{backend, ipam::Ipam, registry};
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    let cfg = registry::resolve(network).map_err(|e| Error::Other(e.to_string()))?;
    let net = s
        .net
        .as_mut()
        .ok_or_else(|| Error::Other("container has no managed network".into()))?;
    if net.network == cfg.name {
        return Err(Error::Other(
            "can't disconnect the container's primary network; remove the container instead".into(),
        ));
    }
    let pos = net
        .extra
        .iter()
        .position(|a| a.network == cfg.name)
        .ok_or_else(|| {
            Error::Other(format!(
                "container is not connected to network {}",
                cfg.name
            ))
        })?;
    let att = net.extra.remove(pos);
    let _ = backend::teardown_veth(&att.veth_host);
    let _ = Ipam::new().free(&cfg.name, id);
    s.save()
}

/// Change a container's IPv4 on a network (docker static-IP edit): reserve the
/// address in IPAM and reconfigure the live interface (primary `eth0` or a
/// secondary `ethN`). The container must be running.
pub fn net_set_ip(id: &str, network: &str, ipv4: &str) -> Result<()> {
    use crate::net::{backend, ipam::Ipam, registry};
    let _guard = State::lock(id)?;
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "set network ip",
        });
    }
    let pid = s.pid;
    let cfg = registry::resolve(network).map_err(|e| Error::Other(e.to_string()))?;
    let want: std::net::Ipv4Addr = ipv4
        .trim()
        .parse()
        .map_err(|_| Error::Other(format!("invalid ipv4: {ipv4}")))?;
    let lease = Ipam::new().allocate_static(&cfg, id, pid, want)?;
    let prefix = cfg.subnet.prefix_len();
    let net = s
        .net
        .as_mut()
        .ok_or_else(|| Error::Other("container has no managed network".into()))?;
    if net.network == cfg.name {
        backend::set_iface_ip(pid, "eth0", net.ip, want, prefix)?;
        net.ip = Some(want);
        net.mac = Some(lease.mac);
    } else if let Some(a) = net.extra.iter_mut().find(|a| a.network == cfg.name) {
        backend::set_iface_ip(pid, &a.ifname, Some(a.ip), want, prefix)?;
        a.ip = want;
        a.mac = lease.mac;
    } else {
        return Err(Error::Other(format!(
            "container is not connected to network {}",
            cfg.name
        )));
    }
    s.save()
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
    //
    // Re-exec via the `/proc/self/exe` MAGIC SYMLINK, not its `read_link` target:
    // the kernel resolves it to the running image's inode even after the on-disk
    // binary is replaced (a self-update renames a new binary over it) or deleted —
    // whereas `read_link` then yields "<path> (deleted)" and `execve` of that
    // literal string fails ENOENT, killing the init before the network is wired
    // and surfacing as a cryptic "move to netns failed: errno 3 (ESRCH)". So every
    // container create/start would break after any self-update until a restart.
    const SELF_EXE: &[u8] = b"/proc/self/exe";
    let (gate_arg, fifo_fd) = match ctx.gate {
        Gate::Immediate => ("immediate".to_string(), -1),
        Gate::Fifo(fd) => (fd.to_string(), fd),
    };
    let sync_rfd = ctx.sync_rfd;
    let log_fd = ctx.log_fd.unwrap_or(-1);

    let cstr = |b: Vec<u8>| CString::new(b).map_err(|_| Error::Other("argv has NUL".into()));
    let argv_owned: Vec<CString> = [
        SELF_EXE.to_vec(),
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
