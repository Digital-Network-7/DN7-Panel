mod app;
mod contracts;
mod core;
mod infra;
mod platform;
mod web;

/// Test-only shared lock serializing every test that mutates the process-global
/// `DN7_RUNTIME_DIR` env var. Those tests live in three modules (settings /
/// docker backups / files controller); a single crate-wide lock is the only way
/// they can mutually exclude. Per-module locks (the previous state) let, say, a
/// settings test and a backups test flip the env var out from under each other
/// mid-run — a rare-but-real gate flake. Held via `.blocking_lock()` from sync
/// `#[test]`s and `.lock().await` from `#[tokio::test]`s.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::LazyLock;
    use tokio::sync::Mutex;

    pub(crate) static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
}

use platform::{autostart, banner, daemon, panel, paths, procfile, supervisor};

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::platform::config::PanelConfig;
use crate::platform::procfile::RolePaths;

/// Single binary, two roles selected by argv:
/// - no args  => supervisor (keeps the panel role alive; self-splits). On a
///   normal launch it prints the local console address, then detaches to the
///   background. Launching again while it's already running re-prints the
///   console info instead of starting a duplicate.
/// - `panel`  => panel role (runs the web console). Spawned by the supervisor
///   with inherited stdio; never daemonizes itself.
fn main() -> Result<()> {
    // If we were re-exec'd as a container init (`__dn7init ...` from the dn7
    // runtime's spawn_init), run it and never return — this MUST happen before
    // any thread / async runtime starts, so the init runs in a pristine
    // single-threaded process image.
    dn7_container::container::reexec::run_init_if_invoked();

    // Privilege-dropping file helper (the pure-Rust replacement for `su`): the
    // panel re-execs itself as `__fshelper <op> <user> <path>` to run a single
    // file operation as a target user. Must short-circuit before ANY setup
    // (no logging / install / async runtime) — it just drops privileges + acts.
    if std::env::args().nth(1).as_deref() == Some("__fshelper") {
        std::process::exit(crate::infra::file::run_fs_helper_main());
    }
    // Same re-exec pattern for the web terminal: `__webshell <user>` drops to the
    // mapped system user in a fresh single-threaded process, then execs their
    // login shell — the pure-Rust replacement for `su - <user>`.
    if std::env::args().nth(1).as_deref() == Some("__webshell") {
        std::process::exit(crate::infra::file::run_web_shell_main());
    }

    // Unified-CLI multiplexing by argv[0] basename: one binary serves the panel,
    // the `dn7` CLI (via the `/usr/local/bin/dn7` symlink), and `dn7crun`. So the
    // CLI links in (crate dn7-cli) rather than shipping a second binary.
    let prog = std::env::args()
        .next()
        .and_then(|a0| {
            std::path::Path::new(&a0)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    if prog == "dn7" {
        let args: Vec<String> = std::env::args().skip(1).collect();
        // `dn7 version` reports the PRODUCT version (this binary), not the CLI
        // crate's, so it tracks the release-stamped version.
        if matches!(
            args.first().map(String::as_str),
            Some("version") | Some("-V") | Some("--version")
        ) {
            // "<version> (build <N>)" — the version stays the first token so the
            // self-updater's anti-rollback gate can parse (version, build).
            println!(
                "{} (build {})",
                env!("CARGO_PKG_VERSION"),
                option_env!("DN7_BUILD").unwrap_or("0")
            );
            return Ok(());
        }
        std::process::exit(dn7_cli::run(&args));
    }
    #[cfg(target_os = "linux")]
    if prog == "dn7crun" {
        let args: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(match dn7_container::cli::run(&args) {
            Ok(code) => code,
            Err(msg) => {
                eprintln!("dn7crun: {msg}");
                1
            }
        });
    }

    let role = std::env::args().nth(1);

    // CLI subcommands (version/reset/port/access/entry) short-circuit before any
    // install side effects.
    if let Some(result) = dispatch_subcommand(role.as_deref()) {
        return result;
    }

    // Serving the console, binding :80/:443, and host management (accounts,
    // containers, firewall) all require root. Resolve privilege up front: a
    // non-root interactive launch re-execs under sudo (prompting for the
    // password); a non-root launch with no TTY/sudo aborts loudly here. This
    // stops a half-working non-root panel that only fails later when the operator
    // starts the web server. Utility subcommands already short-circuited above,
    // so only the serving/install launch is escalated. Once we return, we're root
    // (or on the sudo path we never return — the re-run comes back in as root).
    platform::privilege::ensure_root_or_reexec()?;

    let is_panel = role.as_deref() == Some("panel");

    // Install to the canonical location (/var/dn7/panel/dn7-panel) on the
    // top-level (supervisor) launch, so the operator never has to create dirs
    // and every respawn/self-update uses a stable path. The panel role is an
    // internal child already launched from the canonical path, so skip it
    // there. On success this re-execs and never returns.
    if !is_panel {
        paths::ensure_installed();
    }

    let cfg = PanelConfig::from_env();

    // The panel role is an internal child of the supervisor: it inherits stdio
    // and must not daemonize. Run it directly on a fresh runtime.
    if is_panel {
        return run_async(cfg, run_panel);
    }

    // Ensure the grouped data/run/log subdirs exist under the install dir.
    paths::ensure_dirs();
    // Install the global `dn7` CLI dispatcher (best-effort; needs root).
    paths::install_global_cli();

    // First-run setup: while UNINITIALIZED, run the interactive CLI wizard here
    // in the TTY-attached top-level process. It hard-exits (via `?`) if a
    // prerequisite is missing, the operator declines the mandatory :80/:443
    // takeover, or there's no TTY — so we never serve a half-configured panel,
    // and (running before `install_all`) an aborted setup leaves no reboot loop.
    // Runs BEFORE the single-instance guard: on a fresh init we hand off to the
    // service manager and exit, so we must not be holding the instance lock.
    // A dedicated one-off runtime (not `run_async`, which would double-init
    // tracing). Returns `true` on a fresh init.
    let did_init = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(crate::platform::init_cli::run_if_needed(&cfg))?
    };

    // Install redundant boot autostart (systemd unit + symlink / cron@reboot /
    // rc.local) so the panel comes back after a reboot. Best-effort + idempotent.
    autostart::install_all();

    // Fresh init: register + START the panel via the host service manager
    // (systemd/service), print the management commands + the login summary (address
    // / admin / password), then EXIT — the service now runs the panel (so
    // `systemctl status` is truthful + no double instance).
    if let Some(login) = &did_init {
        crate::platform::init_cli::register_and_start_service();
        crate::platform::init_cli::print_login_summary(login);
        return Ok(());
    }

    // Single-instance guard (with newer-build takeover). Exit early if another
    // instance is already running and we're not replacing it.
    if !ensure_single_instance(&cfg)? {
        return Ok(());
    }

    // Show the console address + credentials to the operator's terminal before
    // we detach (so it's never persisted to a log/script).
    banner::print(&cfg);

    // Detach to the background unless asked to stay in the foreground.
    if daemon::wants_foreground() {
        eprintln!("running in foreground");
    } else {
        let log = paths::log_dir().join(daemon::LOG_FILE);
        println!("DN7 Panel 正在后台运行，日志见 {}", log.display());
        daemon::daemonize()?;
    }

    run_async(cfg, run_supervisor)
}

/// Handle the one-shot CLI subcommands. Returns `Some(result)` when `role` was a
/// subcommand (the caller should return it), or `None` to proceed with a normal
/// panel/supervisor launch.
///
/// - `version`: print the compiled version (the running supervisor reads this
///   off the on-disk binary to detect a self-update and re-exec itself).
/// - `reset`: reset the console account + password to a fresh default (root /
///   the initializing OS user only).
/// - `port` / `access`|`entry`: change the console port / secret entry path.
/// - `help`/`-h`/`--help`: print usage.
///
/// An *unrecognized* leading argument prints usage and exits non-zero rather
/// than falling through to a full supervisor launch (which would install the
/// binary, write autostart units, and daemonize) — so a typo like
/// `dn7-panel statuss` can't silently perform a root install.
fn dispatch_subcommand(role: Option<&str>) -> Option<Result<()>> {
    match role {
        // No arg or a foreground flag → real supervisor launch (handled by main).
        None | Some("-f") | Some("--foreground") | Some("panel") => None,
        Some("version") => {
            // "<version> (build <N>)" — version first so the self-updater's
            // anti-rollback gate (read_binary_release) can parse (version, build).
            println!(
                "{} (build {})",
                env!("CARGO_PKG_VERSION"),
                option_env!("DN7_BUILD").unwrap_or("0")
            );
            Some(Ok(()))
        }
        Some("reset") => Some(run_reset()),
        Some("help") | Some("-h") | Some("--help") => {
            print_usage();
            Some(Ok(()))
        }
        Some(other) => {
            eprintln!("dn7-panel: unknown command '{other}'\n");
            print_usage();
            Some(Err(anyhow::anyhow!("unknown command")))
        }
    }
}

/// Print the CLI usage summary (the recognized subcommands).
fn print_usage() {
    println!(
        "DN7 Panel — on-box management console\n\n\
         Usage:\n\
         \x20 dn7-panel [--foreground|-f]   start the panel (detaches unless -f)\n\
         \x20 dn7-panel version             print the version\n\
         \x20 dn7-panel reset               reset to uninitialized (re-arms the init token)\n\
         \x20 dn7-panel help                show this help"
    );
}

/// Acquire the supervisor single-instance lock. Returns `Ok(true)` to proceed
/// with launch. When another instance already holds the lock, take over only if
/// we're a strictly newer build (replacing it, returns `Ok(true)`); otherwise
/// print the running banner and return `Ok(false)` so the caller exits.
fn ensure_single_instance(cfg: &PanelConfig) -> Result<bool> {
    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    // We got the lock => none running (the guard drops here, freeing it for the
    // real supervisor launch below).
    let already_running = procfile::try_lock(&me.lock)?.is_none();
    if !already_running {
        return Ok(true);
    }
    let current = env!("CARGO_PKG_VERSION");
    let running = procfile::read_version(&cfg.data_dir);
    if is_newer(current, running.as_deref()) {
        println!(
            "检测到正在运行的 DN7 Panel 版本 {} 低于当前版本 {current}，正在替换为新版本……",
            running.as_deref().unwrap_or("未知")
        );
        supervisor::stop_running_instance(cfg);
        paths::ensure_installed();
        Ok(true)
    } else {
        banner::print(cfg);
        println!("  DN7 Panel 已在后台运行。修改端口或账号密码请在控制台「设置」中调整。");
        Ok(false)
    }
}

/// True if `current` is a strictly newer semver than `running`. An unknown /
/// unparseable running version is treated as older, so the first upgrade still
/// takes over.
fn is_newer(current: &str, running: Option<&str>) -> bool {
    let cur = match parse_semver(current) {
        Some(v) => v,
        None => return false, // can't reason about our own version — don't take over
    };
    match running.and_then(parse_semver) {
        Some(run) => cur > run,
        None => true, // unknown running version => treat ours as newer
    }
}

/// Parse a `major.minor.patch` (leading `v` allowed; missing patch => 0).
fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

/// Build a fresh multi-threaded runtime (after any fork) and run `f`.
fn run_async<F, Fut>(cfg: PanelConfig, f: F) -> Result<()>
where
    F: FnOnce(PanelConfig) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    init_tracing();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(f(cfg))
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,dn7_panel=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn run_panel(cfg: PanelConfig) -> Result<()> {
    // Never serve while UNINITIALIZED. First-run setup runs via the CLI wizard in
    // the TTY-attached top-level process (platform::init_cli), never here — the
    // panel role can only reach this point uninitialized after `dn7-panel reset`
    // clears the account. If we served anyway the entry gate would 404 every
    // request (gate.rs) — a silently-bricked console. Instead fail loudly and
    // exit non-zero so the service shows failed and the journal tells the operator
    // exactly how to re-initialize, rather than respawning a 404-serving role.
    if !web::console_info(cfg.web_port).initialized {
        tracing::error!(
            "DN7 面板尚未初始化，拒绝以未初始化状态提供服务 — 请在终端中运行 `dn7-panel` 重新初始化。 \
             DN7 Panel is UNINITIALIZED; refusing to serve. Run `dn7-panel` in a terminal to re-initialize."
        );
        return Err(anyhow::anyhow!(
            "panel is uninitialized — run `dn7-panel` in a terminal to initialize"
        ));
    }
    tracing::info!(web_port = cfg.web_port, "panel role starting");
    // Restart-policy boot reconcile: bring back containers whose policy
    // (always / unless-stopped) asks for it after a panel/host restart, like
    // Docker's daemon. Off the serving path (spawn_blocking) so it never delays
    // the web server; best-effort.
    #[cfg(target_os = "linux")]
    tokio::task::spawn_blocking(|| {
        // Embedded DNS responders for every network (container-name resolution).
        dn7_container::net::dns_server::ensure_all();
        // Reap any orphaned (empty, stateless) container cgroups left by a race.
        dn7_container::container::reclaim_orphan_cgroups();
        // Virtualized /proc/meminfo (LXCFS-style) so free/top inside a container
        // see its cgroup memory limit, not host RAM. Best-effort: on failure,
        // containers keep the host meminfo. Started before reconcile so
        // boot-recovered containers can bind it.
        if dn7_container::sys::meminfo::ensure_started() {
            tracing::info!("meminfo-fs: virtualized /proc/meminfo mounted");
        } else {
            tracing::warn!("meminfo-fs: unavailable — containers see host /proc/meminfo");
        }
        let n = dn7_container::container::reconcile_restart_policies();
        if n > 0 {
            tracing::info!(
                restarted = n,
                "restart-policy: recovered containers at boot"
            );
        }
    });
    panel::run(cfg).await
}

/// Reset to the uninitialized state (subcommand `reset`): clears the account +
/// credentials, so the next launch re-runs the first-run CLI wizard. Restricted
/// to the OS user that first initialized the console, or root.
///
/// There is no web init token any more (first-run setup is CLI-only), so we must
/// NOT leave a running panel behind: a serving-but-uninitialized panel 404s every
/// request (the entry gate refuses to expose anything pre-init). Instead we STOP
/// the running instance and tell the operator to re-run `dn7-panel` in a terminal.
fn run_reset() -> Result<()> {
    let uid = current_uid();
    match web::console_owner_uid() {
        None => {
            eprintln!("控制台尚未初始化：请先启动一次 DN7 Panel 再重置。");
            std::process::exit(1);
        }
        Some(owner) if uid != 0 && uid != owner => {
            eprintln!("无权重置：请以初始安装用户(uid={owner})或 root 身份运行。当前 uid={uid}。");
            std::process::exit(1);
        }
        _ => {}
    }
    // `reset()` returns an empty string now (the web init token is gone); ignore
    // it and never print a bogus "new token".
    let _ = web::reset_console()?;
    // Bring the running panel down rather than leaving a role that would only serve
    // 404s while uninitialized. When systemd-managed, STOP THE SERVICE (systemctl)
    // so `Restart=always` doesn't immediately respawn an uninitialized role into a
    // restart loop; otherwise signal the running process directly.
    if std::path::Path::new("/etc/systemd/system/dn7-panel.service").exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "dn7-panel"])
            .status();
    } else {
        supervisor::stop_running_instance(&PanelConfig::from_env());
    }
    println!();
    println!("  DN7 Panel 已重置为未初始化状态，正在运行的面板已停止。");
    println!("  请在终端中前台运行 `dn7-panel` 以重新初始化（交互式向导）。");
    println!();
    println!(
        "  DN7 Panel has been reset to the uninitialized state; the running panel was stopped."
    );
    println!("  Run `dn7-panel` in a foreground terminal to re-initialize (interactive wizard).");
    println!();
    Ok(())
}

/// The process's real uid (for the reset owner check).
fn current_uid() -> u32 {
    // SAFETY: getuid() just reads the process's real uid; always safe.
    unsafe { libc::getuid() }
}

async fn run_supervisor(cfg: PanelConfig) -> Result<()> {
    supervisor::run(cfg).await
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn newer_version_takes_over() {
        assert!(is_newer("1.0.10", Some("1.0.9")));
        assert!(is_newer("1.1.0", Some("1.0.99")));
        assert!(is_newer("2.0.0", Some("1.9.9")));
    }

    #[test]
    fn same_or_older_keeps_old() {
        assert!(!is_newer("1.0.9", Some("1.0.9")));
        assert!(!is_newer("1.0.8", Some("1.0.9")));
    }

    #[test]
    fn unknown_running_version_is_replaced() {
        assert!(is_newer("1.0.1", None));
        assert!(is_newer("1.0.1", Some("")));
        assert!(is_newer("1.0.1", Some("garbage")));
    }

    #[test]
    fn unparseable_current_does_not_take_over() {
        assert!(!is_newer("not-a-version", Some("1.0.1")));
    }
}
