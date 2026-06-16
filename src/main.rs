mod app;
mod contracts;
mod domain;
mod infra;
mod platform;
mod web;

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
    let role = std::env::args().nth(1);

    // CLI subcommands (version/reset/port/access/entry) short-circuit before any
    // install side effects.
    if let Some(result) = dispatch_subcommand(role.as_deref()) {
        return result;
    }

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
    // Install redundant boot autostart (systemd + cron@reboot + rc.local) so the
    // panel comes back after a reboot. Best-effort + idempotent.
    autostart::install_all();

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
            println!("{}", env!("CARGO_PKG_VERSION"));
            Some(Ok(()))
        }
        Some("reset") => Some(run_reset()),
        Some("port") => Some(run_set_port(std::env::args().nth(2))),
        Some("access") | Some("entry") => Some(run_set_entry(std::env::args().nth(2))),
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
         \x20 dn7-panel reset               reset the console account + password\n\
         \x20 dn7-panel port [N]            set the console port (random if omitted)\n\
         \x20 dn7-panel access [/path]      set the secret entry path (random if omitted)\n\
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
    tracing::info!(web_port = cfg.web_port, "panel role starting");
    panel::run(cfg).await
}

/// Reset the console account + password (subcommand `reset`). Restricted to the
/// OS user that first initialized the console, or root.
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
    let pw = web::reset_console()?;
    println!();
    println!("  DN7 Panel 账号密码已重置：");
    println!("    账号 username → admin");
    println!("    密码 password → {pw}");
    if let Some(url) = web::access_url(&banner::best_host()) {
        println!("    访问地址 url  → {url}");
    }
    println!("  （仅显示一次，请妥善保存；忘记可再次运行 dn7 panel reset）");
    println!();
    // Make a running instance pick up the new credentials: stop the panel-role
    // child so the supervisor respawns it (it reloads web.json on start).
    restart_panel_child();
    Ok(())
}

/// `dn7 panel port [N]` — set the console port (random high port when omitted).
fn run_set_port(arg: Option<String>) -> Result<()> {
    require_console_owner();
    let port = match arg.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => match s.parse::<u16>() {
            Ok(p) if p >= 1 => Some(p),
            _ => {
                eprintln!("端口无效：请输入 1-65535 之间的数字，或省略以随机生成。");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let new_port = web::console_port_set(port)?;
    println!();
    println!("  DN7 Panel 端口已更新 → {new_port}");
    if let Some(url) = web::access_url(&banner::best_host()) {
        println!("  新的访问地址 → {url}");
    }
    println!("  （需重启面板后生效，正在重启……）");
    println!();
    restart_panel_child();
    Ok(())
}

/// `dn7 panel access [/path]` — set the secret safe-entry path (random when
/// omitted). Takes effect immediately (no restart needed).
fn run_set_entry(arg: Option<String>) -> Result<()> {
    require_console_owner();
    let entry = web::console_entry_set(arg)?;
    println!();
    if entry == "/" {
        println!("  DN7 Panel 安全入口已关闭（登录页在根路径 / 可直接访问）。");
    } else {
        println!("  DN7 Panel 安全入口已更新 → {entry}");
    }
    if let Some(url) = web::access_url(&banner::best_host()) {
        println!("  新的访问地址 → {url}");
    }
    println!();
    restart_panel_child();
    Ok(())
}

/// Guard: only the install owner (or root) may run console-management commands.
fn require_console_owner() {
    let uid = current_uid();
    match web::console_owner_uid() {
        None => {
            eprintln!("控制台尚未初始化：请先启动一次 DN7 Panel。");
            std::process::exit(1);
        }
        Some(owner) if uid != 0 && uid != owner => {
            eprintln!("无权操作：请以初始安装用户(uid={owner})或 root 身份运行。当前 uid={uid}。");
            std::process::exit(1);
        }
        _ => {}
    }
}

/// The process's real uid (for the reset owner check).
fn current_uid() -> u32 {
    // SAFETY: getuid() just reads the process's real uid; always safe.
    unsafe { libc::getuid() }
}

/// Signal the running panel-role child to exit so the supervisor relaunches it
/// with the freshly-reset credentials. No-op when nothing is running.
fn restart_panel_child() {
    let cfg = PanelConfig::from_env();
    let panel = RolePaths::new(&cfg.runtime_dir, "panel");
    if let Some(pid) = procfile::read_pid(&panel.pid) {
        const SIGTERM: i32 = 15;
        procfile::signal_pid(pid, SIGTERM);
        println!("  已通知运行中的面板重启以应用新密码。");
    }
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
