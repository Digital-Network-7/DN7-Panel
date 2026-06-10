mod autostart;
mod config;
mod crypto;
mod daemon;
mod docker;
mod fetch;
mod file;
mod guardian;
mod logrotate;
mod metrics;
mod mysql;
mod nginx;
mod panel;
mod paths;
mod procfile;
mod procs;
mod signing;
mod supervisor;
mod terminal;
mod update;
mod web;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::PanelConfig;
use crate::procfile::RolePaths;

/// Single binary, two roles selected by argv:
/// - no args  => supervisor (keeps the panel role alive; self-splits). On a
///   normal launch it prints the local console address, then detaches to the
///   background. Launching again while it's already running re-prints the
///   console info instead of starting a duplicate.
/// - `panel`  => panel role (runs the web console). Spawned by the supervisor
///   with inherited stdio; never daemonizes itself.
fn main() -> Result<()> {
    let role = std::env::args().nth(1);
    let is_panel = role.as_deref() == Some("panel");

    // `version` subcommand: print the compiled version and exit. Used by the
    // running supervisor to read the on-disk binary's version, so it can notice
    // a self-update replaced the binary with a newer build and re-exec itself.
    if role.as_deref() == Some("version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Migrate to the canonical install location (/var/ops/dn7-panel) on the
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

    // Clean up any residue left in legacy locations and group the /var/ops
    // files into data/run/log subdirs. Idempotent.
    paths::cleanup_legacy_locations();
    paths::ensure_dirs();
    paths::migrate_flat_layout();

    // Install redundant boot autostart (systemd + cron@reboot + rc.local) so the
    // panel comes back after a reboot. Best-effort + idempotent.
    autostart::install_all();

    // ---- Supervisor role: single-instance guard + background detach ----

    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    let already_running = match procfile::try_lock(&me.lock)? {
        Some(_guard) => false, // we got the lock => none running (guard drops here)
        None => true,
    };

    if already_running {
        // Take over only if we're a strictly newer build; otherwise just report
        // that it's already running and exit.
        let current = env!("CARGO_PKG_VERSION");
        let running = procfile::read_version(&cfg.data_dir);
        if is_newer(current, running.as_deref()) {
            println!(
                "检测到正在运行的 DN7 Panel 版本 {} 低于当前版本 {current}，正在替换为新版本……",
                running.as_deref().unwrap_or("未知")
            );
            supervisor::stop_running_instance(&cfg);
            paths::ensure_installed();
            // Fall through to a normal launch (old supervisor released its lock).
        } else {
            println!(
                "DN7 Panel 已在后台运行（本机控制台默认端口 1080）。\n如需修改端口或账号密码，请在控制台「设置」中调整。"
            );
            return Ok(());
        }
    }

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
