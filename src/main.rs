mod agent;
mod api;
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
mod nginx;
mod pairing;
mod paths;
mod procfile;
mod supervisor;
mod terminal;
mod update;
mod ws;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AgentConfig;
use crate::procfile::RolePaths;

/// Single binary, two roles selected by argv:
/// - no args  => supervisor (keeps the agent role alive; self-splits). On a
///   normal launch it prints the pairing QR/code, then detaches to the
///   background. Launching again while it's already running re-prints fresh
///   pairing info instead of starting a duplicate.
/// - `agent`  => agent role (collects + reports metrics). Spawned by the
///   supervisor with inherited stdio; never daemonizes itself.
fn main() -> Result<()> {
    let role = std::env::args().nth(1);
    let is_agent = role.as_deref() == Some("agent");

    // `version` subcommand: print the compiled version and exit. Used by the
    // running supervisor to read the on-disk binary's version, so it can notice
    // a self-update replaced the binary with a newer build and re-exec itself
    // (otherwise the long-lived supervisor keeps running old code forever).
    if role.as_deref() == Some("version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // Migrate to the canonical install location (/var/ops/teaops-agent) on the
    // top-level (supervisor) launch, so the operator never has to create dirs
    // and every respawn/self-update uses a stable path. The agent role is an
    // internal child already launched from the canonical path, so skip it
    // there. On success this re-execs and never returns.
    if !is_agent {
        paths::ensure_installed();
    }

    let cfg = AgentConfig::from_env();

    // The agent role is an internal child of the supervisor: it inherits stdio
    // and must not daemonize or do pairing. Run it directly on a fresh runtime.
    if is_agent {
        return run_async(cfg, run_agent);
    }

    // Clean up any agent residue left in legacy locations (~, /, /root, cwd):
    // stop a stale old supervisor still running there (the usual cause of a
    // "heartbeat that won't delete") and remove its pid/heartbeat/lock/log,
    // migrating the token into /var/ops. Runs every launch, not just on the
    // first relocation.
    paths::cleanup_legacy_locations();

    // Install redundant boot autostart (systemd + cron@reboot + rc.local) so the
    // agent comes back after a reboot. Best-effort + idempotent; no-ops for an
    // unprivileged run. Done on the supervisor (top-level) launch only.
    autostart::install_all(&cfg.backend_url);

    // ---- Supervisor role: pairing pre-flight + background detach ----

    // Is a supervisor already running? Probe the role lock without holding it.
    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    let already_running = match procfile::try_lock(&me.lock)? {
        Some(_guard) => false, // we got the lock => none running (guard drops here)
        None => true,
    };

    if already_running {
        // Compare the running instance's version against ours. If we're a
        // strictly newer build, take over: kill the old pair and fall through
        // to a normal launch. Otherwise keep the old behavior — just re-display
        // pairing info for the current server and exit.
        let current = env!("CARGO_PKG_VERSION");
        let running = procfile::read_version(&cfg.runtime_dir);
        if is_newer(current, running.as_deref()) {
            println!(
                "检测到正在运行的 Agent 版本 {} 低于当前版本 {current}，正在替换为新版本……",
                running.as_deref().unwrap_or("未知")
            );
            supervisor::stop_running_instance(&cfg);
            // The old processes were running from /var/ops/teaops-agent, so the
            // very first ensure_installed() at the top of main couldn't copy the
            // new binary there (ETXTBSY — text file busy). Now that they're
            // dead, migrate the new binary into /var/ops and re-exec from the
            // canonical path so the supervisor self-splits the *new* version.
            // On success this never returns; on failure we keep running from
            // here and fall through to a normal launch below.
            paths::ensure_installed();
            // Fall through to the normal launch path below (the old supervisor
            // released its lock when killed, so we can acquire it).
        } else {
            // Don't start a duplicate. Re-display pairing for the current
            // server. Prefer the claimed token; otherwise a not-yet-claimed
            // pending token.
            let token = pairing::saved_token(&cfg)
                .or_else(|| pairing::read_pending(&cfg).map(|p| p.agent_token));
            match token {
                Some(token) => {
                    if let Err(e) = pairing::repair_and_print(&cfg, &token) {
                        eprintln!("重新生成配对信息失败：{e}");
                    }
                }
                None => {
                    println!(
                        "Agent 已在后台运行，但尚未完成配对。请查看最初启动时输出的二维码，\n或停止后台进程后重新启动以获取新的配对码。"
                    );
                }
            }
            return Ok(());
        }
    }

    // First/normal launch. Do the pairing print in the foreground (so the QR is
    // visible) BEFORE detaching: register if we have no token/pending yet,
    // otherwise we're already paired (or have a pending) and just start up.
    if pairing::saved_token(&cfg).is_none() && pairing::read_pending(&cfg).is_none() {
        if let Err(e) = pairing::register_and_print(&cfg) {
            eprintln!("配对注册失败：{e}（将继续启动并在后台重试）");
        }
    }

    // Detach to the background unless asked to stay in the foreground.
    if daemon::wants_foreground() {
        eprintln!("running in foreground");
    } else {
        let log = paths::default_base_dir().join(daemon::LOG_FILE);
        println!("Agent 正在后台运行，日志见 {}", log.display());
        daemon::daemonize()?;
    }

    run_async(cfg, run_supervisor)
}

/// True if `current` is a strictly newer semver than `running`. An unknown /
/// unparseable running version (e.g. an old agent that predates the version
/// file) is treated as older, so the first upgrade still takes over.
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
fn run_async<F, Fut>(cfg: AgentConfig, f: F) -> Result<()>
where
    F: FnOnce(AgentConfig) -> Fut,
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
                .unwrap_or_else(|_| "info,teaops_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn run_agent(cfg: AgentConfig) -> Result<()> {
    tracing::info!(backend = %cfg.backend_url, interval = cfg.interval_secs, "agent role starting");
    agent::run(cfg).await
}

async fn run_supervisor(cfg: AgentConfig) -> Result<()> {
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
        assert!(!is_newer("1.0.9", Some("1.0.9"))); // equal => keep old
        assert!(!is_newer("1.0.8", Some("1.0.9"))); // older => keep old
    }

    #[test]
    fn unknown_running_version_is_replaced() {
        // An old agent that predates the version file => treat ours as newer.
        assert!(is_newer("1.0.1", None));
        assert!(is_newer("1.0.1", Some("")));
        assert!(is_newer("1.0.1", Some("garbage")));
    }

    #[test]
    fn unparseable_current_does_not_take_over() {
        // If we can't parse our own version, be conservative and don't replace.
        assert!(!is_newer("not-a-version", Some("1.0.1")));
    }
}
