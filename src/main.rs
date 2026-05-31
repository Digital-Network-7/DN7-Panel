mod agent;
mod api;
mod config;
mod daemon;
mod fetch;
mod file;
mod guardian;
mod metrics;
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
///   - no args  => supervisor (keeps the agent role alive; self-splits). On a
///                 normal launch it prints the pairing QR/code, then detaches
///                 to the background. Launching again while it's already running
///                 re-prints fresh pairing info instead of starting a duplicate.
///   - `agent`  => agent role (collects + reports metrics). Spawned by the
///                 supervisor with inherited stdio; never daemonizes itself.
fn main() -> Result<()> {
    let role = std::env::args().nth(1);
    let is_agent = role.as_deref() == Some("agent");

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

    // ---- Supervisor role: pairing pre-flight + background detach ----

    // Is a supervisor already running? Probe the role lock without holding it.
    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    let already_running = match procfile::try_lock(&me.lock)? {
        Some(_guard) => false, // we got the lock => none running (guard drops here)
        None => true,
    };

    if already_running {
        // Don't start a duplicate. Re-display pairing for the current server.
        // Prefer the claimed token; otherwise a not-yet-claimed pending token.
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
