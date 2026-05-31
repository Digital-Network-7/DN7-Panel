//! Supervisor role (the former teaops-agentd).
//!
//! Runs as the default (no-arg) role. It keeps the agent role alive by spawning
//! *itself* with the `agent` subcommand (self-split via `current_exe`) and
//! restarting it on exit. The agent role reciprocally guards the supervisor
//! (see `guardian`), so either half can resurrect the other.
//!
//! Because both roles are the same binary, a self-update replaces one file and
//! both halves come back upgraded.

use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use tokio::process::{Child, Command};

use crate::config::AgentConfig;
use crate::procfile::{role_alive, try_lock, write_heartbeat, write_pid, RolePaths};

/// Entry point for the supervisor role.
pub async fn run(cfg: AgentConfig) -> Result<()> {
    std::fs::create_dir_all(&cfg.runtime_dir).ok();

    let me = RolePaths::new(&cfg.runtime_dir, "supervisor");
    let agent = RolePaths::new(&cfg.runtime_dir, "agent");

    // Single-instance guard: hold the supervisor lock for our whole lifetime.
    let _lock = match try_lock(&me.lock)? {
        Some(g) => g,
        None => {
            tracing::info!("another supervisor is already running; exiting");
            return Ok(());
        }
    };
    write_pid(&me.pid)?;
    write_heartbeat(&me.heartbeat)?;
    tracing::info!(pid = std::process::id(), "supervisor started");

    // Heartbeat task: keep our heartbeat fresh so the agent's guardian sees us.
    {
        let hb = me.heartbeat.clone();
        let interval = cfg.supervise_interval_secs.max(1);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                let _ = write_heartbeat(&hb);
            }
        });
    }

    let mut child: Option<Child> = None;
    let mut shutdown = signal_stream()?;

    // If an agent is already alive (e.g. started by hand or by a previous
    // supervisor), adopt it: monitor until it dies instead of spawning a dup.
    if role_alive(&agent, cfg.heartbeat_timeout_secs) {
        tracing::info!("found a live agent on startup; adopting (monitor-only)");
        tokio::select! {
            _ = wait_until_agent_dead(&agent, &cfg) => {}
            _ = shutdown.recv() => {
                tracing::info!("shutdown signal received");
                return Ok(());
            }
        }
    }

    loop {
        if child.is_none() {
            match spawn_agent() {
                Ok(c) => {
                    tracing::info!(pid = c.id(), "spawned agent role");
                    child = Some(c);
                }
                Err(e) => {
                    tracing::error!("failed to spawn agent: {e}");
                    tokio::time::sleep(Duration::from_secs(cfg.restart_backoff_secs.max(1))).await;
                    continue;
                }
            }
        }

        let c = child.as_mut().unwrap();
        tokio::select! {
            status = c.wait() => {
                match status {
                    Ok(s) => tracing::warn!("agent exited with {s}; restarting"),
                    Err(e) => tracing::warn!("agent wait error: {e}; restarting"),
                }
                child = None;
                tokio::time::sleep(Duration::from_secs(cfg.restart_backoff_secs)).await;
            }
            _ = shutdown.recv() => {
                tracing::info!("shutdown signal received; terminating agent");
                let _ = c.start_kill();
                let _ = c.wait().await;
                break;
            }
        }
    }

    Ok(())
}

/// Spawn the agent role by re-executing *this* binary with the `agent`
/// subcommand (the "self-split"). Stdio is inherited so the agent's logs show.
fn spawn_agent() -> Result<Child> {
    let exe = std::env::current_exe()?;
    let child = Command::new(exe)
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(false)
        .spawn()?;
    Ok(child)
}

/// Poll until the (adopted) agent is no longer alive.
async fn wait_until_agent_dead(agent: &RolePaths, cfg: &AgentConfig) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.supervise_interval_secs.max(1)));
    loop {
        ticker.tick().await;
        if !role_alive(agent, cfg.heartbeat_timeout_secs) {
            tracing::warn!("adopted agent is no longer alive");
            return;
        }
    }
}

/// Combined SIGTERM/SIGINT receiver.
fn signal_stream() -> Result<tokio::sync::mpsc::Receiver<()>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::spawn(async move {
        loop {
            let send: Result<(), _> = tokio::select! {
                _ = term.recv() => tx.send(()).await,
                _ = int.recv() => tx.send(()).await,
            };
            if send.is_err() {
                break;
            }
        }
    });
    Ok(rx)
}
