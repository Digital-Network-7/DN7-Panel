//! Agent role: collect system metrics and report them to the backend.
//!
//! Run as `teaops-agent agent` (spawned by the supervisor role). It also guards
//! the supervisor: if the supervisor dies, the guardian relaunches it.

use std::time::Duration;

use anyhow::Result;

use crate::api::ApiClient;
use crate::config::AgentConfig;
use crate::metrics::Collector;
use crate::ws::{MetricsStream, ServerCommand};
use crate::{fetch, guardian, update};

/// Entry point for the agent role.
pub async fn run(cfg: AgentConfig) -> Result<()> {
    // Write our pid/heartbeat and start guarding the supervisor.
    guardian::write_own_pid(&cfg);
    guardian::spawn(cfg.clone());

    let client = ApiClient::new(&cfg);
    let mut collector = Collector::new();

    // Resolve the agent token: env override > token file > pairing flow.
    let agent_token = resolve_token(&cfg, &client, &mut collector).await?;
    tracing::info!("agent token acquired, entering report loop");

    let ws_url = cfg.agent_ws_url(&agent_token);
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    let mut stream: Option<MetricsStream> = None;

    // Periodic auto-update poll: every ~5 minutes, ask the backend whether
    // auto-update is on, and upgrade only when a newer version exists.
    let upgrade_check_every = std::cmp::max(1, 300 / cfg.interval_secs.max(1));
    let mut tick_count: u64 = 0;

    loop {
        interval.tick().await;
        tick_count = tick_count.wrapping_add(1);
        let snapshot = collector.collect();

        // Keep our heartbeat fresh so the supervisor knows we're alive.
        guardian::touch_own_heartbeat(&cfg);

        if tick_count % upgrade_check_every == 0 {
            if let Ok(info) = client.should_upgrade(&agent_token).await {
                if info.auto_update && upgrade_available(&cfg).await {
                    tracing::info!("auto-update enabled and newer version available; upgrading");
                    if let Err(e) = do_self_update(&cfg).await {
                        tracing::warn!("auto-update failed: {e}");
                    }
                }
            }
        }

        if stream.is_none() {
            match MetricsStream::connect(&ws_url, &agent_token).await {
                Ok(s) => {
                    tracing::info!(url = %ws_url, "metrics websocket connected");
                    stream = Some(s);
                }
                Err(e) => {
                    tracing::debug!("websocket connect failed ({e}); using HTTP this tick");
                }
            }
        }

        let mut sent = false;
        if let Some(s) = stream.as_mut() {
            match s.send(&snapshot).await {
                Ok(commands) => {
                    sent = true;
                    for cmd in commands {
                        match cmd {
                            ServerCommand::Upgrade => {
                                tracing::info!("received upgrade command");
                                if upgrade_available(&cfg).await {
                                    if let Err(e) = do_self_update(&cfg).await {
                                        tracing::warn!("upgrade failed: {e}");
                                    }
                                } else {
                                    tracing::info!("already on the latest version; ignoring upgrade");
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("websocket send failed ({e}); falling back to HTTP");
                    stream = None;
                }
            }
        }

        if !sent {
            match client.report(&agent_token, &snapshot).await {
                Ok(_) => sent = true,
                Err(e) => tracing::warn!("http report failed: {e}"),
            }
        }

        if sent {
            tracing::info!(
                via = if stream.is_some() { "ws" } else { "http" },
                cpu = format!("{:.1}%", snapshot.cpu_usage),
                mem = format!("{:.1}%", snapshot.memory_usage),
                disk = format!("{:.1}%", snapshot.disk_usage),
                uptime = snapshot.uptime,
                "metrics reported"
            );
        }
    }
}

/// True if an upgrade would move to a strictly newer version than ours.
async fn upgrade_available(cfg: &AgentConfig) -> bool {
    let current = env!("CARGO_PKG_VERSION");
    match fetch::latest_version(cfg).await {
        Ok(latest) => match (parse_semver(&latest), parse_semver(current)) {
            (Some(l), Some(c)) => l > c,
            _ => false,
        },
        Err(e) => {
            tracing::debug!("could not resolve latest version: {e}");
            false
        }
    }
}

fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

/// Fetch the latest binary, replace our own executable, and exit so the
/// supervisor relaunches us on the new version.
async fn do_self_update(cfg: &AgentConfig) -> Result<()> {
    update::self_update(cfg).await?;
    tracing::info!("upgrade complete; exiting for restart");
    std::process::exit(0);
}

/// Determine the agent token, performing the pairing flow if necessary.
async fn resolve_token(
    cfg: &AgentConfig,
    client: &ApiClient,
    collector: &mut Collector,
) -> Result<String> {
    // 1. Explicit token from environment.
    if let Some(token) = &cfg.agent_token {
        tracing::info!("using agent token from TEAOPS_AGENT_TOKEN env var");
        return Ok(token.clone());
    }

    // 2. Token persisted from a previous pairing.
    if let Ok(token) = std::fs::read_to_string(&cfg.token_file) {
        let token = token.trim().to_string();
        if !token.is_empty() {
            tracing::info!(file = ?cfg.token_file, "loaded agent token from file");
            return Ok(token);
        }
    }

    // 3. Pairing flow: register -> print 6-digit code -> poll until claimed.
    let snapshot = collector.collect();
    let reg = client.register(&snapshot).await?;

    println!("\n========================================");
    println!("  TeaOps Agent Pairing");
    println!("  Enter this code in the Mini Program:");
    println!("\n        >>>  {}  <<<\n", reg.pairing_code);
    println!("  (valid until {})", reg.expires_at);
    println!("========================================\n");
    tracing::info!(code = %reg.pairing_code, "waiting for pairing in mini program");

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match client.poll(&reg.register_secret).await {
            Ok(poll) => {
                if poll.claimed {
                    if let Some(token) = poll.agent_token {
                        if let Err(e) = std::fs::write(&cfg.token_file, &token) {
                            tracing::warn!("failed to persist token file: {e}");
                        }
                        tracing::info!("pairing claimed successfully");
                        return Ok(token);
                    }
                } else {
                    tracing::debug!("not claimed yet, still waiting...");
                }
            }
            Err(e) => {
                tracing::warn!("poll error: {e}");
            }
        }
    }
}
