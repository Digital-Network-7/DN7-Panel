mod api;
mod config;
mod metrics;
mod update;
mod ws;

use std::time::Duration;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api::ApiClient;
use crate::config::AgentConfig;
use crate::metrics::Collector;
use crate::ws::{MetricsStream, ServerCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,teaops_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = AgentConfig::from_env();
    tracing::info!(backend = %cfg.backend_url, interval = cfg.interval_secs, "TeaOps agent starting");

    let client = ApiClient::new(&cfg);
    let mut collector = Collector::new();

    // Resolve the agent token: env override > token file > pairing flow.
    let agent_token = resolve_token(&cfg, &client, &mut collector).await?;
    tracing::info!("agent token acquired, entering report loop");

    // Main metrics loop: prefer the WebSocket stream, fall back to HTTP.
    let ws_url = cfg.agent_ws_url();
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    let mut stream: Option<MetricsStream> = None;

    loop {
        interval.tick().await;
        let snapshot = collector.collect();

        // (Re)connect the WebSocket if needed.
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

        // Try the WebSocket first; on any error drop it and fall back to HTTP.
        let mut sent = false;
        if let Some(s) = stream.as_mut() {
            match s.send(&snapshot).await {
                Ok(commands) => {
                    sent = true;
                    // Handle any backend-pushed commands (e.g. self-update).
                    for cmd in commands {
                        match cmd {
                            ServerCommand::Upgrade { download_url } => {
                                tracing::info!("received upgrade command");
                                match update::self_replace(&download_url).await {
                                    Ok(_) => {
                                        tracing::info!("upgrade complete; exiting for restart");
                                        // Exit cleanly; systemd relaunches the new binary.
                                        std::process::exit(0);
                                    }
                                    Err(e) => tracing::warn!("upgrade failed: {e}"),
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

    // Poll every 5 seconds until claimed.
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match client.poll(&reg.register_secret).await {
            Ok(poll) => {
                if poll.claimed {
                    if let Some(token) = poll.agent_token {
                        // Persist for future restarts.
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
