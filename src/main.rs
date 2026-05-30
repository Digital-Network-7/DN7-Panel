mod api;
mod config;
mod metrics;

use std::time::Duration;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api::ApiClient;
use crate::config::AgentConfig;
use crate::metrics::Collector;

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

    // Main metrics loop.
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    loop {
        interval.tick().await;
        let snapshot = collector.collect();
        match client.report(&agent_token, &snapshot).await {
            Ok(_) => {
                tracing::info!(
                    cpu = format!("{:.1}%", snapshot.cpu_usage),
                    mem = format!("{:.1}%", snapshot.memory_usage),
                    disk = format!("{:.1}%", snapshot.disk_usage),
                    uptime = snapshot.uptime,
                    "metrics reported"
                );
            }
            Err(e) => {
                tracing::warn!("report failed: {e}");
            }
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
