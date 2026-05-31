mod agent;
mod api;
mod config;
mod fetch;
mod guardian;
mod metrics;
mod procfile;
mod supervisor;
mod terminal;
mod update;
mod ws;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::AgentConfig;

/// Single binary, two roles selected by argv:
///   - no args        => supervisor (keeps the agent role alive; self-splits)
///   - `agent`        => agent role (collects + reports metrics)
#[tokio::main]
async fn main() -> Result<()> {
    let role = std::env::args().nth(1);
    let is_agent = role.as_deref() == Some("agent");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if is_agent {
                    "info,teaops_agent=info".into()
                } else {
                    "info,teaops_agent=info".into()
                }
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = AgentConfig::from_env();

    if is_agent {
        tracing::info!(backend = %cfg.backend_url, interval = cfg.interval_secs, "agent role starting");
        agent::run(cfg).await
    } else {
        supervisor::run(cfg).await
    }
}
