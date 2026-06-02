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
    // Record the running version so a later foreground launch can decide whether
    // it's newer (and should replace us) or not (and should just re-pair).
    crate::procfile::write_version(&cfg.data_dir);
    guardian::spawn(cfg.clone());

    let client = ApiClient::new(&cfg);
    let mut collector = Collector::new();

    // Resolve the agent token: env override > token file > pairing flow.
    let agent_token = resolve_token(&cfg, &client, &mut collector).await?;
    tracing::info!("agent token acquired, entering report loop");

    let ws_url = cfg.agent_ws_url();
    let mut interval = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    // Don't burst-catch-up missed ticks: if a send stalls (slow network, an
    // in-flight update saturating the link), we want to resume at the normal
    // cadence afterwards, not fire a backlog of ticks back-to-back (which made
    // the UI jump and skewed the stored history with a clump of same-timestamp
    // samples).
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Bound how long a single report waits for the backend ack before we treat
    // the socket as stalled and reconnect. At least 5s, otherwise ~2 intervals.
    let ack_timeout = Duration::from_secs((cfg.interval_secs.saturating_mul(2)).max(5));
    let mut stream: Option<MetricsStream> = None;

    // Private-network overlay state (one active membership at a time). The
    // backend pushes a `pnet` command to bring it up / change it / tear it down.
    let pnet_state = crate::pnet::PnetState::new();

    // Auto-update polling runs in its OWN task, not inline in the metrics loop.
    // The upgrade check does blocking network I/O (should_upgrade up to 15s,
    // resolving the latest version up to its own timeout) and, when it fires,
    // a download — none of which should stall metrics reporting. Decoupling it
    // keeps the report cadence steady regardless of update activity (this was a
    // source of the "updates interfere with reporting/other functions" feel).
    spawn_upgrade_poller(cfg.clone(), client.clone(), agent_token.clone());

    // Per-process traffic accounting runs in its own task on a slower cadence
    // (scanning /proc + a netlink dump every second would be wasteful and isn't
    // needed for Top-N rankings). It's fully decoupled from the metrics loop so
    // it can never stall reporting.
    spawn_traffic_reporter(client.clone(), agent_token.clone());

    loop {
        interval.tick().await;
        let snapshot = collector.collect();

        // Keep our heartbeat fresh so the supervisor knows we're alive.
        guardian::touch_own_heartbeat(&cfg);

        if stream.is_none() {
            match tokio::time::timeout(ack_timeout, MetricsStream::connect(&ws_url, &agent_token))
                .await
            {
                Ok(Ok(s)) => {
                    tracing::info!(url = %ws_url, "metrics websocket connected");
                    stream = Some(s);
                }
                Ok(Err(e)) => {
                    tracing::debug!("websocket connect failed ({e}); using HTTP this tick");
                }
                Err(_) => {
                    tracing::debug!("websocket connect timed out; using HTTP this tick");
                }
            }
        }

        let mut sent = false;
        if let Some(s) = stream.as_mut() {
            match s.send(&snapshot, ack_timeout).await {
                Ok(commands) => {
                    sent = true;
                    for cmd in commands {
                        match cmd {
                            ServerCommand::Upgrade => {
                                tracing::info!("received upgrade command");
                                if upgrade_available(&cfg).await {
                                    spawn_self_update(&cfg);
                                } else {
                                    tracing::info!(
                                        "already on the latest version; ignoring upgrade"
                                    );
                                }
                            }
                            ServerCommand::OpenTerminal(session) => {
                                tracing::info!(%session, "received open-terminal command");
                                // Relay a local PTY shell back to the backend in
                                // its own task so the metrics loop keeps running.
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        crate::terminal::run_terminal(&cfg_t, &token_t, &session)
                                            .await
                                    {
                                        tracing::warn!(%session, "terminal relay ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::OpenContainerExec { session, container } => {
                                tracing::info!(%session, %container, "received open-container-exec command");
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = crate::terminal::run_container_exec(
                                        &cfg_t, &token_t, &session, &container,
                                    )
                                    .await
                                    {
                                        tracing::warn!(%session, "container exec relay ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::OpenFile(session) => {
                                tracing::info!(%session, "received open-file command");
                                // Relay a file-transfer channel in its own task.
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        crate::file::run_file_channel(&cfg_t, &token_t, &session)
                                            .await
                                    {
                                        tracing::warn!(%session, "file relay ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::OpenContainerFile { session, container } => {
                                tracing::info!(%session, %container, "received open-container-file command");
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = crate::file::run_container_file_channel(
                                        &cfg_t, &token_t, &session, &container,
                                    )
                                    .await
                                    {
                                        tracing::warn!(%session, "container file relay ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::OpenDocker(session) => {
                                tracing::info!(%session, "received open-docker command");
                                // Serve the Docker management channel in its own
                                // task so the metrics loop keeps running.
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = crate::docker::run_docker_channel(
                                        &cfg_t, &token_t, &session,
                                    )
                                    .await
                                    {
                                        tracing::warn!(%session, "docker channel ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::OpenNginx(session) => {
                                tracing::info!(%session, "received open-nginx command");
                                let cfg_t = cfg.clone();
                                let token_t = agent_token.clone();
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        crate::nginx::run_nginx_channel(&cfg_t, &token_t, &session)
                                            .await
                                    {
                                        tracing::warn!(%session, "nginx channel ended: {e}");
                                    }
                                });
                            }
                            ServerCommand::Pnet { ip, prefix, gone } => {
                                tracing::info!(%ip, prefix, gone, "received pnet command");
                                crate::pnet::apply(
                                    &pnet_state,
                                    &cfg,
                                    &agent_token,
                                    ip,
                                    prefix,
                                    gone,
                                )
                                .await;
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

/// Spawn the per-process traffic reporter as an independent task. Every minute
/// it samples per-process byte deltas (via the platform `TrafficMonitor`) and
/// POSTs the heaviest contributors to the backend, which keeps windowed Top-N
/// rankings. Decoupled from the metrics loop so the (heavier) /proc + netlink
/// scan never affects report cadence. No-op data on unsupported platforms.
fn spawn_traffic_reporter(client: ApiClient, agent_token: String) {
    /// How often to sample + report per-process traffic.
    const SAMPLE_EVERY: Duration = Duration::from_secs(60);
    /// Cap on processes reported per batch (the backend ranks Top-10; sending a
    /// few more lets short-lived spikes still place).
    const MAX_PROCS: usize = 40;

    tokio::spawn(async move {
        let mut monitor = crate::traffic::TrafficMonitor::new();
        tracing::info!(
            collector = monitor.kind(),
            "per-process traffic accounting started"
        );
        let mut ticker = tokio::time::interval(SAMPLE_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            // Sampling touches /proc + a netlink dump; run it on the blocking
            // pool so it never holds up the async runtime.
            let mut deltas = tokio::task::block_in_place(|| monitor.sample());
            if deltas.is_empty() {
                continue;
            }
            // Keep the heaviest contributors (by rx+tx) so the batch stays small.
            deltas.sort_by_key(|d| std::cmp::Reverse(d.rx_bytes.saturating_add(d.tx_bytes)));
            deltas.truncate(MAX_PROCS);
            if let Err(e) = client.report_traffic(&agent_token, &deltas).await {
                tracing::debug!("traffic report failed: {e}");
            }
        }
    });
}

/// Spawn the periodic auto-update poller as an independent task so its blocking
/// network I/O (backend poll + version resolve + download) never stalls the
/// metrics loop. Every ~5 minutes it asks the backend whether this agent is
/// cleared to upgrade now; if so (and a newer version really exists), it kicks
/// off a background self-update. `run_self_update` already coalesces duplicate
/// triggers, so overlapping with a WS `upgrade` command is harmless.
fn spawn_upgrade_poller(cfg: AgentConfig, client: ApiClient, agent_token: String) {
    tokio::spawn(async move {
        let every =
            Duration::from_secs((300 / cfg.interval_secs.max(1)).max(1) * cfg.interval_secs.max(1));
        let mut ticker = tokio::time::interval(every.max(Duration::from_secs(30)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match client.should_upgrade(&agent_token).await {
                Ok(info) => {
                    // The backend owns the rollout schedule + target version: it
                    // tells us exactly when our turn has come (`upgrade_now`). We
                    // still confirm a newer version is actually available before
                    // pulling, so a stale signal can't trigger a needless update.
                    if info.auto_update && info.upgrade_now && upgrade_available(&cfg).await {
                        tracing::info!("backend cleared this agent for rollout; upgrading");
                        spawn_self_update(&cfg);
                    }
                }
                Err(e) => tracing::debug!("should_upgrade poll failed: {e}"),
            }
        }
    });
}

/// Fetch the latest binary, replace our own executable, and exit so the
/// supervisor relaunches us on the new version. Runs in a background task so the
/// metrics loop keeps reporting (and showing update progress) during a slow
/// download; the binary is fully downloaded BEFORE we exit, so a flaky network
/// never leaves the host without a running agent.
fn spawn_self_update(cfg: &AgentConfig) {
    let cfg = cfg.clone();
    tokio::spawn(async move {
        update::run_self_update(&cfg).await;
    });
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

    // 2. Token persisted from a previous (completed) pairing. Decrypt the
    // at-rest ciphertext; a legacy plaintext token is read as-is.
    if let Ok(raw) = std::fs::read_to_string(&cfg.token_file) {
        if let Some(token) = crate::crypto::maybe_decrypt(&raw).filter(|s| !s.is_empty()) {
            tracing::info!(file = ?cfg.token_file, "loaded agent token from file");
            return Ok(token);
        }
    }

    // 3. A pending pairing staged by the foreground pre-flight: poll until the
    // user claims it, then persist the final token. This avoids re-registering
    // (which would print a second QR to the log with a different token).
    if let Some(pending) = crate::pairing::read_pending(cfg) {
        tracing::info!("found pending pairing; waiting for claim in mini program");
        return poll_until_claimed(cfg, client, &pending.register_secret, &pending.agent_token)
            .await;
    }

    // 4. Fallback pairing flow (pre-flight didn't run / failed): register here
    // and poll. Output goes to the daemon log.
    let snapshot = collector.collect();
    let reg = client.register(&snapshot).await?;

    let expiry = if reg.expires_at_display.is_empty() {
        reg.expires_at.clone()
    } else {
        format!("{} (北京时间)", reg.expires_at_display)
    };
    crate::pairing::print_pairing(&reg.agent_token, &reg.pairing_code, &expiry);
    tracing::info!(code = %reg.pairing_code, "waiting for pairing in mini program");
    poll_until_claimed(cfg, client, &reg.register_secret, &reg.agent_token).await
}

/// Poll the backend until the pairing is claimed, then persist + return the
/// final token and clear any pending-pairing file.
///
/// Each iteration re-reads the pending file: if a separate `repair` invocation
/// rewrote it with a fresh secret (because the old pairing was invalidated),
/// we transparently switch to polling the new one.
async fn poll_until_claimed(
    cfg: &AgentConfig,
    client: &ApiClient,
    register_secret: &str,
    fallback_token: &str,
) -> Result<String> {
    let mut secret = register_secret.to_string();
    let mut token = fallback_token.to_string();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Pick up a fresh secret/token if a re-pair invocation rewrote the
        // pending file.
        if let Some(p) = crate::pairing::read_pending(cfg) {
            if !p.register_secret.is_empty() && p.register_secret != secret {
                tracing::info!("pending pairing refreshed; switching to new code");
                secret = p.register_secret;
                token = p.agent_token;
            }
        }

        match client.poll(&secret).await {
            Ok(poll) => {
                if poll.claimed {
                    let token = poll.agent_token.unwrap_or_else(|| token.clone());
                    if let Err(e) = crate::pairing::persist_token(cfg, &token) {
                        tracing::warn!("failed to persist token file: {e}");
                    }
                    crate::pairing::clear_pending(cfg);
                    tracing::info!("pairing claimed successfully");
                    return Ok(token);
                }
                tracing::debug!("not claimed yet, still waiting...");
            }
            Err(e) => {
                tracing::warn!("poll error: {e}");
            }
        }
    }
}
