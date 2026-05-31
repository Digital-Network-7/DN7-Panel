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

    // 3. Pairing flow: register -> show QR (token) + 8-digit code -> poll.
    let snapshot = collector.collect();
    let reg = client.register(&snapshot).await?;

    print_pairing(&reg.agent_token, &reg.pairing_code, &reg.expires_at);
    tracing::info!(code = %reg.pairing_code, "waiting for pairing in mini program");

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match client.poll(&reg.register_secret).await {
            Ok(poll) => {
                if poll.claimed {
                    // The backend reuses the pre-generated token, so prefer the
                    // polled token but fall back to the one we already have.
                    let token = poll.agent_token.unwrap_or_else(|| reg.agent_token.clone());
                    if let Err(e) = std::fs::write(&cfg.token_file, &token) {
                        tracing::warn!("failed to persist token file: {e}");
                    }
                    tracing::info!("pairing claimed successfully");
                    return Ok(token);
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

/// Render the pairing instructions: a QR encoding the 128-char server token
/// (scan to add directly) plus the 8-digit quick-add code (type it instead).
fn print_pairing(agent_token: &str, pairing_code: &str, expires_at: &str) {
    println!("\n========================================");
    println!("  TeaOps Agent 配对");
    println!("  用小程序扫描下方二维码即可添加本服务器：\n");
    match render_qr(agent_token) {
        Some(qr) => println!("{qr}"),
        None => println!("  (二维码渲染失败，请改用下方快速添加码)\n"),
    }
    println!("  或在小程序中输入 8 位快速添加码：");
    println!("\n        >>>  {pairing_code}  <<<\n");
    println!("  (有效期至 {expires_at})");
    println!("========================================\n");
}

/// Render a QR code into the terminal using unicode upper-half blocks with
/// explicit ANSI colors (black modules on a white background). Setting both the
/// foreground and background per cell makes the code scannable regardless of
/// the terminal's own color theme, while the half-block trick maps two QR rows
/// to one text line so the symbol stays roughly square. Returns None if
/// encoding fails.
fn render_qr(data: &str) -> Option<String> {
    use qrcode::types::Color;
    use qrcode::{EcLevel, QrCode};

    // Uppercase hex stays in the QR alphanumeric charset, which is denser than
    // byte mode and yields a smaller, easier-to-scan symbol.
    let payload = data.to_ascii_uppercase();
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L).ok()?;
    let width = code.width();
    let modules = code.to_colors();

    let quiet = 2isize; // light quiet zone around the symbol
    let total = width as isize + quiet * 2;
    // True = dark module; outside the symbol (quiet zone) is light.
    let dark = |x: isize, y: isize| -> bool {
        let mx = x - quiet;
        let my = y - quiet;
        if mx < 0 || my < 0 || mx >= width as isize || my >= width as isize {
            return false;
        }
        modules[(my as usize) * width + (mx as usize)] == Color::Dark
    };
    // 256-color codes: 0 = black (dark module), 15 = white (light module).
    let ansi = |is_dark: bool| if is_dark { 0 } else { 15 };

    let mut out = String::new();
    let mut y = 0isize;
    while y < total {
        for x in 0..total {
            let fg = ansi(dark(x, y)); // top half = this row
            let bg = ansi(dark(x, y + 1)); // bottom half = next row
            out.push_str(&format!("\x1b[38;5;{fg};48;5;{bg}m\u{2580}"));
        }
        out.push_str("\x1b[0m\n");
        y += 2;
    }
    Some(out)
}
