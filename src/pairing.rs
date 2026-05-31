//! Foreground pairing pre-flight (runs in `main` before daemonizing).
//!
//! Two entry points, both synchronous (blocking HTTP) so they can run before
//! the tokio runtime / daemon fork while the operator can still see the output:
//!
//! - `register_and_print`: first launch with no saved token. Registers with the
//!   backend, prints the QR (token) + 8-digit quick-add code, and persists the
//!   token so the background agent starts reporting with it immediately.
//! - `repair_and_print`: launch while an instance is already running. Reads the
//!   saved token, asks the backend for a fresh quick-add code (old ones expire),
//!   re-prints the QR + new code, and exits without starting a duplicate.

use anyhow::{anyhow, Result};
use serde_json::Value;

use crate::config::AgentConfig;

/// Blocking HTTP client for the pre-daemonize phase.
fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("failed to build blocking http client")
}

/// Read the persisted token, if any.
pub fn saved_token(cfg: &AgentConfig) -> Option<String> {
    if let Some(token) = &cfg.agent_token {
        return Some(token.clone());
    }
    std::fs::read_to_string(&cfg.token_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Path of the "pending pairing" file (token + register_secret) written by the
/// foreground pre-flight and consumed by the agent role's poll loop.
pub fn pending_path(cfg: &AgentConfig) -> std::path::PathBuf {
    let mut p = cfg.token_file.clone().into_os_string();
    p.push(".pending");
    std::path::PathBuf::from(p)
}

/// A pending pairing the agent role polls on until the user claims it.
pub struct Pending {
    pub agent_token: String,
    pub register_secret: String,
}

/// Read a pending pairing written by the pre-flight (token\nsecret), if present.
pub fn read_pending(cfg: &AgentConfig) -> Option<Pending> {
    let body = std::fs::read_to_string(pending_path(cfg)).ok()?;
    let mut lines = body.lines();
    let agent_token = lines.next()?.trim().to_string();
    let register_secret = lines.next()?.trim().to_string();
    if agent_token.is_empty() || register_secret.is_empty() {
        return None;
    }
    Some(Pending { agent_token, register_secret })
}

/// Remove the pending pairing file (after a successful claim).
pub fn clear_pending(cfg: &AgentConfig) {
    let _ = std::fs::remove_file(pending_path(cfg));
}

/// First-launch registration: register, print pairing, and stage a pending
/// pairing file (token + secret) for the agent role to poll on. The final token
/// file is only written once the user actually claims the server, so the agent
/// doesn't report (and get 401s) before then.
pub fn register_and_print(cfg: &AgentConfig) -> Result<()> {
    let http = client();
    let body = serde_json::json!({
        "hostname": hostname(),
        "ip": "",
        "os_version": "",
    });
    let resp = http
        .post(format!("{}/agent/register", cfg.backend_url))
        .json(&body)
        .send()?
        .error_for_status()?;
    let env: Value = resp.json()?;
    let data = env
        .get("data")
        .ok_or_else(|| anyhow!("register: missing data"))?;

    let token = data.get("agent_token").and_then(Value::as_str).unwrap_or("");
    let code = data.get("pairing_code").and_then(Value::as_str).unwrap_or("");
    let secret = data.get("register_secret").and_then(Value::as_str).unwrap_or("");
    let expiry = data
        .get("expires_at_display")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s} (北京时间)"))
        .or_else(|| data.get("expires_at").and_then(Value::as_str).map(String::from))
        .unwrap_or_default();
    if token.is_empty() || code.is_empty() || secret.is_empty() {
        return Err(anyhow!("register: empty token/code/secret"));
    }

    print_pairing(token, code, &expiry);

    // Stage the pending pairing so the background agent can poll until claimed.
    if let Err(e) = std::fs::write(pending_path(cfg), format!("{token}\n{secret}\n")) {
        tracing::warn!("failed to persist pending pairing: {e}");
    }
    Ok(())
}

/// Re-pair an already-running agent: fetch a fresh code for the saved token.
pub fn repair_and_print(cfg: &AgentConfig, token: &str) -> Result<()> {
    let http = client();
    let resp = http
        .post(format!("{}/agent/repair", cfg.backend_url))
        .json(&serde_json::json!({ "agent_token": token }))
        .send()?
        .error_for_status()?;
    let env: Value = resp.json()?;
    let data = env
        .get("data")
        .ok_or_else(|| anyhow!("repair: missing data"))?;

    let claimed = data.get("claimed").and_then(Value::as_bool).unwrap_or(false);
    if claimed {
        println!("\n========================================");
        println!("  本服务器已被添加到 TeaOps，无需再次配对。");
        println!("========================================\n");
        return Ok(());
    }

    let code = data.get("pairing_code").and_then(Value::as_str).unwrap_or("");
    let secret = data.get("register_secret").and_then(Value::as_str).unwrap_or("");
    let expiry = data
        .get("expires_at_display")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s} (北京时间)"))
        .unwrap_or_default();
    if code.is_empty() {
        return Err(anyhow!("repair: empty code"));
    }

    // If the running agent is still waiting to be claimed, hand it the new
    // pairing secret via the pending file so it polls the fresh pairing (the
    // old one was just invalidated server-side). Only do this when a pending
    // file already exists (i.e. not yet claimed).
    if !secret.is_empty() && std::fs::metadata(pending_path(cfg)).is_ok() {
        let _ = std::fs::write(pending_path(cfg), format!("{token}\n{secret}\n"));
    }

    println!("\n  检测到 Agent 已在后台运行，已为当前服务器重新生成配对信息：");
    print_pairing(token, code, &expiry);
    Ok(())
}

fn hostname() -> String {
    sysinfo::System::host_name().unwrap_or_default()
}

/// Render the pairing instructions: a QR encoding the 128-char server token
/// (scan to add directly) plus the 8-digit quick-add code.
pub fn print_pairing(agent_token: &str, pairing_code: &str, expires_at: &str) {
    println!("\n========================================");
    println!("  TeaOps Agent 配对");
    println!("  用小程序扫描下方二维码即可添加本服务器：\n");
    match render_qr(agent_token) {
        Some(qr) => println!("{qr}"),
        None => println!("  (二维码渲染失败，请改用下方快速添加码)\n"),
    }
    println!("  或在小程序中输入 8 位快速添加码：");
    println!("\n        >>>  {pairing_code}  <<<\n");
    if !expires_at.is_empty() {
        println!("  (有效期至 {expires_at})");
    }
    println!("========================================\n");
}

/// Render a QR code into the terminal using unicode upper-half blocks with
/// explicit ANSI colors (black modules on a white background), so it scans
/// regardless of the terminal theme. Returns None if encoding fails.
pub fn render_qr(data: &str) -> Option<String> {
    use qrcode::types::Color;
    use qrcode::{EcLevel, QrCode};

    let payload = data.to_ascii_uppercase();
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L).ok()?;
    let width = code.width();
    let modules = code.to_colors();

    let quiet = 2isize;
    let total = width as isize + quiet * 2;
    let dark = |x: isize, y: isize| -> bool {
        let mx = x - quiet;
        let my = y - quiet;
        if mx < 0 || my < 0 || mx >= width as isize || my >= width as isize {
            return false;
        }
        modules[(my as usize) * width + (mx as usize)] == Color::Dark
    };
    let ansi = |is_dark: bool| if is_dark { 0 } else { 15 };

    let mut out = String::new();
    let mut y = 0isize;
    while y < total {
        for x in 0..total {
            let fg = ansi(dark(x, y));
            let bg = ansi(dark(x, y + 1));
            out.push_str(&format!("\x1b[38;5;{fg};48;5;{bg}m\u{2580}"));
        }
        out.push_str("\x1b[0m\n");
        y += 2;
    }
    Some(out)
}
