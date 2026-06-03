//! Live process-list channel (Top-N by CPU / memory).
//!
//! In response to an `open-procs` command the agent dials back
//! `/agent/procs?session=...` and serves a tiny request/response protocol over
//! that WebSocket: the client sends `{"id":N,"op":"list"}` and we reply with a
//! snapshot of the heaviest processes. The mini program's CPU/memory gauges use
//! this to show a Top-20 ranking on tap.
//!
//! CPU% needs two samples spaced by a short interval, so a `list` request
//! refreshes the process CPU usage, waits briefly, refreshes again, then reads.

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use sysinfo::System;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

/// One process row in the ranking.
#[derive(Debug, Clone, Serialize)]
struct ProcRow {
    pid: u32,
    name: String,
    /// CPU usage percent across all cores summed (sysinfo convention: 100 = one
    /// full core). Rounded to 1 decimal.
    cpu: f64,
    /// Resident memory in bytes.
    mem: u64,
}

/// Connect to the backend procs relay and serve the protocol until either side
/// closes.
pub async fn run_procs_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_procs_ws_url(session);
    let mut req = url
        .into_client_request()
        .map_err(|e| anyhow!("bad ws url: {e}"))?;
    req.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {agent_token}")
            .parse()
            .map_err(|e| anyhow!("bad auth header: {e}"))?,
    );
    let (ws, _resp) = connect_async(req).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let mut sys = System::new();

    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                let id = v.get("id").cloned().unwrap_or(Value::Null);
                let op = v.get("op").and_then(|o| o.as_str()).unwrap_or("");
                let frame = match op {
                    "list" => {
                        let limit = v
                            .get("limit")
                            .and_then(|n| n.as_u64())
                            .unwrap_or(20)
                            .clamp(1, 50) as usize;
                        let data = snapshot(&mut sys, limit).await;
                        json!({ "id": id, "ok": true, "data": data })
                    }
                    _ => json!({ "id": id, "ok": false, "error": "unknown op" }),
                };
                if ws_tx.send(Message::Text(frame.to_string())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = ws_tx.send(Message::Pong(p)).await;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
    let _ = ws_tx.close().await;
    Ok(())
}

/// Take a process snapshot: refresh CPU twice (so CPU% is meaningful), then
/// return the union of the Top-`limit` by CPU and Top-`limit` by memory, each
/// list pre-sorted, plus the host's total memory for percentage display.
async fn snapshot(sys: &mut System, limit: usize) -> Value {
    // First CPU sample.
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
    sys.refresh_cpu_usage();
    // Brief wait so the second sample yields a real CPU delta.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    let total_mem = sys.total_memory();

    let mut rows: Vec<ProcRow> = sys
        .processes()
        .values()
        .map(|p| ProcRow {
            pid: p.pid().as_u32(),
            name: proc_name(p),
            cpu: ((p.cpu_usage() as f64) * 10.0).round() / 10.0,
            mem: p.memory(),
        })
        .collect();

    // Top by CPU.
    rows.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let by_cpu: Vec<ProcRow> = rows.iter().take(limit).cloned().collect();

    // Top by memory.
    rows.sort_by(|a, b| b.mem.cmp(&a.mem));
    let by_mem: Vec<ProcRow> = rows.iter().take(limit).cloned().collect();

    json!({
        "total_mem": total_mem,
        "by_cpu": by_cpu,
        "by_mem": by_mem,
    })
}

/// A readable process name: prefer the executable/command name; fall back to
/// the first cmdline arg's basename.
fn proc_name(p: &sysinfo::Process) -> String {
    let n = p.name().to_string_lossy().trim().to_string();
    if !n.is_empty() {
        return n;
    }
    if let Some(arg0) = p.cmd().first() {
        let s = arg0.to_string_lossy();
        let base = s.rsplit('/').next().unwrap_or(&s);
        if !base.is_empty() {
            return base.to_string();
        }
    }
    format!("pid {}", p.pid().as_u32())
}
