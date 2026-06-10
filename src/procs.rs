//! Live process-list channel (Top-N by CPU / memory).
//!
//! In response to an `open-procs` command the panel dials back
//! `/panel/procs?session=...` and serves a tiny request/response protocol over
//! that WebSocket: the client sends `{"id":N,"op":"list"}` and we reply with a
//! snapshot of the heaviest processes. The mini program's CPU/memory gauges use
//! this to show a Top-20 ranking on tap.
//!
//! CPU% needs two samples spaced by a short interval, so a `list` request
//! refreshes the process CPU usage, waits briefly, refreshes again, then reads.

use serde::Serialize;
use serde_json::{json, Value};
use sysinfo::System;

/// One process row in the ranking.
#[derive(Debug, Clone, Serialize)]
struct ProcRow {
    pid: u32,
    name: String,
    /// Owning user name (resolved from the uid; falls back to the uid number).
    user: String,
    /// CPU usage percent across all cores summed (sysinfo convention: 100 = one
    /// full core). Rounded to 1 decimal.
    cpu: f64,
    /// Resident memory in bytes.
    mem: u64,
    /// Cumulative CPU time used by the process, in seconds (like top's TIME).
    time: i64,
}

/// Public entrypoint for the local web console: a one-shot process snapshot.
pub async fn web_snapshot(limit: usize) -> Value {
    let mut sys = System::new();
    snapshot(&mut sys, limit.clamp(1, 50)).await
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

    // Resolve uid -> name once (rebuilding the user DB per row is expensive).
    let users = sysinfo::Users::new_with_refreshed_list();

    let mut rows: Vec<ProcRow> = sys
        .processes()
        .values()
        // Exclude threads: on Linux sysinfo lists a process's threads as
        // separate entries with the SAME name and (near) identical cpu/mem,
        // which is what produced the "duplicate" rows. Keep only real
        // processes (thread_kind() == None).
        .filter(|p| p.thread_kind().is_none())
        .map(|p| ProcRow {
            pid: p.pid().as_u32(),
            name: proc_name(p),
            user: p
                .user_id()
                .map(|uid| {
                    users
                        .get_user_by_id(uid)
                        .map(|u| u.name().to_string())
                        .unwrap_or_else(|| uid.to_string())
                })
                .unwrap_or_default(),
            cpu: ((p.cpu_usage() as f64) * 10.0).round() / 10.0,
            mem: p.memory(),
            time: p.run_time() as i64,
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
