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

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

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

/// Background-sampled snapshot (Top-50 by CPU and by memory + total memory).
/// Requests read the most recent sample instead of scanning the whole process
/// table (twice, with a 400ms delay) on every call.
#[derive(Default, Clone)]
struct Cached {
    ready: bool,
    total_mem: u64,
    by_cpu: Vec<ProcRow>,
    by_mem: Vec<ProcRow>,
}

const CACHE_TOP: usize = 50;
/// How often the background sampler refreshes the process table (also the CPU%
/// averaging window, since a persistent `System` handle accumulates the delta).
const SAMPLE_INTERVAL: Duration = Duration::from_secs(3);

fn cache() -> &'static Mutex<Cached> {
    static CACHE: OnceLock<Mutex<Cached>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cached::default()))
}

/// Start the background sampler once. It owns a persistent `System` handle and
/// refreshes it on an interval, storing each computed snapshot in the cache —
/// so request handlers never scan the process table or sleep.
fn ensure_sampler() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        tokio::spawn(async {
            let mut sys = System::new();
            // Prime the CPU baseline; the next refresh yields a real delta.
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
            sys.refresh_cpu_usage();
            loop {
                tokio::time::sleep(SAMPLE_INTERVAL).await;
                sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
                sys.refresh_cpu_usage();
                sys.refresh_memory();
                let snap = compute(&sys, CACHE_TOP);
                *cache().lock().unwrap() = snap;
            }
        });
    });
}

/// Public entrypoint for the local web console: return the latest background
/// sample (Top-`limit`). On the very first call before the sampler has produced
/// a sample, falls back to a single one-shot snapshot so the response isn't
/// empty; thereafter all calls are served instantly from the cache.
pub async fn web_snapshot(limit: usize) -> Value {
    ensure_sampler();
    let lim = limit.clamp(1, CACHE_TOP);
    {
        let c = cache().lock().unwrap();
        if c.ready {
            return json!({
                "total_mem": c.total_mem,
                "by_cpu": c.by_cpu.iter().take(lim).collect::<Vec<_>>(),
                "by_mem": c.by_mem.iter().take(lim).collect::<Vec<_>>(),
            });
        }
    }
    // Cold start: one-shot snapshot (the only path that pays the sampling cost).
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
    sys.refresh_cpu_usage();
    tokio::time::sleep(Duration::from_millis(400)).await;
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    let c = compute(&sys, lim);
    json!({ "total_mem": c.total_mem, "by_cpu": c.by_cpu, "by_mem": c.by_mem })
}

/// Build the Top-`limit` by-CPU and by-memory rankings from an already-refreshed
/// `System` handle (no sleeping, no extra scan).
fn compute(sys: &System, limit: usize) -> Cached {
    let total_mem = sys.total_memory();
    // Resolve uid -> name once (rebuilding the user DB per row is expensive).
    let users = sysinfo::Users::new_with_refreshed_list();

    let mut rows: Vec<ProcRow> = sys
        .processes()
        .values()
        // Exclude threads: on Linux sysinfo lists a process's threads as
        // separate entries with the SAME name and (near) identical cpu/mem.
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

    rows.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let by_cpu: Vec<ProcRow> = rows.iter().take(limit).cloned().collect();

    rows.sort_by(|a, b| b.mem.cmp(&a.mem));
    let by_mem: Vec<ProcRow> = rows.iter().take(limit).cloned().collect();

    Cached {
        ready: true,
        total_mem,
        by_cpu,
        by_mem,
    }
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
