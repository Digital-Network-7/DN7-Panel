//! Background time-series sampler for the dashboard history view.
//!
//! A single sampler at the smallest needed interval (15min / 100 ≈ 9s) records
//! the host's `cpu% / mem% / net throughput`. Each selectable range
//! (15m/1h/6h/1d/7d) is a fixed 100-slot ring fed from that one stream by
//! folding an integer number of base samples per slot — so there is **one**
//! sampler, not one per range. The rings are persisted to
//! `<data>/metrics-history.json` (bounded to ~500 points total, rewritten in
//! place so the file can't grow) and reloaded on start. Points older than their
//! window are dropped on query, so a restart/downtime gap never renders as a
//! stale flat line. The sample is aggregate-only (no per-process scan), so the
//! continuous CPU cost is far below the process table it replaces.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sysinfo::{Networks, System};

/// Base sample interval: 15 minutes / 100 points.
const BASE_SECS: u64 = 9;
/// Points kept per range (per chart).
const SLOTS: usize = 100;
/// Fold factor per range: how many base samples make one slot. All are integer
/// multiples of the base (15m=1, 1h=4, 6h=24, 1d=96, 7d=672).
const RANGES: &[(&str, u32)] = &[("15m", 1), ("1h", 4), ("6h", 24), ("1d", 96), ("7d", 672)];
/// Flush the rings to disk roughly every minute (every `FLUSH_EVERY` samples).
const FLUSH_EVERY: u32 = 7;

#[derive(Clone, Serialize, Deserialize)]
struct Point {
    /// Unix seconds at slot close.
    t: i64,
    cpu: f32, // percent
    mem: f32, // percent
    rx: f32,  // bytes/sec (download)
    tx: f32,  // bytes/sec (upload)
}

/// Running accumulator for a ring's in-progress slot (not persisted).
#[derive(Default)]
struct Acc {
    cpu: f64,
    mem: f64,
    rx: f64,
    tx: f64,
    n: u32,
}

#[derive(Default, Serialize, Deserialize)]
struct Ring {
    fold: u32,
    points: Vec<Point>,
    #[serde(skip)]
    acc: Acc,
}

impl Ring {
    /// Fold one base sample in; emit a slot point once `fold` samples averaged.
    fn feed(&mut self, s: &Sample, now: i64) {
        self.acc.cpu += s.cpu as f64;
        self.acc.mem += s.mem as f64;
        self.acc.rx += s.rx as f64;
        self.acc.tx += s.tx as f64;
        self.acc.n += 1;
        if self.acc.n < self.fold.max(1) {
            return;
        }
        let n = self.acc.n as f64;
        self.points.push(Point {
            t: now,
            cpu: (self.acc.cpu / n) as f32,
            mem: (self.acc.mem / n) as f32,
            rx: (self.acc.rx / n) as f32,
            tx: (self.acc.tx / n) as f32,
        });
        if self.points.len() > SLOTS {
            let excess = self.points.len() - SLOTS;
            self.points.drain(0..excess);
        }
        self.acc = Acc::default();
    }
}

struct Sample {
    cpu: f32,
    mem: f32,
    rx: f32,
    tx: f32,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    rings: Vec<Ring>,
}

fn store() -> &'static Mutex<Store> {
    static S: OnceLock<Mutex<Store>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(load_store()))
}

fn path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("metrics-history.json")
}

/// Load persisted rings, reconciled against the current `RANGES` set (keeps the
/// points of any range whose fold factor still exists; drops/creates the rest).
fn load_store() -> Store {
    let mut prev: Store = std::fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let rings = RANGES
        .iter()
        .map(|(_, fold)| {
            let mut points = prev
                .rings
                .iter_mut()
                .find(|r| r.fold == *fold)
                .map(|r| std::mem::take(&mut r.points))
                .unwrap_or_default();
            sanitize_points(&mut points);
            Ring {
                fold: *fold,
                points,
                acc: Acc::default(),
            }
        })
        .collect();
    Store { rings }
}

fn sanitize_points(points: &mut Vec<Point>) {
    points.retain(|p| {
        p.t > 0 && p.cpu.is_finite() && p.mem.is_finite() && p.rx.is_finite() && p.tx.is_finite()
    });
    if points.len() > SLOTS {
        let excess = points.len() - SLOTS;
        points.drain(0..excess);
    }
}

/// Rewrite the on-disk snapshot in place (bounded ~500 points; never appends).
fn persist() {
    let p = path();
    let data = {
        let st = store().lock().unwrap_or_else(|e| e.into_inner());
        serde_json::to_string(&*st).unwrap_or_else(|_| "{}".into())
    };
    let _ = crate::platform::paths::write_public(&p, data.as_bytes());
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Start the background sampler once (idempotent). Called at panel boot so the
/// history is warm before anyone opens the dashboard.
pub fn start() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        tokio::spawn(run());
    });
}

async fn run() {
    let mut sys = System::new();
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    let mut nets = Networks::new_with_refreshed_list();
    let mut last = Instant::now();
    let mut flush = 0u32;
    loop {
        tokio::time::sleep(Duration::from_secs(BASE_SECS)).await;
        let s = sample(&mut sys, &mut nets, &mut last);
        let now = now_secs();
        {
            let mut st = store().lock().unwrap_or_else(|e| e.into_inner());
            for r in &mut st.rings {
                r.feed(&s, now);
            }
        }
        flush += 1;
        if flush >= FLUSH_EVERY {
            flush = 0;
            persist();
        }
    }
}

/// Take one lightweight sample: average cpu%, memory%, and net throughput
/// (bytes/sec) since the previous sample. No disk stat / per-process scan.
fn sample(sys: &mut System, nets: &mut Networks, last: &mut Instant) -> Sample {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    nets.refresh();
    let cpus = sys.cpus();
    let cpu = if cpus.is_empty() {
        0.0
    } else {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    }
    .clamp(0.0, 100.0);
    let total = sys.total_memory();
    let mem = if total == 0 {
        0.0
    } else {
        (sys.used_memory() as f64 / total as f64 * 100.0) as f32
    };
    let now = Instant::now();
    let elapsed = now.duration_since(*last).as_secs_f64().max(1.0);
    *last = now;
    let (mut rx, mut tx) = (0u64, 0u64);
    for (_iface, d) in nets.iter() {
        rx += d.received();
        tx += d.transmitted();
    }
    Sample {
        cpu,
        mem,
        rx: (rx as f64 / elapsed) as f32,
        tx: (tx as f64 / elapsed) as f32,
    }
}

/// Project the requested range + metric into a JSON series for the UI. Points
/// older than the range window are dropped (downtime/restart gaps don't show as
/// a stale line). `metric` is `cpu` | `mem` | `net` (net returns rx + tx).
pub fn series(range: &str, metric: &str) -> Value {
    let (range, fold) = range_fold(range);
    let metric = normalize_metric(metric);
    let window = fold as i64 * SLOTS as i64 * BASE_SECS as i64;
    let now = now_secs();
    let cutoff = now - window;
    let st = store().lock().unwrap_or_else(|e| e.into_inner());
    let points: Vec<Value> = match st.rings.iter().find(|r| r.fold == fold) {
        Some(r) => r
            .points
            .iter()
            .filter(|p| p.t >= cutoff)
            .map(|p| match metric {
                "mem" => json!({ "t": p.t, "v": p.mem as f64 }),
                "net" => json!({ "t": p.t, "rx": p.rx as f64, "tx": p.tx as f64 }),
                _ => json!({ "t": p.t, "v": p.cpu as f64 }),
            })
            .collect(),
        None => Vec::new(),
    };
    json!({
        "metric": metric,
        "range": range,
        "now": now,
        "window_secs": window,
        "slot_secs": fold as i64 * BASE_SECS as i64,
        "points": points
    })
}

fn range_fold(range: &str) -> (&'static str, u32) {
    RANGES
        .iter()
        .find(|(r, _)| *r == range)
        .map(|(r, f)| (*r, *f))
        .unwrap_or(("15m", 1))
}

fn normalize_metric(metric: &str) -> &'static str {
    match metric {
        "mem" => "mem",
        "net" => "net",
        _ => "cpu",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_points_keeps_bounded_finite_tail() {
        let mut points = Vec::new();
        points.push(Point {
            t: 1,
            cpu: f32::NAN,
            mem: 0.0,
            rx: 0.0,
            tx: 0.0,
        });
        for i in 0..(SLOTS + 5) {
            points.push(Point {
                t: (i + 2) as i64,
                cpu: 1.0,
                mem: 2.0,
                rx: 3.0,
                tx: 4.0,
            });
        }
        sanitize_points(&mut points);
        assert_eq!(points.len(), SLOTS);
        assert_eq!(points.first().unwrap().t, 7);
        assert!(points.iter().all(|p| p.cpu.is_finite()));
    }

    #[test]
    fn invalid_query_values_normalize_to_dashboard_defaults() {
        assert_eq!(range_fold("bad"), ("15m", 1));
        assert_eq!(normalize_metric("bad"), "cpu");
        assert_eq!(normalize_metric("mem"), "mem");
        assert_eq!(normalize_metric("net"), "net");
    }
}
