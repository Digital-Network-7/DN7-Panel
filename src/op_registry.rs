//! Unified detached-operation registry.
//!
//! Long-running operations (image pulls, package installs, cert issuance,
//! engine switches) are created here, stream progress `lines`, and are polled
//! by the web console via `list_ops` / `op_log` until done/error. The registry
//! is process-global so an op survives client reconnects.
//!
//! The docker / nginx / mysql modules each used to carry a near-identical copy
//! of this registry; they now share one [`OpRegistry`], differing only in their
//! id prefix, progress-percent estimator, dismiss policy, and the extra result
//! fields they attach on completion (e.g. `result_image`, `inst_id`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Map, Value};

/// Max progress lines retained per op (the tail; bounds memory on long pulls).
const MAX_LINES: usize = 400;

/// Whether [`OpRegistry::dismiss`] may forget a still-running op.
#[derive(Clone, Copy)]
pub(crate) enum Dismiss {
    /// Remove any op, running or not (docker / nginx).
    Any,
    /// Only forget finished ops; a running op stays (mysql).
    FinishedOnly,
}

#[derive(Clone)]
struct OpRecord {
    kind: String,
    target: String,
    status: String, // "running" | "done" | "error"
    error: String,
    lines: Vec<String>,
    /// Extra result fields merged into the op's JSON (e.g. `result_image`).
    extra: Map<String, Value>,
}

/// A process-global registry of detached operations for one subsystem.
pub(crate) struct OpRegistry {
    prefix: &'static str,
    counter: AtomicU64,
    ops: Mutex<HashMap<String, OpRecord>>,
    /// Progress estimator (0..=100, or -1 for indeterminate).
    pct: fn(&[String], &str) -> i64,
    dismiss: Dismiss,
}

impl OpRegistry {
    pub(crate) fn new(
        prefix: &'static str,
        pct: fn(&[String], &str) -> i64,
        dismiss: Dismiss,
    ) -> Self {
        Self {
            prefix,
            counter: AtomicU64::new(1),
            ops: Mutex::new(HashMap::new()),
            pct,
            dismiss,
        }
    }

    /// Mint a fresh, monotonic op id (`<prefix><n>`).
    pub(crate) fn new_id(&self) -> String {
        format!(
            "{}{}",
            self.prefix,
            self.counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    pub(crate) fn create(&self, id: &str, kind: &str, target: &str) {
        if let Ok(mut m) = self.ops.lock() {
            m.insert(
                id.to_string(),
                OpRecord {
                    kind: kind.to_string(),
                    target: target.to_string(),
                    status: "running".to_string(),
                    error: String::new(),
                    lines: Vec::new(),
                    extra: Map::new(),
                },
            );
        }
    }

    pub(crate) fn push(&self, id: &str, line: &str) {
        if line.is_empty() {
            return;
        }
        if let Ok(mut m) = self.ops.lock() {
            if let Some(o) = m.get_mut(id) {
                o.lines.push(line.to_string());
                let len = o.lines.len();
                if len > MAX_LINES {
                    o.lines.drain(0..len - MAX_LINES);
                }
            }
        }
    }

    /// Mark an op finished. `extra` (a JSON object) is merged into the op's
    /// snapshot/log output — pass `json!({})` when there are no extra fields.
    pub(crate) fn finish(&self, id: &str, status: &str, error: &str, extra: Value) {
        if let Ok(mut m) = self.ops.lock() {
            if let Some(o) = m.get_mut(id) {
                o.status = status.to_string();
                o.error = error.to_string();
                if let Value::Object(map) = extra {
                    o.extra = map;
                }
            }
        }
    }

    /// Whether an op with this id exists and is still running.
    pub(crate) fn running(&self, id: &str) -> bool {
        self.ops
            .lock()
            .ok()
            .and_then(|m| m.get(id).map(|o| o.status == "running"))
            .unwrap_or(false)
    }

    pub(crate) fn dismiss(&self, id: &str) {
        if let Ok(mut m) = self.ops.lock() {
            let remove = match self.dismiss {
                Dismiss::Any => true,
                Dismiss::FinishedOnly => m.get(id).map(|o| o.status != "running").unwrap_or(false),
            };
            if remove {
                m.remove(id);
            }
        }
    }

    /// Snapshot of all ops (without full logs) for `list_ops`.
    pub(crate) fn snapshot(&self) -> Value {
        let m = match self.ops.lock() {
            Ok(m) => m,
            Err(_) => return json!({ "ops": [] }),
        };
        let list: Vec<Value> = m
            .iter()
            .map(|(id, o)| self.row(Some(id), o, false))
            .collect();
        json!({ "ops": list })
    }

    /// Full log + status for one op.
    pub(crate) fn log(&self, id: &str) -> Value {
        let m = match self.ops.lock() {
            Ok(m) => m,
            Err(_) => return json!({ "lines": [], "status": "error", "error": "lock" }),
        };
        match m.get(id) {
            Some(o) => self.row(None, o, true),
            None => json!({ "lines": [], "status": "gone", "error": "" }),
        }
    }

    /// Build one op's JSON. `full` includes the whole `lines` tail (op_log);
    /// otherwise it carries `op_id` + a one-line `last_line` hint (list_ops).
    fn row(&self, id: Option<&str>, o: &OpRecord, full: bool) -> Value {
        let mut obj = Map::new();
        if full {
            obj.insert("lines".into(), json!(o.lines));
        } else {
            if let Some(id) = id {
                obj.insert("op_id".into(), json!(id));
            }
            obj.insert(
                "last_line".into(),
                json!(o.lines.last().cloned().unwrap_or_default()),
            );
        }
        obj.insert("kind".into(), json!(o.kind));
        obj.insert("target".into(), json!(o.target));
        obj.insert("status".into(), json!(o.status));
        obj.insert("error".into(), json!(o.error));
        obj.insert("pct".into(), json!((self.pct)(&o.lines, &o.status)));
        for (k, v) in &o.extra {
            obj.insert(k.clone(), v.clone());
        }
        Value::Object(obj)
    }
}

/// Build a localizable progress line for the op log: a sentinel-delimited `MSG`
/// record the web console maps to `msg.<code>` (positional `{0}`, `{1}`… args).
/// An arg prefixed with `@` is itself a translation key resolved on the client.
/// Plain command output is pushed verbatim and rendered as-is.
pub(crate) fn pmsg(code: &str, args: &[&str]) -> String {
    let mut s = format!("\u{1e}MSG\u{1e}{code}");
    for a in args {
        s.push('\u{1e}');
        s.push_str(a);
    }
    s
}

/// Indeterminate progress (always -1) — for ops with no reliable percentage
/// (e.g. host package installs). The web console renders an indeterminate bar.
pub(crate) fn indeterminate_pct(_lines: &[String], _status: &str) -> i64 {
    -1
}

/// Estimate 0..100 progress from docker image-pull log lines, weighting each
/// layer by its phase (downloading → download-complete → extracting → complete)
/// and averaging across all layers seen. Returns -1 when indeterminate. This
/// makes the bar advance steadily during download/extract instead of only
/// jumping when whole layers finish. Shared by the docker / mysql modules
/// (their image pulls log the same docker progress lines).
pub(crate) fn pull_pct(lines: &[String], status: &str) -> i64 {
    if status == "done" {
        return 100;
    }
    // Per-layer phase weight (0.0..1.0), keyed by the layer's leading hex id.
    let mut layers: HashMap<String, f64> = HashMap::new();
    let phase = |l: &str| -> Option<f64> {
        if l.contains("Already exists") || l.contains("Pull complete") {
            Some(1.0)
        } else if l.contains("Extracting") {
            Some(0.80)
        } else if l.contains("Verifying Checksum") || l.contains("Download complete") {
            Some(0.55)
        } else if l.contains("Downloading") {
            Some(0.45)
        } else if l.contains("Waiting") || l.contains("Pulling fs layer") {
            Some(0.05)
        } else {
            None
        }
    };
    for ln in lines {
        let l = ln.as_str();
        if l.contains("Pulling from") || l.contains("Digest:") || l.contains("Status:") {
            continue;
        }
        let p = match phase(l) {
            Some(p) => p,
            None => continue,
        };
        let key: String = l
            .split_whitespace()
            .next()
            .map(|s| s.trim_end_matches(':').to_string())
            .unwrap_or_else(|| l.to_string());
        // Keep the furthest phase seen for this layer (never go backwards).
        let entry = layers.entry(key).or_insert(0.0);
        if p > *entry {
            *entry = p;
        }
    }
    if layers.is_empty() {
        return -1;
    }
    let sum: f64 = layers.values().sum();
    let pct = (sum / layers.len() as f64) * 100.0;
    pct.clamp(1.0, 99.0) as i64
}
