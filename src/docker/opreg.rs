//! Detached operation registry (pulls + install) (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Detached operation registry (pulls + install). Process-global so an op keeps
// running across client reconnects.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct OpState {
    kind: String,              // "pull" | "install" | "create"
    target: String,            // image name (pull) or "docker" (install) or container name (create)
    pub(crate) status: String, // "running" | "done" | "error"
    error: String,             // populated when status == "error"
    result_image: String,      // final clean image name on a successful pull
    lines: Vec<String>,        // progress tail (bounded)
}

pub(crate) fn ops() -> &'static Mutex<HashMap<String, OpState>> {
    static OPS: OnceLock<Mutex<HashMap<String, OpState>>> = OnceLock::new();
    OPS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn new_op_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("op{}", N.fetch_add(1, Ordering::Relaxed))
}

pub(crate) fn op_create(op_id: &str, kind: &str, target: &str) {
    if let Ok(mut m) = ops().lock() {
        m.insert(
            op_id.to_string(),
            OpState {
                kind: kind.to_string(),
                target: target.to_string(),
                status: "running".to_string(),
                error: String::new(),
                result_image: String::new(),
                lines: Vec::new(),
            },
        );
    }
}

/// Build a localizable progress line for the op log: a sentinel-delimited
/// `MSG` record the web console maps to `msg.<code>` (positional `{0}`, `{1}`…
/// args). An arg prefixed with `@` is itself a translation key resolved on the
/// client. Plain command output is pushed verbatim and rendered as-is.
pub(crate) fn pmsg(code: &str, args: &[&str]) -> String {
    let mut s = format!("\u{1e}MSG\u{1e}{code}");
    for a in args {
        s.push('\u{1e}');
        s.push_str(a);
    }
    s
}

pub(crate) fn op_push(op_id: &str, line: &str) {
    if line.is_empty() {
        return;
    }
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.lines.push(line.to_string());
            // Keep only the recent tail so a long pull can't grow unbounded.
            let len = o.lines.len();
            if len > 400 {
                o.lines.drain(0..len - 400);
            }
        }
    }
}

pub(crate) fn op_finish(op_id: &str, status: &str, error: &str, result_image: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.status = status.to_string();
            o.error = error.to_string();
            o.result_image = result_image.to_string();
        }
    }
}

/// Estimate 0..100 progress from pull/install log lines (counts layers that
/// Estimate 0..100 progress from pull/install log lines, weighting each layer
/// by its phase (downloading → download-complete → extracting → complete) and
/// averaging across all layers seen. Returns -1 when indeterminate. This makes
/// the bar advance steadily during download/extract instead of only jumping
/// when whole layers finish. The web/mini-program render an indeterminate bar
/// for -1. Shared by the nginx/mysql modules (their image pulls log the same
/// docker progress lines).
pub(crate) fn pull_pct(lines: &[String], status: &str) -> i64 {
    if status == "done" {
        return 100;
    }
    use std::collections::HashMap;
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

/// Snapshot of all operations (without the full log) for `list_ops`.
pub(crate) fn ops_snapshot() -> Value {
    let m = match ops().lock() {
        Ok(m) => m,
        Err(_) => return json!({ "ops": [] }),
    };
    let list: Vec<Value> = m
        .iter()
        .map(|(id, o)| {
            json!({
                "op_id": id,
                "kind": o.kind,
                "target": o.target,
                "status": o.status,
                "error": o.error,
                "result_image": o.result_image,
                "pct": pull_pct(&o.lines, &o.status),
                // The latest line gives the list a one-line progress hint.
                "last_line": o.lines.last().cloned().unwrap_or_default(),
            })
        })
        .collect();
    json!({ "ops": list })
}

pub(crate) fn op_log(op_id: &str) -> Value {
    let m = match ops().lock() {
        Ok(m) => m,
        Err(_) => return json!({ "lines": [], "status": "error", "error": "lock" }),
    };
    match m.get(op_id) {
        Some(o) => json!({
            "lines": o.lines,
            "status": o.status,
            "error": o.error,
            "result_image": o.result_image,
            "kind": o.kind,
            "target": o.target,
            "pct": pull_pct(&o.lines, &o.status),
        }),
        None => json!({ "lines": [], "status": "gone", "error": "" }),
    }
}

pub(crate) fn op_dismiss(op_id: &str) {
    if let Ok(mut m) = ops().lock() {
        m.remove(op_id);
    }
}
