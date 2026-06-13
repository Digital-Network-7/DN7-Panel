//! Detached op registry for the MySQL module (image pull / install / switch /
//! backup). Mirrors the docker + nginx registries; progress percent reuses the
//! docker image-pull estimator. Split out to keep the parent module focused.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

#[derive(Clone)]
struct OpState {
    kind: String,   // "install" | "switch"
    target: String, // instance id
    status: String, // "running" | "done" | "error"
    error: String,
    inst_id: String, // resulting instance id on success
    lines: Vec<String>,
}

fn ops() -> &'static Mutex<HashMap<String, OpState>> {
    static OPS: OnceLock<Mutex<HashMap<String, OpState>>> = OnceLock::new();
    OPS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn new_op_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("mop{}", N.fetch_add(1, Ordering::Relaxed))
}

pub(super) fn op_create(op_id: &str, kind: &str, target: &str) {
    if let Ok(mut m) = ops().lock() {
        m.insert(
            op_id.to_string(),
            OpState {
                kind: kind.to_string(),
                target: target.to_string(),
                status: "running".to_string(),
                error: String::new(),
                inst_id: String::new(),
                lines: Vec::new(),
            },
        );
    }
}

/// Build a localizable progress line for the op log: a sentinel-delimited
/// `MSG` record the web console maps to `msg.<code>` (positional `{0}`, `{1}`…
/// args). An arg prefixed with `@` is itself a translation key resolved on the
/// client. Plain command output is pushed verbatim and rendered as-is.
pub(super) fn pmsg(code: &str, args: &[&str]) -> String {
    let mut s = format!("\u{1e}MSG\u{1e}{code}");
    for a in args {
        s.push('\u{1e}');
        s.push_str(a);
    }
    s
}

pub(super) fn op_push(op_id: &str, line: &str) {
    if line.is_empty() {
        return;
    }
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.lines.push(line.to_string());
            let len = o.lines.len();
            if len > 400 {
                o.lines.drain(0..len - 400);
            }
        }
    }
}

pub(super) fn op_finish(op_id: &str, status: &str, error: &str, inst_id: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.status = status.to_string();
            o.error = error.to_string();
            o.inst_id = inst_id.to_string();
        }
    }
}

/// Estimate 0..100 progress from install/backup image-pull log lines (shared
/// with the docker module — same phase-weighted logic). Returns -1 when
/// indeterminate.
fn pull_pct(lines: &[String], status: &str) -> i64 {
    crate::docker::pull_pct(lines, status)
}

pub(super) fn ops_snapshot() -> Value {
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
                "inst_id": o.inst_id,
                "pct": pull_pct(&o.lines, &o.status),
                "last_line": o.lines.last().cloned().unwrap_or_default(),
            })
        })
        .collect();
    json!({ "ops": list })
}

pub(super) fn op_log(op_id: &str) -> Value {
    let m = match ops().lock() {
        Ok(m) => m,
        Err(_) => return json!({ "lines": [], "status": "error", "error": "lock" }),
    };
    match m.get(op_id) {
        Some(o) => json!({
            "lines": o.lines,
            "status": o.status,
            "error": o.error,
            "inst_id": o.inst_id,
            "kind": o.kind,
            "target": o.target,
            "pct": pull_pct(&o.lines, &o.status),
        }),
        None => json!({ "lines": [], "status": "gone", "error": "" }),
    }
}

pub(super) fn op_dismiss(op_id: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get(op_id) {
            // Only forget finished ops; a running op stays.
            if o.status != "running" {
                m.remove(op_id);
            }
        }
    }
}
