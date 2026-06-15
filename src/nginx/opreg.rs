//! Detached operation registry for the Nginx module (host setup + certificate
//! issuance) — a thin wrapper over the shared [`crate::op_registry`]. These ops
//! have no reliable progress percentage, so they report indeterminate.
use crate::op_registry::{indeterminate_pct, Dismiss, OpRegistry};
use serde_json::Value;
use std::sync::OnceLock;

pub(super) use crate::op_registry::pmsg;

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("nop", indeterminate_pct, Dismiss::Any))
}

pub(super) fn new_op_id() -> String {
    reg().new_id()
}

pub(super) fn op_create(op_id: &str, kind: &str, target: &str) {
    reg().create(op_id, kind, target);
}

pub(super) fn op_push(op_id: &str, line: &str) {
    reg().push(op_id, line);
}

pub(super) fn op_finish(op_id: &str, status: &str, error: &str) {
    reg().finish(op_id, status, error, serde_json::json!({}));
}

pub(super) fn ops_snapshot() -> Value {
    reg().snapshot()
}

pub(super) fn op_log(op_id: &str) -> Value {
    reg().log(op_id)
}

pub(super) fn op_dismiss(op_id: &str) {
    reg().dismiss(op_id);
}

/// Whether an op with this id exists and is still running.
pub(super) fn op_running(op_id: &str) -> bool {
    reg().running(op_id)
}
