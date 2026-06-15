//! Detached operation registry (pulls + install + create) — a thin wrapper over
//! the shared [`crate::op_registry`]. Ops here attach a `result_image` field
//! (the final clean image name on a successful pull) and use the docker
//! image-pull progress estimator.
use crate::op_registry::{Dismiss, OpRegistry};
use serde_json::{json, Value};
use std::sync::OnceLock;

pub(crate) use crate::op_registry::{pmsg, pull_pct};

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("op", pull_pct, Dismiss::Any))
}

pub(crate) fn new_op_id() -> String {
    reg().new_id()
}

pub(crate) fn op_create(op_id: &str, kind: &str, target: &str) {
    reg().create(op_id, kind, target);
}

pub(crate) fn op_push(op_id: &str, line: &str) {
    reg().push(op_id, line);
}

pub(crate) fn op_finish(op_id: &str, status: &str, error: &str, result_image: &str) {
    reg().finish(
        op_id,
        status,
        error,
        json!({ "result_image": result_image }),
    );
}

pub(crate) fn ops_snapshot() -> Value {
    reg().snapshot()
}

pub(crate) fn op_log(op_id: &str) -> Value {
    reg().log(op_id)
}

pub(crate) fn op_dismiss(op_id: &str) {
    reg().dismiss(op_id);
}

/// Whether an op with this id exists and is still running.
pub(crate) fn op_running(op_id: &str) -> bool {
    reg().running(op_id)
}
