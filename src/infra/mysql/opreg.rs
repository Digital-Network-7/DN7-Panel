//! Detached op registry for the MySQL module (image pull / install / switch /
//! backup) — a thin wrapper over the shared [`crate::op_registry`]. Ops attach
//! the resulting `inst_id` on success, reuse the docker image-pull progress
//! estimator, and only forget finished ops on dismiss.
use crate::op_registry::{pull_pct, Dismiss, OpRegistry};
use serde_json::{json, Value};
use std::sync::OnceLock;

pub(super) use crate::op_registry::pmsg;

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("mop", pull_pct, Dismiss::FinishedOnly))
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

pub(super) fn op_finish(op_id: &str, status: &str, error: &str, inst_id: &str) {
    reg().finish(op_id, status, error, json!({ "inst_id": inst_id }));
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
