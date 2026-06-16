//! Detached op registry for the MySQL module (image pull / install / switch /
//! backup) — a thin wrapper over the shared [`crate::infra::support::op_registry`]. Ops attach
//! the resulting `inst_id` on success, reuse the docker image-pull progress
//! estimator, and only forget finished ops on dismiss.
use crate::infra::support::op_registry::{opreg_forwarders, pull_pct, Dismiss, OpRegistry};
use serde_json::json;
use std::sync::OnceLock;

pub(super) use crate::infra::support::op_registry::pmsg;

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("mop", pull_pct, Dismiss::FinishedOnly))
}

// The byte-identical forwarders (new_op_id / op_create / op_push / ops_snapshot
// / op_log / op_dismiss).
opreg_forwarders!(pub(super) reg);

pub(super) fn op_finish(op_id: &str, status: &str, error: &str, inst_id: &str) {
    reg().finish(op_id, status, error, json!({ "inst_id": inst_id }));
}
