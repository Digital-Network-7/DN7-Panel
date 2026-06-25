//! Detached operation registry for the Nginx module (host setup + certificate
//! issuance) — a thin wrapper over the shared [`crate::infra::support::op_registry`]. These ops
//! have no reliable progress percentage, so they report indeterminate.
use crate::infra::support::op_registry::{
    indeterminate_pct, opreg_forwarders, Dismiss, OpRegistry,
};
use std::sync::OnceLock;

pub(super) use crate::infra::support::op_registry::pmsg;

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("nop", indeterminate_pct, Dismiss::Any))
}

// The byte-identical forwarders (new_op_id / op_create / op_push / ops_snapshot
// / op_log / op_dismiss).
opreg_forwarders!(pub(super) reg);

pub(super) fn op_finish(op_id: &str, status: &str, error: &str) {
    reg().finish(op_id, status, error, serde_json::json!({}));
}

/// Whether an op with this id exists and is still running.
pub(super) fn op_running(op_id: &str) -> bool {
    reg().running(op_id)
}
