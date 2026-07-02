//! Detached operation registry (pulls + install + create) — a thin wrapper over
//! the shared [`crate::infra::support::op_registry`]. Ops here attach a `result_image` field
//! (the final clean image name on a successful pull) and use the docker
//! image-pull progress estimator.
use crate::infra::support::op_registry::{opreg_forwarders, Dismiss, OpRegistry};
use serde_json::json;
use std::sync::OnceLock;

pub(crate) use crate::infra::support::op_registry::{pmsg, pull_pct};

fn reg() -> &'static OpRegistry {
    static R: OnceLock<OpRegistry> = OnceLock::new();
    R.get_or_init(|| OpRegistry::new("op", pull_pct, Dismiss::Any))
}

// The byte-identical forwarders (new_op_id / op_create / op_push / ops_snapshot
// / op_log / op_dismiss).
opreg_forwarders!(pub(crate) reg);

pub(crate) fn op_finish(op_id: &str, status: &str, error: &str, result_image: &str) {
    reg().finish(
        op_id,
        status,
        error,
        json!({ "result_image": result_image }),
    );
}
