//! Docker capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::docker`), so the
//! application service layer is the single enforced seam for the docker
//! capability: authn/audit live in the web boundary, this entry owns the
//! use-case, and execution is delegated to the `infra::docker` adapter (bollard).
//!
//! Docker ops carry no cleanly-extractable pure-domain rules (validation is
//! bollard/daemon-state-interleaved), so the authoritative per-op match stays
//! in the infra capability dispatcher — re-implementing it here would risk
//! mis-routing an op. See .kiro/steering/architecture.md §10.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

/// Run one docker capability request. The app layer owns parsing (into the
/// docker request DTO) and op routing; the in-memory op-registry ops are handled
/// here, and the daemon/container ops are delegated to the `infra::docker`
/// adapter cluster (which holds the authoritative per-op match + managed-service
/// guard). `is_super` carries the caller's authz level so the infra layer can
/// gate the host-escape create primitives (privileged / host network).
pub(crate) async fn dispatch(body: &Value, is_super: bool) -> Result<Value> {
    let req: crate::infra::docker::Req =
        serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad docker request: {e}"))?;
    match req.op.as_str() {
        // Detached-op-registry ops — pure in-memory, no Docker contact.
        "list_ops" => Ok(crate::infra::docker::ops_snapshot_value()),
        "op_log" => Ok(crate::infra::docker::op_log_value(
            req.op_id.as_deref().unwrap_or(""),
        )),
        "dismiss_op" => {
            if let Some(id) = req.op_id.as_deref() {
                crate::infra::docker::op_dismiss_registry(id);
            }
            Ok(json!({ "dismissed": true }))
        }
        // Daemon / container ops: the infra adapter holds the authoritative
        // match (+ the managed-service guard that must run for every op).
        _ => crate::infra::docker::run_op(&req, is_super).await,
    }
}

/// Whether `container` is privileged / host-namespaced — a `docker exec` into it
/// is effectively host root. The web layer uses this to gate the container
/// terminal on the super-admin (a non-super admin may exec into ordinary
/// containers, but not host-escape ones). Fails closed: an inspect error or a
/// missing daemon resolves to `true`.
pub(crate) async fn container_is_privileged(container: &str) -> bool {
    crate::infra::docker::container_is_privileged(container).await
}
