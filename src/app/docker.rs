//! Docker capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::docker`), so the
//! application service layer is the single seam for the docker capability:
//! authn/audit live in the web boundary, this entry owns the use-case, and the
//! side-effecting work is delegated to the `infra::docker` adapter (bollard).
//!
//! Today this forwards to the capability's internal JSON dispatcher; the
//! op-level orchestration (validate → adapter call order → manifest writes)
//! migrates into this module incrementally, each step verified against a live
//! Docker daemon (see .kiro/steering/architecture.md §10).

use anyhow::Result;
use serde_json::Value;

/// Run one docker capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    crate::infra::docker::web_dispatch(body).await
}
