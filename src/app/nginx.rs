//! Nginx capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::nginx`), so the
//! application service layer is the single seam for the nginx capability:
//! authn/audit live in the web boundary, this entry owns the use-case, and the
//! side-effecting work is delegated to the `infra::nginx` adapter (confgen /
//! filesystem / `nginx -t` + reload).
//!
//! Today this forwards to the capability's internal JSON dispatcher; the
//! op-level orchestration (validate → render conf → write → reload/rollback)
//! migrates into this module incrementally, each step verified against a live
//! nginx (see .kiro/steering/architecture.md §10).

use anyhow::Result;
use serde_json::Value;

/// Run one nginx capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    crate::infra::nginx::web_dispatch(body).await
}
