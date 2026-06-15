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

use anyhow::Result;
use serde_json::Value;

/// Run one docker capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    crate::infra::docker::web_dispatch(body).await
}
