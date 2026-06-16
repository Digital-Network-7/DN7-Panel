//! MySQL/MariaDB capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::mysql`), so the
//! application service layer is the single enforced seam for the mysql
//! capability: authn/audit live in the web boundary, this entry owns the
//! use-case, and execution is delegated to the `infra::mysql` adapter (bollard +
//! `mysql` client exec inside the managed container).
//!
//! MySQL ops carry no cleanly-extractable pure-domain rules (validation is
//! container/exec-state-interleaved), so the authoritative per-op match stays
//! in the infra capability dispatcher — re-implementing it here would risk
//! mis-routing an op. See .kiro/steering/architecture.md §10.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

/// Run one mysql capability request. The app layer owns parsing (into the
/// `contracts::mysql` DTO) and op routing; the in-memory op-registry ops are
/// handled here, and the DB/container ops are delegated to the `infra::mysql`
/// adapter cluster.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    let req: crate::contracts::mysql::Req =
        serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad mysql request: {e}"))?;
    match req.op.as_str() {
        // Detached-op-registry ops — pure in-memory, no DB/Docker contact.
        "list_ops" => Ok(crate::infra::mysql::ops_snapshot_value()),
        "op_log" => Ok(crate::infra::mysql::op_log_value(
            req.op_id.as_deref().unwrap_or(""),
        )),
        "dismiss_op" => {
            if let Some(id) = req.op_id.as_deref() {
                crate::infra::mysql::op_dismiss_registry(id);
            }
            Ok(json!({ "dismissed": true }))
        }
        // DB / container ops: the infra adapter holds the authoritative match.
        _ => crate::infra::mysql::run_op(&req).await,
    }
}
