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

use anyhow::Result;
use serde_json::{json, Value};

/// Run one mysql capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    match body.get("op").and_then(|v| v.as_str()) {
        // Detached-op-registry ops — pure in-memory, no DB/Docker contact.
        Some("list_ops") => Ok(crate::infra::mysql::ops_snapshot_value()),
        Some("op_log") => Ok(crate::infra::mysql::op_log_value(
            body.get("op_id").and_then(|v| v.as_str()).unwrap_or(""),
        )),
        Some("dismiss_op") => {
            if let Some(id) = body.get("op_id").and_then(|v| v.as_str()) {
                crate::infra::mysql::op_dismiss_registry(id);
            }
            Ok(json!({ "dismissed": true }))
        }
        // Everything else: the infra dispatcher holds the authoritative op match
        // (DB/container-state-interleaved; migrated incrementally with live
        // verification — see .kiro/steering/architecture.md §10).
        _ => crate::infra::mysql::web_dispatch(body).await,
    }
}
