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
use serde_json::{json, Value};

/// Run one nginx capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
///
/// Ops are migrated off the infra dispatcher into explicit use-cases here one at
/// a time (each verified against a live nginx); the rest still forward to the
/// capability's internal JSON dispatcher.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    match body.get("op").and_then(|v| v.as_str()) {
        // Read-only ops — owned by the application layer (no nginx reload).
        Some("get_settings") => get_settings(),
        Some("info") => crate::infra::nginx::nginx_info().await,
        Some("list_sites") => Ok(json!({ "sites": crate::infra::nginx::sites_snapshot() })),
        Some("list_named_certs") => crate::infra::nginx::list_named_certs().await,
        Some("list_access") => crate::infra::nginx::list_access().await,
        Some("list_containers") => crate::infra::nginx::list_running_containers().await,
        Some("list_dirs") => {
            crate::infra::nginx::list_dirs(body.get("path").and_then(|v| v.as_str())).await
        }
        Some("list_ops") => Ok(crate::infra::nginx::ops_snapshot_value()),
        Some("op_log") => Ok(crate::infra::nginx::op_log_value(
            body.get("op_id").and_then(|v| v.as_str()).unwrap_or(""),
        )),
        _ => crate::infra::nginx::web_dispatch(body).await,
    }
}

/// `get_settings` use-case: project the persisted website-settings state
/// (default-site behaviour + http/server tuning + configured flags) into the
/// console response. Orchestration lives here; the raw read is delegated to the
/// `infra::nginx` adapter.
fn get_settings() -> Result<Value> {
    let (g, t, configured, tuning_configured) = crate::infra::nginx::web_settings_state();
    Ok(json!({
        "default_site": { "mode": g.default_site.mode, "redirect_url": g.default_site.redirect_url },
        "configured": configured,
        "tuning": {
            "server_names_hash_bucket_size": t.server_names_hash_bucket_size,
            "gzip": t.gzip,
            "client_header_buffer_size": t.client_header_buffer_size,
            "gzip_min_length": t.gzip_min_length,
            "client_max_body_size": t.client_max_body_size,
            "gzip_comp_level": t.gzip_comp_level,
            "keepalive_timeout": t.keepalive_timeout,
        },
        "tuning_configured": tuning_configured,
    }))
}
