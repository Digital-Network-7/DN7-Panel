//! Nginx capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::nginx`), so the
//! application service layer is the single seam for the nginx capability:
//! authn/audit live in the web boundary, this entry owns op routing, and the
//! side-effecting work is delegated to the `infra::nginx` adapters (confgen /
//! filesystem / `nginx -t` + reload).
//!
//! Routing is kept thin: per-op command construction lives in `commands`, and
//! the settings/tuning use-cases (`get_settings`/`set_tuning`/`set_default_site`)
//! live in `tuning`. `set_tuning` / `set_default_site` have their pure
//! validation in `core::nginx`; the other write ops still carry their
//! (infra-state-interleaved) validation inside the infra use-case body, called
//! here with the parsed capability command (see .kiro/steering/architecture.md §10).

mod commands;
mod tuning;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

/// Run one nginx capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("");
    match op {
        // Read-only ops — owned by the application layer (no nginx reload).
        "get_settings" => tuning::get_settings(),
        "info" => crate::infra::nginx::nginx_info().await,
        "list_sites" => Ok(json!({ "sites": crate::infra::nginx::sites_snapshot() })),
        "list_named_certs" => crate::infra::nginx::list_named_certs().await,
        "list_access" => crate::infra::nginx::list_access().await,
        "list_containers" => crate::infra::nginx::list_running_containers().await,
        "list_dirs" => {
            crate::infra::nginx::list_dirs(body.get("path").and_then(|v| v.as_str())).await
        }
        "list_ops" => Ok(crate::infra::nginx::ops_snapshot_value()),
        "op_log" => Ok(crate::infra::nginx::op_log_value(
            body.get("op_id").and_then(|v| v.as_str()).unwrap_or(""),
        )),
        "dismiss_op" => {
            if let Some(id) = body.get("op_id").and_then(|v| v.as_str()) {
                crate::infra::nginx::op_dismiss_registry(id);
            }
            Ok(json!({ "dismissed": true }))
        }
        // Write ops with their pure validation/merge in domain.
        "set_tuning" => tuning::set_tuning(body).await,
        "set_default_site" => tuning::set_default_site(body).await,
        // Reload + remaining write ops: parse the focused command, then delegate
        // execution to the infra use-case adapters.
        "reload" => {
            crate::infra::nginx::op_reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "setup" => crate::infra::nginx::op_setup(),
        "add_site" => crate::infra::nginx::op_add_site(&commands::site_form(body)?).await,
        "update_site" => crate::infra::nginx::op_update_site(&commands::site_form(body)?).await,
        "remove_site" => crate::infra::nginx::op_remove_site(&commands::remove_site(body)).await,
        "create_cert" => crate::infra::nginx::op_create_cert(&commands::create_cert(body)).await,
        "renew_cert" => crate::infra::nginx::op_renew_cert(&commands::renew_cert(body)).await,
        "delete_cert" => crate::infra::nginx::op_delete_cert(&commands::delete_cert(body)).await,
        "save_access" => crate::infra::nginx::op_save_access(&commands::save_access(body)?).await,
        "delete_access" => {
            crate::infra::nginx::op_delete_access(&commands::delete_access(body)).await
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
}
