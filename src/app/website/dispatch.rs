//! Website capability dispatch: route an authenticated capability command to
//! the right read-only projection or write-op adapter.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::{commands, tuning};

/// Run one website capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("");
    match op {
        // Read-only ops — owned by the application layer (no edge reload).
        "get_settings" => tuning::get_settings(),
        "info" => crate::infra::website::website_info().await,
        "list_sites" => Ok(json!({ "sites": crate::infra::website::sites_snapshot() })),
        "list_named_certs" => crate::infra::website::list_named_certs().await,
        "list_access" => crate::infra::website::list_access().await,
        "list_containers" => crate::infra::website::list_running_containers().await,
        "list_dirs" => {
            crate::infra::website::list_dirs(body.get("path").and_then(|v| v.as_str())).await
        }
        "list_ops" => Ok(crate::infra::website::ops_snapshot_value()),
        "op_log" => Ok(crate::infra::website::op_log_value(
            body.get("op_id").and_then(|v| v.as_str()).unwrap_or(""),
        )),
        "dismiss_op" => {
            if let Some(id) = body.get("op_id").and_then(|v| v.as_str()) {
                crate::infra::website::op_dismiss_registry(id);
            }
            Ok(json!({ "dismissed": true }))
        }
        // Write ops with their pure validation/merge in domain.
        "set_tuning" => tuning::set_tuning(body).await,
        "set_default_site" => tuning::set_default_site(body).await,
        // Reload + remaining write ops: parse the focused command, then delegate
        // execution to the infra use-case adapters.
        "reload" => {
            crate::infra::website::op_reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "setup" => crate::infra::website::op_setup(),
        "force_start" => crate::infra::website::force_start().await,
        "add_site" => crate::infra::website::op_add_site(&commands::site_form(body)?).await,
        "update_site" => crate::infra::website::op_update_site(&commands::site_form(body)?).await,
        "remove_site" => crate::infra::website::op_remove_site(&commands::remove_site(body)).await,
        "create_cert" => crate::infra::website::op_create_cert(&commands::create_cert(body)).await,
        "renew_cert" => crate::infra::website::op_renew_cert(&commands::renew_cert(body)).await,
        "delete_cert" => crate::infra::website::op_delete_cert(&commands::delete_cert(body)).await,
        "save_access" => crate::infra::website::op_save_access(&commands::save_access(body)?).await,
        "delete_access" => {
            crate::infra::website::op_delete_access(&commands::delete_access(body)).await
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
}
