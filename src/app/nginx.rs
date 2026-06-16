//! Nginx capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::nginx`), so the
//! application service layer is the single seam for the nginx capability:
//! authn/audit live in the web boundary, this entry owns op routing, and the
//! side-effecting work is delegated to the `infra::nginx` adapters (confgen /
//! filesystem / `nginx -t` + reload).
//!
//! `dispatch` is a flat one-line-per-arm routing table (the sanctioned op-table
//! exception); the per-op command construction + the settings/tuning use-cases
//! are the small helper fns below it. `set_tuning` / `set_default_site` have
//! their pure validation in `core::nginx`; the other write ops carry their
//! (infra-state-interleaved) validation inside the infra use-case body.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::contracts::nginx::{
    CreateCert, DeleteAccess, DeleteCert, RemoveSite, RenewCert, SaveAccess, SiteForm,
};

/// Run one nginx capability request. `body` is the capability JSON command
/// already authenticated/authorized by the web boundary.
pub(crate) async fn dispatch(body: &Value) -> Result<Value> {
    let op = body.get("op").and_then(|v| v.as_str()).unwrap_or("");
    match op {
        // Read-only ops — owned by the application layer (no nginx reload).
        "get_settings" => get_settings(),
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
        "set_tuning" => set_tuning(body).await,
        "set_default_site" => set_default_site(body).await,
        // Reload + remaining write ops: parse the focused command, then delegate
        // execution to the infra use-case adapters.
        "reload" => {
            crate::infra::nginx::op_reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "setup" => crate::infra::nginx::op_setup(),
        "add_site" => crate::infra::nginx::op_add_site(&site_form(body)?).await,
        "update_site" => crate::infra::nginx::op_update_site(&site_form(body)?).await,
        "remove_site" => crate::infra::nginx::op_remove_site(&remove_site(body)).await,
        "create_cert" => crate::infra::nginx::op_create_cert(&create_cert(body)).await,
        "renew_cert" => crate::infra::nginx::op_renew_cert(&renew_cert(body)).await,
        "delete_cert" => crate::infra::nginx::op_delete_cert(&delete_cert(body)).await,
        "save_access" => crate::infra::nginx::op_save_access(&save_access(body)?).await,
        "delete_access" => crate::infra::nginx::op_delete_access(&delete_access(body)).await,
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Per-op command construction (raw capability JSON → focused contracts command).
// ---------------------------------------------------------------------------

/// Read an optional string field from the request body.
fn s(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).map(str::to_string)
}

/// `add_site` / `update_site`: the full site form (serde-parsed).
fn site_form(body: &Value) -> Result<SiteForm> {
    serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))
}

/// `save_access`: the access-list form (serde-parsed).
fn save_access(body: &Value) -> Result<SaveAccess> {
    serde_json::from_value(body.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))
}

/// `remove_site`.
fn remove_site(body: &Value) -> RemoveSite {
    RemoveSite {
        site_id: s(body, "site_id"),
    }
}

/// `create_cert`.
fn create_cert(body: &Value) -> CreateCert {
    CreateCert {
        cert_mode: s(body, "cert_mode"),
        server_name: s(body, "server_name"),
        cert_pem: s(body, "cert_pem"),
        key_pem: s(body, "key_pem"),
    }
}

/// `renew_cert`.
fn renew_cert(body: &Value) -> RenewCert {
    RenewCert {
        cert_name: s(body, "cert_name"),
    }
}

/// `delete_cert`.
fn delete_cert(body: &Value) -> DeleteCert {
    DeleteCert {
        cert_name: s(body, "cert_name"),
    }
}

/// `delete_access`.
fn delete_access(body: &Value) -> DeleteAccess {
    DeleteAccess {
        access_id: s(body, "access_id"),
    }
}

// ---------------------------------------------------------------------------
// Settings / tuning use-cases. Pure validation lives in `core::nginx`;
// persistence + conf rewrite + reload are delegated to the `infra::nginx` adapter.
// ---------------------------------------------------------------------------

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

/// `set_tuning` use-case: read current tuning (infra) → validate/merge against
/// fixed bounds (domain) → persist + rewrite confs + reload (infra). The stable
/// validation code is surfaced through the transitional `ERR_CODE:` channel.
async fn set_tuning(body: &Value) -> Result<Value> {
    let input = crate::core::nginx::HttpTuningInput {
        server_names_hash_bucket_size: body
            .get("server_names_hash_bucket_size")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        gzip: body.get("gzip").and_then(|v| v.as_bool()),
        client_header_buffer_size: body
            .get("client_header_buffer_size")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        gzip_min_length: body
            .get("gzip_min_length")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        client_max_body_size: body
            .get("client_max_body_size")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        gzip_comp_level: body
            .get("gzip_comp_level")
            .and_then(|v| v.as_u64())
            .map(|n| n as u8),
        keepalive_timeout: body
            .get("keepalive_timeout")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
    };
    let cur = crate::infra::nginx::current_tuning();
    let t = crate::core::nginx::merge_http_tuning(&cur, &input)
        .map_err(|e| anyhow::anyhow!("ERR_CODE:{}", tuning_err_code(e)))?;
    crate::infra::nginx::apply_tuning(&t).await
}

/// `set_default_site` use-case: validate + build the default-site entity
/// (domain) → persist + (re)write catch-all conf + reload/rollback (infra).
async fn set_default_site(body: &Value) -> Result<Value> {
    let mode = body
        .get("default_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("404");
    let redirect_url = body
        .get("redirect_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let g = crate::core::nginx::build_default_site(mode, redirect_url)
        .map_err(|e| anyhow::anyhow!("ERR_CODE:{}", tuning_err_code(e)))?;
    crate::infra::nginx::apply_default_site(&g).await
}

/// Map a domain [`crate::core::nginx::TuningError`] to its stable frontend
/// `err.*` code, surfaced through the transitional `ERR_CODE:` channel
/// (architecture §6). This is the single place the nginx tuning/default-site
/// codes are spelled out; the domain stays free of protocol strings (§2).
fn tuning_err_code(e: crate::core::nginx::TuningError) -> &'static str {
    use crate::core::nginx::TuningError::*;
    match e {
        HashBucket => "nginx.bad_hash_bucket",
        CompLevel => "nginx.bad_comp_level",
        MinLength => "nginx.bad_min_length",
        Keepalive => "nginx.bad_keepalive",
        SizeValue => "nginx.bad_size_value",
        DefaultMode => "nginx.bad_default_mode",
        RedirectUrl => "nginx.bad_redirect_url",
    }
}
