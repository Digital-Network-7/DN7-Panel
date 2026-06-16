//! Panel-side Nginx management (host-only).
//!
//! Manages the **host's own nginx**: DN7 Panel ensures nginx is installed (via
//! the system package manager) and only ever writes its own
//! `dn7-<id>.conf` files into `/etc/nginx/conf.d`, never touching the user's
//! existing configs, reloading via `nginx -s reload`. Certs and static webroots
//! live under the panel state dir (`/var/dn7/panel/.../nginx/`).
//!
//! Long operations (install / Let's Encrypt issuance) run **detached** in a
//! process-global op registry so they survive client reconnects.
//!
//! Sites are form-defined (domain + target), never raw nginx config, so there's
//! no config-injection surface. Each site is generated from a small manifest
//! (`sites.json`) into a single conf file and validated with `nginx -t` before
//! it's kept (otherwise it's rolled back).
//!
//! Requests (client -> panel):
//!   {"id","op":"info"}
//!   {"id","op":"setup"}                       -> {op_id} (detached install)
//!   {"id","op":"list_sites"}
//!   {"id","op":"add_site", <site fields>}     -> {site} or {op_id} (LE issuance)
//!   {"id","op":"remove_site","site_id"}
//!   {"id","op":"reload"}
//!   {"id","op":"list_containers"}             -> running containers (proxy menu)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;

/// Per-op typed commands the app builds and hands to the infra adapters (so an
/// op receives only its own fields, not the whole `Req`). Re-exported for the
/// nginx submodules' `use super::*`.
pub(crate) use crate::contracts::nginx::RemoveSite;
/// The nginx capability request DTO now lives in the `contracts` layer (the
/// external-protocol source of truth); re-exported here so the nginx submodules
/// keep referring to `Req` via `use super::*` unchanged.
pub(crate) use crate::contracts::nginx::Req;
pub(crate) use crate::contracts::nginx::{DeleteAccess, DeleteCert, RenewCert};

/// A managed site (domain entity), re-exported from `domain::nginx` so the
/// nginx submodules keep referring to `Site`/`Location` unchanged.
pub(crate) use crate::domain::nginx::{Location, Site};

// ---------------------------------------------------------------------------
// Access lists (NPM-style): HTTP Basic Auth users + IP allow/deny rules, with
// "satisfy any/all" and an option to forward (or strip) the Authorization
// header upstream. Assigned to proxy hosts by id.
// ---------------------------------------------------------------------------

/// Access-list domain entities (`AccessList`/`AccessUser`/`AccessClient`),
/// re-exported from `domain::nginx` so the nginx submodules reference them
/// unchanged. `AccessUserInput` (transport input) lives in `contracts::nginx`.
pub(crate) use crate::domain::nginx::{AccessClient, AccessList, AccessUser};

/// Default-site / global-settings / http-tuning domain entities, re-exported
/// from `domain::nginx` so the nginx submodules reference them unchanged.
pub(crate) use crate::domain::nginx::{HttpTuning, WebGlobal};

/// A custom path rule (NPM-style "custom location"): forward a path prefix to a
// ---------------------------------------------------------------------------
// Detached operation registry (setup + cert issuance) — see `opreg` submodule.
// ---------------------------------------------------------------------------
mod opreg;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};
mod certparse;
use crate::domain::nginx::{
    norm_scheme, primary_host, valid_access_name, valid_auth_username, valid_cert_name,
    valid_client_address, valid_container_name, valid_host_token, valid_location_path, valid_port,
    valid_root_segment, valid_server_name,
};

// ---------------------------------------------------------------------------
// Operation submodules (see .kiro/steering/code-structure.md). All shared
// structs (Req/Site/Layout/...) stay in this parent so descendant modules can
// read their private fields via `use super::*`.
// ---------------------------------------------------------------------------
mod access;
mod certs;
mod certs_named;
mod confgen;
mod detect;
mod htpasswd;
mod setup;
mod sites;
mod state;
mod store;
mod upload;
use access::*;
use certs::*;
use certs_named::*;
use confgen::*;
use detect::*;
use htpasswd::*;
use setup::*;
pub use sites::*;
use state::*;
use store::*;

/// Read-only use-case accessors exposed for `app::nginx`. The application layer
/// owns op routing (`info`/`list_access`/`list_named_certs`/`list_containers`/
/// `list_dirs`); these delegate to the infra adapters that do the actual read.
pub(crate) use access::list_access;
pub(crate) use access::{apply_default_site, apply_tuning, current_tuning};
pub(crate) use certs_named::list_named_certs;
pub(crate) use detect::{list_dirs, list_running_containers, nginx_info};
pub use upload::*;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// App-facing per-op adapters. The application layer (`app::nginx`) owns op
// routing and parses the capability `Req`; these expose the infra use-case
// bodies it delegates each (side-effecting) write op to. Read ops use the
// dedicated read accessors above.
// ---------------------------------------------------------------------------

/// Read-only website-settings snapshot for the `get_settings` use-case (owned by
/// `app::nginx`): persisted default-site + http tuning, plus whether each has
/// been configured. Pure read — no nginx reload.
pub(crate) fn web_settings_state() -> (
    crate::domain::nginx::WebGlobal,
    crate::domain::nginx::HttpTuning,
    bool,
    bool,
) {
    (
        load_webglobal(),
        load_tuning_opt().unwrap_or_default(),
        websettings_file().exists(),
        webtuning_file().exists(),
    )
}

/// Read-only managed-site list for the `list_sites` use-case (owned by
/// `app::nginx`). Pure read — manifests only, no nginx contact.
pub(crate) fn sites_snapshot() -> Vec<crate::domain::nginx::Site> {
    load_sites()
}

/// Detached-op-registry read projections for the `app::nginx` `list_ops` /
/// `op_log` use-cases (the registry's own fns are `pub(super)`).
pub(crate) fn ops_snapshot_value() -> Value {
    ops_snapshot()
}
pub(crate) fn op_log_value(op_id: &str) -> Value {
    op_log(op_id)
}

pub(crate) fn op_setup(req: &Req) -> Result<Value> {
    start_setup(req)
}
pub(crate) async fn op_add_site(req: &Req) -> Result<Value> {
    add_site(req).await
}
pub(crate) async fn op_update_site(req: &Req) -> Result<Value> {
    update_site(req).await
}
pub(crate) async fn op_remove_site(cmd: &RemoveSite) -> Result<Value> {
    remove_site(cmd).await
}
pub(crate) async fn op_create_cert(req: &Req) -> Result<Value> {
    create_cert(req).await
}
pub(crate) async fn op_renew_cert(cmd: &RenewCert) -> Result<Value> {
    renew_cert(cmd).await
}
pub(crate) async fn op_delete_cert(cmd: &DeleteCert) -> Result<Value> {
    delete_cert(cmd).await
}
pub(crate) async fn op_save_access(req: &Req) -> Result<Value> {
    save_access_op(req).await
}
pub(crate) async fn op_delete_access(cmd: &DeleteAccess) -> Result<Value> {
    delete_access_op(cmd).await
}
pub(crate) async fn op_reload() -> Result<()> {
    reload().await
}
pub(crate) fn op_dismiss_registry(op_id: &str) {
    op_dismiss(op_id);
}

// ---------------------------------------------------------------------------
// Sites: add / remove / generate config / reload.
// ---------------------------------------------------------------------------

/// Where generated conf files live, and the paths the running host nginx reads
/// certs/webroots from. Host-only: nginx reads the same on-disk paths we write.
#[derive(Clone)]
pub(crate) struct Layout {
    confd: std::path::PathBuf, // where we WRITE conf files (/etc/nginx/conf.d)
    cert_ref: String,          // dir nginx READS certs from (== cert_store)
    www_ref: String,           // dir nginx READS webroots from (== www_store)
    cert_store: std::path::PathBuf, // where we WRITE cert files
    www_store: std::path::PathBuf, // where we WRITE webroots
}

fn layout() -> Result<Layout> {
    if !is_setup() {
        return Err(anyhow!("ERR_CODE:nginx.not_setup"));
    }
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    ensure_shared_conf();
    Ok(Layout {
        confd: std::path::PathBuf::from(HOST_CONFD),
        cert_ref: certs_dir().display().to_string(),
        www_ref: www_dir().display().to_string(),
        cert_store: certs_dir(),
        www_store: www_dir(),
    })
}

/// Write the shared http-context `map` once, so proxied sites can set the
/// WebSocket `Connection` header correctly: a normal request → `close`, a real
/// upgrade → `upgrade`. (Hardcoding `Connection: upgrade` on every request, as
/// older builds did, makes some backends abort plain HTTP requests, which the
/// browser surfaces as ERR_EMPTY_RESPONSE.) Named `00-` so it loads first and
/// isn't matched by the `dn7-<id>.conf` orphan cleanup.
fn ensure_shared_conf() {
    let path = std::path::Path::new(HOST_CONFD).join("00-dn7-maps.conf");
    let body = "map $http_upgrade $dn7_conn_upgrade {\n    default upgrade;\n    '' close;\n}\n\n\
                map $http_x_forwarded_proto $dn7_fwd_proto {\n    default $http_x_forwarded_proto;\n    '' $scheme;\n}\n";
    if std::fs::read_to_string(&path).ok().as_deref() != Some(body) {
        let _ = std::fs::create_dir_all(HOST_CONFD);
        let _ = std::fs::write(&path, body);
    }
}

fn conf_path(lo: &Layout, site_id: &str) -> std::path::PathBuf {
    lo.confd.join(format!("dn7-{site_id}.conf"))
}
