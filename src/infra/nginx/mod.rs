//! Panel-side Nginx management (host-only).
//!
//! Manages the **host's own nginx**: DN7 Panel ensures nginx is installed (via
//! the system package manager) and only ever writes its own
//! `dn7-<id>.conf` files into `/etc/nginx/conf.d`, never touching the user's
//! existing configs, reloading via `nginx -s reload`. Certs and static webroots
//! live under the panel state dir (`/var/dn7/panel/.../nginx/`).
//!
//! Pure assembly: the app-facing adapters + shared `Layout`/error helpers live
//! in `api`; each capability area is a submodule (sites/certs/access/confgen/…).
//! All shared entities are re-exported from `core::nginx` / `contracts::nginx`
//! so the submodules reference `Site`/`Layout`/… via `use super::*` unchanged.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;

// Per-op typed commands (from the contracts layer) + persisted domain entities
// (from core::nginx), re-exported so the nginx submodules reference them via
// `use super::*` unchanged.
pub(crate) use crate::contracts::nginx::{
    CreateCert, DeleteAccess, DeleteCert, RemoveSite, RenewCert, SaveAccess, SiteForm,
};
use crate::core::nginx::{
    norm_scheme, primary_host, valid_access_name, valid_auth_username, valid_cert_name,
    valid_client_address, valid_container_name, valid_host_token, valid_location_path, valid_port,
    valid_root_segment, valid_server_name, NginxError,
};
pub(crate) use crate::core::nginx::{
    AccessClient, AccessList, AccessUser, HttpTuning, Location, Site, WebGlobal,
};

mod access;
mod api;
mod certs;
mod confgen;
mod detect;
mod htpasswd;
mod opreg;
mod setup;
mod sites;
mod state;
mod store;
mod upload;

use access::*;
use certs::*;
use confgen::*;
use detect::*;
use htpasswd::*;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};
use setup::*;
use state::*;
use store::*;

// Public surface used by the application layer (`app::nginx`) + other infra
// adapters.
pub(crate) use access::list_access;
pub(crate) use access::{apply_default_site, apply_tuning, current_tuning};
pub(crate) use api::*;
pub(crate) use certs::list_named_certs;
pub(crate) use detect::{list_dirs, list_running_containers, nginx_info};
pub(crate) use sites::*;
pub use upload::*;

#[cfg(test)]
mod tests;
