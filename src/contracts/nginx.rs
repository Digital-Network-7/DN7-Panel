//! Nginx capability — external request DTO (the wire protocol the console
//! sends). Owned here (the contracts layer), parsed by `app::nginx`, and read
//! by the `infra::nginx` adapters. Fields are `pub(crate)` so both layers can
//! read them; the few that are routed/handled at the app boundary (op name,
//! op_id, path, tuning, default-site) are still deserialized here so the whole
//! request lands in one struct.
//!
//! `Location` / `AccessClient` are domain entities (contracts may reference
//! domain base types); `AccessUserInput` is transport-only and lives here.

use crate::domain::nginx::{AccessClient, Location};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) id: i64,
    // `op` / `op_id` are routed at the app boundary (app::nginx); kept here so
    // the rest of the request still deserializes into one struct.
    #[allow(dead_code)]
    pub(crate) op: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) op_id: Option<String>,
    #[serde(default)]
    pub(crate) site_id: Option<String>,
    // add_site fields
    #[serde(default)]
    pub(crate) server_name: Option<String>,
    #[serde(default)]
    pub(crate) kind: Option<String>, // "proxy_host" | "proxy_container" | "static"
    #[serde(default)]
    pub(crate) target_url: Option<String>, // proxy_host
    #[serde(default)]
    pub(crate) container: Option<String>, // proxy_container
    #[serde(default)]
    pub(crate) container_port: Option<i64>, // proxy_container
    #[serde(default)]
    pub(crate) root: Option<String>, // static (subdir name)
    #[serde(default)]
    pub(crate) local_root: Option<String>, // static (existing absolute host dir)
    #[serde(default)]
    #[allow(dead_code)] // read at the app boundary (app::nginx list_dirs), not in infra
    pub(crate) path: Option<String>, // list_dirs: directory to enumerate
    // http/server tuning (set_tuning) — read at the app boundary (app::nginx
    // set_tuning), deserialized here only to accept the wire fields.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) server_names_hash_bucket_size: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) gzip: Option<bool>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) client_header_buffer_size: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) gzip_min_length: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) client_max_body_size: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) gzip_comp_level: Option<u8>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) keepalive_timeout: Option<u32>,
    #[serde(default)]
    pub(crate) ssl: Option<bool>,
    #[serde(default)]
    pub(crate) cert_mode: Option<String>, // "self" | "le" | "manual"
    #[serde(default)]
    pub(crate) cert_pem: Option<String>, // manual
    #[serde(default)]
    pub(crate) key_pem: Option<String>, // manual
    #[serde(default)]
    pub(crate) cert_name: Option<String>, // standalone cert name (create_cert / reference)
    // New add-site fields (NPM-style options + custom path rules).
    #[serde(default)]
    pub(crate) scheme: Option<String>, // proxy upstream scheme "http"|"https"
    #[serde(default)]
    pub(crate) cache: Option<bool>,
    #[serde(default)]
    pub(crate) block_attacks: Option<bool>,
    #[serde(default)]
    pub(crate) websockets: Option<bool>,
    #[serde(default)]
    pub(crate) force_ssl: Option<bool>,
    #[serde(default)]
    pub(crate) http2: Option<bool>,
    #[serde(default)]
    pub(crate) hsts: Option<bool>,
    #[serde(default)]
    pub(crate) hsts_sub: Option<bool>,
    #[serde(default)]
    pub(crate) trust_proxy: Option<bool>,
    #[serde(default)]
    pub(crate) trust_proxy_cidrs: Option<String>, // explicit trusted front-proxy IP/CIDR list
    #[serde(default)]
    pub(crate) locations: Option<Vec<Location>>, // custom path rules
    #[serde(default)]
    pub(crate) extra_conf: Option<String>, // raw nginx directives injected into the server block
    // Access list reference on a site (empty = public/none).
    #[serde(default)]
    pub(crate) access_id: Option<String>,
    // Access list management (create/update/delete).
    #[serde(default)]
    pub(crate) name: Option<String>, // access list display name
    #[serde(default)]
    pub(crate) satisfy: Option<String>, // "any" | "all"
    #[serde(default)]
    pub(crate) pass_auth: Option<bool>, // forward Authorization header upstream
    #[serde(default)]
    pub(crate) users: Option<Vec<AccessUserInput>>, // basic-auth users (username + optional new pw)
    #[serde(default)]
    pub(crate) clients: Option<Vec<AccessClient>>, // allow/deny IP rules
    // Default-site (Settings) configuration — read at the app boundary
    // (app::nginx set_default_site), deserialized here only to accept the wire.
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) default_mode: Option<String>, // "404" | "welcome" | "444" | "redirect"
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) redirect_url: Option<String>,
}

/// New/changed access-list user input from the client (password is plaintext,
/// optional on edit — empty keeps the existing hash).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct AccessUserInput {
    #[serde(default)]
    pub(crate) username: String,
    #[serde(default)]
    pub(crate) password: String,
}

// ---------------------------------------------------------------------------
// Per-op command model (incremental): focused typed inputs the app builds from
// the request and hands to the infra adapters — so a write op receives only its
// own fields, not the whole `Req`. Migrated one op at a time.
// ---------------------------------------------------------------------------

/// `remove_site`: delete a managed site by id.
pub(crate) struct RemoveSite {
    pub(crate) site_id: Option<String>,
}
