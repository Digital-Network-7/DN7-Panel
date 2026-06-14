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

#[derive(Debug, Deserialize)]
pub(crate) struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    id: i64,
    op: String,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    site_id: Option<String>,
    // add_site fields
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    kind: Option<String>, // "proxy_host" | "proxy_container" | "static"
    #[serde(default)]
    target_url: Option<String>, // proxy_host
    #[serde(default)]
    container: Option<String>, // proxy_container
    #[serde(default)]
    container_port: Option<i64>, // proxy_container
    #[serde(default)]
    root: Option<String>, // static (subdir name)
    #[serde(default)]
    local_root: Option<String>, // static (existing absolute host dir)
    #[serde(default)]
    path: Option<String>, // list_dirs: directory to enumerate
    // http/server tuning (set_tuning).
    #[serde(default)]
    server_names_hash_bucket_size: Option<u32>,
    #[serde(default)]
    gzip: Option<bool>,
    #[serde(default)]
    client_header_buffer_size: Option<String>,
    #[serde(default)]
    gzip_min_length: Option<u32>,
    #[serde(default)]
    client_max_body_size: Option<String>,
    #[serde(default)]
    gzip_comp_level: Option<u8>,
    #[serde(default)]
    keepalive_timeout: Option<u32>,
    #[serde(default)]
    ssl: Option<bool>,
    #[serde(default)]
    cert_mode: Option<String>, // "self" | "le" | "manual"
    #[serde(default)]
    cert_pem: Option<String>, // manual
    #[serde(default)]
    key_pem: Option<String>, // manual
    #[serde(default)]
    cert_name: Option<String>, // standalone cert name (create_cert / reference)
    // New add-site fields (NPM-style options + custom path rules).
    #[serde(default)]
    scheme: Option<String>, // proxy upstream scheme "http"|"https"
    #[serde(default)]
    cache: Option<bool>,
    #[serde(default)]
    block_attacks: Option<bool>,
    #[serde(default)]
    websockets: Option<bool>,
    #[serde(default)]
    force_ssl: Option<bool>,
    #[serde(default)]
    http2: Option<bool>,
    #[serde(default)]
    hsts: Option<bool>,
    #[serde(default)]
    hsts_sub: Option<bool>,
    #[serde(default)]
    trust_proxy: Option<bool>,
    #[serde(default)]
    locations: Option<Vec<Location>>, // custom path rules
    #[serde(default)]
    extra_conf: Option<String>, // raw nginx directives injected into the server block
    // Access list reference on a site (empty = public/none).
    #[serde(default)]
    access_id: Option<String>,
    // Access list management (create/update/delete).
    #[serde(default)]
    name: Option<String>, // access list display name
    #[serde(default)]
    satisfy: Option<String>, // "any" | "all"
    #[serde(default)]
    pass_auth: Option<bool>, // forward Authorization header upstream
    #[serde(default)]
    users: Option<Vec<AccessUserInput>>, // basic-auth users (username + optional new password)
    #[serde(default)]
    clients: Option<Vec<AccessClient>>, // allow/deny IP rules
    // Default-site (Settings) configuration.
    #[serde(default)]
    default_mode: Option<String>, // "404" | "welcome" | "444" | "redirect"
    #[serde(default)]
    redirect_url: Option<String>,
}

/// A managed site, persisted in the manifest and regenerated into one conf file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Site {
    id: String,
    server_name: String,
    kind: String,
    #[serde(default)]
    target_url: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    container_port: i64,
    #[serde(default)]
    root: String,
    /// Static site served from an existing absolute host directory (instead of
    /// the panel-managed `<www>/<root>` upload dir). Empty == upload mode.
    #[serde(default)]
    local_root: String,
    #[serde(default)]
    ssl: bool,
    #[serde(default)]
    cert_mode: String,
    /// When set, this site uses a standalone named cert from the cert manifest
    /// instead of a per-site `<id>.crt/.key`. Empty means per-site (legacy).
    #[serde(default)]
    cert_name: String,
    /// Upstream scheme for proxy kinds ("http" | "https"). Empty == http.
    #[serde(default)]
    scheme: String,
    /// Behaviour toggles (NPM-style): long-cache static assets, block common
    /// exploit patterns, and enable WebSocket upgrade headers on proxies.
    #[serde(default)]
    cache: bool,
    #[serde(default)]
    block_attacks: bool,
    #[serde(default)]
    websockets: bool,
    /// HTTPS feature toggles. `force_ssl` (HTTP→HTTPS redirect) and `http2`
    /// default on for backward compatibility; the rest default off.
    #[serde(default = "default_true")]
    force_ssl: bool,
    #[serde(default = "default_true")]
    http2: bool,
    #[serde(default)]
    hsts: bool,
    #[serde(default)]
    hsts_sub: bool,
    #[serde(default)]
    trust_proxy: bool,
    /// Extra path rules layered on top of the main location (NPM "custom
    /// locations"): each forwards a path prefix to a host[:port].
    #[serde(default)]
    locations: Vec<Location>,
    /// Raw nginx directives, injected verbatim into the serving server block(s).
    /// Validated by `nginx -t` on save (invalid input rolls back).
    #[serde(default)]
    extra_conf: String,
    /// Access list id controlling this site (HTTP Basic Auth + IP allow/deny).
    /// Empty == publicly accessible.
    #[serde(default)]
    access_id: String,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Access lists (NPM-style): HTTP Basic Auth users + IP allow/deny rules, with
// "satisfy any/all" and an option to forward (or strip) the Authorization
// header upstream. Assigned to proxy hosts by id.
// ---------------------------------------------------------------------------

/// A stored access list. Passwords are kept only as nginx-htpasswd hashes
/// (`{SHA}…`), never in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessList {
    id: String,
    name: String,
    /// "any" | "all" — how auth and IP rules combine (nginx `satisfy`).
    #[serde(default)]
    satisfy: String,
    /// Forward the client's Authorization header to the upstream (else strip).
    #[serde(default)]
    pass_auth: bool,
    #[serde(default)]
    users: Vec<AccessUser>,
    #[serde(default)]
    clients: Vec<AccessClient>,
}

/// A basic-auth credential: the username and its precomputed htpasswd hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessUser {
    username: String,
    /// nginx-compatible hash, e.g. `{SHA}base64(sha1(password))`.
    #[serde(default)]
    hash: String,
}

/// An allow/deny rule against a client address (IP, CIDR, or "all").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AccessClient {
    /// "allow" | "deny".
    directive: String,
    /// IP / CIDR / "all".
    address: String,
}

/// New/changed user input from the client (password is plaintext, optional on
/// edit — empty keeps the existing hash).
#[derive(Debug, Clone, Deserialize, Default)]
pub(crate) struct AccessUserInput {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Default-site behaviour for requests matching no managed server_name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DefaultSite {
    /// "404" | "welcome" | "444" | "redirect".
    mode: String,
    #[serde(default)]
    redirect_url: String,
}

impl Default for DefaultSite {
    fn default() -> Self {
        DefaultSite {
            mode: "404".to_string(),
            redirect_url: String::new(),
        }
    }
}

/// Global website settings (persisted in `websettings.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct WebGlobal {
    #[serde(default)]
    default_site: DefaultSite,
}

/// nginx http/server tuning knobs (persisted in `webtuning.json`). Values
/// mirror nginx's own defaults. The server-context ones are injected into each
/// managed site's server block (so they override per-site without clashing with
/// the distro nginx.conf's http-level directives); `server_names_hash_bucket_size`
/// is http-only and written to a guarded http include.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HttpTuning {
    #[serde(default = "d_snhbs")]
    server_names_hash_bucket_size: u32,
    #[serde(default = "d_gzip_on")]
    gzip: bool,
    #[serde(default = "d_ghdr")]
    client_header_buffer_size: String,
    #[serde(default = "d_gmin")]
    gzip_min_length: u32,
    #[serde(default = "d_cmbs")]
    client_max_body_size: String,
    #[serde(default = "d_gcl")]
    gzip_comp_level: u8,
    #[serde(default = "d_kat")]
    keepalive_timeout: u32,
}
fn d_snhbs() -> u32 {
    64
}
fn d_ghdr() -> String {
    "32k".to_string()
}
fn d_gmin() -> u32 {
    20
}
fn d_cmbs() -> String {
    "50m".to_string()
}
fn d_gcl() -> u8 {
    1
}
fn d_kat() -> u32 {
    60
}
fn d_gzip_on() -> bool {
    true
}
impl Default for HttpTuning {
    fn default() -> Self {
        HttpTuning {
            server_names_hash_bucket_size: d_snhbs(),
            gzip: true,
            client_header_buffer_size: d_ghdr(),
            gzip_min_length: d_gmin(),
            client_max_body_size: d_cmbs(),
            gzip_comp_level: d_gcl(),
            keepalive_timeout: d_kat(),
        }
    }
}

/// A custom path rule (NPM-style "custom location"): forward a path prefix to a
/// host[:port] over http/https. Form-driven (no raw nginx config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct Location {
    /// The location prefix, e.g. "/api". Must start with '/'.
    path: String,
    /// Upstream scheme: "http" | "https". Empty == http.
    #[serde(default)]
    scheme: String,
    /// Upstream host[:port].
    #[serde(default)]
    target: String,
    /// Enable WebSocket upgrade headers for this path.
    #[serde(default)]
    websockets: bool,
    /// Upstream kind: "host" (target host:port) | "container" (docker
    /// container). Empty == host (backward compatible).
    #[serde(default)]
    kind: String,
    /// Docker container name (when `kind == "container"`).
    #[serde(default)]
    container: String,
    /// Container port to proxy to (when `kind == "container"`).
    #[serde(default)]
    container_port: i64,
}

// ---------------------------------------------------------------------------
// Detached operation registry (setup + cert issuance) — see `opreg` submodule.
// ---------------------------------------------------------------------------
mod opreg;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};
mod certparse;
mod validate;
use validate::{
    norm_scheme, primary_host, valid_access_name, valid_auth_username, valid_cert_name,
    valid_client_address, valid_container_name, valid_host_token, valid_location_path, valid_port,
    valid_redirect_url, valid_root_segment, valid_server_name,
};

// ---------------------------------------------------------------------------
// State directory layout (persisted under the panel runtime dir).
//
//   <base>/nginx/setup_done    marker that host nginx setup completed
//   <base>/nginx/sites.json    the site manifest
//   <base>/nginx/certs/        per-site + named certs (nginx reads from here)
//   <base>/nginx/www/          static webroots (nginx reads from here)
//
// Generated conf files go directly into the host's /etc/nginx/conf.d.
// ---------------------------------------------------------------------------

fn base_dir() -> std::path::PathBuf {
    crate::paths::default_base_dir().join("nginx")
}
fn setup_marker() -> std::path::PathBuf {
    base_dir().join("setup_done")
}
fn sites_file() -> std::path::PathBuf {
    base_dir().join("sites.json")
}
fn certs_dir() -> std::path::PathBuf {
    base_dir().join("certs")
}
fn www_dir() -> std::path::PathBuf {
    base_dir().join("www")
}

/// Host nginx config drop-in directory.
const HOST_CONFD: &str = "/etc/nginx/conf.d";

/// Where we write HTTP Basic Auth htpasswd files. This MUST live under
/// `/etc/nginx` (not the panel's private `/var/dn7/...` tree): the nginx
/// *worker* opens `auth_basic_user_file` at request time as its run-user
/// (www-data / nginx), so the file and every parent directory must be
/// traversable by that account — and on SELinux systems the file needs an
/// nginx-readable context, which `/etc/nginx/*` already carries. Keeping it
/// under the panel dir made the worker hit EACCES and return 500 for every
/// request (correct password or not).
const HOST_ACCESS_DIR: &str = "/etc/nginx/dn7-access";

/// Whether host nginx setup has been completed (marker file present).
fn is_setup() -> bool {
    setup_marker().exists()
}

fn mark_setup() -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(setup_marker(), "host")?;
    Ok(())
}

fn load_sites() -> Vec<Site> {
    std::fs::read_to_string(sites_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<Site>>(&s).ok())
        .unwrap_or_default()
}

fn save_sites(sites: &[Site]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(sites_file(), serde_json::to_string_pretty(sites)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone named-certificate store.
//
// Certs can be created independently of any site (manifest `certs.json`) and
// then referenced by one or more sites. Each named cert is stored as
//   <cert_store>/cert-<name>.crt   and   cert-<name>.key
// so a site that references it just points its conf at those files.
// ---------------------------------------------------------------------------

/// A standalone, named certificate. The PEM files live in the cert store; this
/// manifest just records its name, the domain it was issued for, and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NamedCert {
    name: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    cert_mode: String, // "self" | "le" | "manual"
}

fn certs_manifest_file() -> std::path::PathBuf {
    base_dir().join("certs.json")
}

fn load_named_certs() -> Vec<NamedCert> {
    std::fs::read_to_string(certs_manifest_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<NamedCert>>(&s).ok())
        .unwrap_or_default()
}

fn save_named_certs(certs: &[NamedCert]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(certs_manifest_file(), serde_json::to_string_pretty(certs)?)?;
    Ok(())
}

fn named_crt_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.crt"))
}
fn named_key_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.key"))
}
/// Derive a filesystem-safe cert manifest key from a domain. Certs are keyed by
/// (unique) domain now — there's no separate user-chosen name. `*` (wildcard)
/// is replaced so the result stays a valid cert name / filename token.
fn cert_name_from_domain(domain: &str) -> String {
    domain
        .trim()
        .to_ascii_lowercase()
        .replace('*', "_wildcard_")
        .chars()
        .take(64)
        .collect()
}

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
mod setup;
mod sites;
mod store;
mod upload;
use access::*;
use certs::*;
use certs_named::*;
use confgen::*;
use detect::*;
use setup::*;
pub use sites::*;
use store::*;
pub use upload::*;

#[cfg(test)]
mod tests;

// Channel runner + dispatch.
// ---------------------------------------------------------------------------

/// Public entrypoint for the local web console: parse a JSON request and run it.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))?;
    handle(&r).await
}

async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => nginx_info().await,
        "setup" => start_setup(req),
        "list_sites" => Ok(json!({ "sites": load_sites() })),
        "add_site" => add_site(req).await,
        "update_site" => update_site(req).await,
        "remove_site" => remove_site(req).await,
        "list_named_certs" => list_named_certs().await,
        "create_cert" => create_cert(req).await,
        "renew_cert" => renew_cert(req).await,
        "delete_cert" => delete_cert(req).await,
        "list_access" => list_access().await,
        "save_access" => save_access_op(req).await,
        "delete_access" => delete_access_op(req).await,
        "get_settings" => get_web_settings().await,
        "set_default_site" => set_default_site(req).await,
        "set_tuning" => set_tuning(req).await,
        "reload" => {
            reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "list_containers" => list_running_containers().await,
        "list_dirs" => list_dirs(req).await,
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => Ok(op_log(req.op_id.as_deref().unwrap_or(""))),
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
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
