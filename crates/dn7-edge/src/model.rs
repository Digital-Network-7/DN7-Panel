//! The edge's own route-table INPUT CONTRACT.
//!
//! Like `dn7-container`'s `ImageRunSpec`, this crate owns its input types and does
//! NOT depend on the panel's domain model. The panel converts its persisted
//! `core::website::*` entities into these (a serde round-trip, since the field
//! names match) at the reload seam. Fields default so the panel's (richer) model
//! deserializes cleanly even as it grows. `build` projects these into the
//! immutable `config::RuntimeConfig` the data plane serves from.

use serde::{Deserialize, Serialize};

/// A managed site (the proxy/static/route definition).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Site {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub target_url: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub container_port: i64,
    #[serde(default)]
    pub root: String,
    #[serde(default)]
    pub local_root: String,
    #[serde(default)]
    pub ssl: bool,
    #[serde(default)]
    pub cert_name: String,
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub cache: bool,
    #[serde(default)]
    pub block_attacks: bool,
    #[serde(default)]
    pub websockets: bool,
    #[serde(default)]
    pub force_ssl: bool,
    #[serde(default)]
    pub hsts: bool,
    #[serde(default)]
    pub hsts_sub: bool,
    #[serde(default)]
    pub trust_proxy: bool,
    #[serde(default)]
    pub trust_proxy_cidrs: String,
    #[serde(default)]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub extra_conf: String,
    #[serde(default)]
    pub rate_limit_rps: u32,
    #[serde(default)]
    pub rate_limit_burst: u32,
    #[serde(default)]
    pub bandwidth_kbps: u32,
    #[serde(default)]
    pub autoban_threshold: u32,
    #[serde(default)]
    pub autoban_window: u32,
    #[serde(default)]
    pub autoban_minutes: u32,
    #[serde(default)]
    pub cert_mode: String,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub conn_per_ip: u32,
    #[serde(default)]
    pub ip_acl_mode: String,
    #[serde(default)]
    pub ip_acl_list: String,
    #[serde(default)]
    pub hotlink_referers: String,
    #[serde(default)]
    pub access_id: String,
}

/// A custom path rule layered on a proxy site.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Location {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub websockets: bool,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub container_port: i64,
}

/// A stored access list (HTTP Basic Auth + IP allow/deny).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessList {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub satisfy: String,
    #[serde(default)]
    pub pass_auth: bool,
    #[serde(default)]
    pub users: Vec<AccessUser>,
    #[serde(default)]
    pub clients: Vec<AccessClient>,
}

/// A basic-auth credential: username + precomputed htpasswd hash.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessUser {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hash: String,
}

/// An allow/deny rule against a client address (IP, CIDR, or "all").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessClient {
    #[serde(default)]
    pub directive: String,
    #[serde(default)]
    pub address: String,
}

/// Default-site behaviour for requests matching no managed server_name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSite {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub redirect_url: String,
}

impl Default for DefaultSite {
    fn default() -> Self {
        DefaultSite {
            mode: "404".to_string(),
            redirect_url: String::new(),
        }
    }
}

/// HTTP tuning knobs the edge honours (gzip + body size + keepalive). Other
/// nginx-tuning fields the panel persists are ignored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTuning {
    #[serde(default = "d_gzip_on")]
    pub gzip: bool,
    #[serde(default = "d_gmin")]
    pub gzip_min_length: u32,
    #[serde(default = "d_cmbs")]
    pub client_max_body_size: String,
    #[serde(default = "d_gcl")]
    pub gzip_comp_level: u8,
    #[serde(default = "d_kat")]
    pub keepalive_timeout: u32,
}

fn d_gzip_on() -> bool {
    true
}
fn d_gmin() -> u32 {
    20
}
fn d_cmbs() -> String {
    "1024m".to_string()
}
fn d_gcl() -> u8 {
    1
}
fn d_kat() -> u32 {
    60
}

impl Default for HttpTuning {
    fn default() -> Self {
        HttpTuning {
            gzip: d_gzip_on(),
            gzip_min_length: d_gmin(),
            client_max_body_size: d_cmbs(),
            gzip_comp_level: d_gcl(),
            keepalive_timeout: d_kat(),
        }
    }
}
