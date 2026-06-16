//! Persisted nginx domain entities (Site/Location/AccessList/DefaultSite/
//! HttpTuning …).
//!
//! NOTE: these are persisted **domain entities** — the `serde` derives are a
//! reviewed exception (see steering §2/§4). Fields are `pub(crate)` so the
//! nginx infra submodules (confgen/sites/access/…) can read/build them across
//! modules. Transport-only input shapes (`HttpTuningInput`) live here too but
//! carry no serde.

use serde::{Deserialize, Serialize};

/// A managed site, persisted in the manifest and regenerated into one conf file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Site {
    pub(crate) id: String,
    pub(crate) server_name: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) target_url: String,
    #[serde(default)]
    pub(crate) container: String,
    #[serde(default)]
    pub(crate) container_port: i64,
    #[serde(default)]
    pub(crate) root: String,
    /// Static site served from an existing absolute host directory (instead of
    /// the panel-managed `<www>/<root>` upload dir). Empty == upload mode.
    #[serde(default)]
    pub(crate) local_root: String,
    #[serde(default)]
    pub(crate) ssl: bool,
    #[serde(default)]
    pub(crate) cert_mode: String,
    /// When set, this site uses a standalone named cert from the cert manifest
    /// instead of a per-site `<id>.crt/.key`. Empty means per-site (legacy).
    #[serde(default)]
    pub(crate) cert_name: String,
    /// Upstream scheme for proxy kinds ("http" | "https"). Empty == http.
    #[serde(default)]
    pub(crate) scheme: String,
    /// Behaviour toggles (NPM-style): long-cache static assets, block common
    /// exploit patterns, and enable WebSocket upgrade headers on proxies.
    #[serde(default)]
    pub(crate) cache: bool,
    #[serde(default)]
    pub(crate) block_attacks: bool,
    #[serde(default)]
    pub(crate) websockets: bool,
    /// HTTPS feature toggles. `force_ssl` (HTTP→HTTPS redirect) and `http2`
    /// default on for backward compatibility; the rest default off.
    #[serde(default = "default_true")]
    pub(crate) force_ssl: bool,
    #[serde(default = "default_true")]
    pub(crate) http2: bool,
    #[serde(default)]
    pub(crate) hsts: bool,
    #[serde(default)]
    pub(crate) hsts_sub: bool,
    #[serde(default)]
    pub(crate) trust_proxy: bool,
    /// Trusted front-proxy sources for `real_ip` (comma/space/newline-separated
    /// IPs or CIDRs). Only honoured when `trust_proxy` is set. Empty means trust
    /// private/loopback ranges only — never the entire internet.
    #[serde(default)]
    pub(crate) trust_proxy_cidrs: String,
    /// Extra path rules layered on top of the main location (NPM "custom
    /// locations"): each forwards a path prefix to a host[:port].
    #[serde(default)]
    pub(crate) locations: Vec<Location>,
    /// Raw nginx directives, injected verbatim into the serving server block(s).
    /// Validated by `nginx -t` on save (invalid input rolls back).
    #[serde(default)]
    pub(crate) extra_conf: String,
    /// Access list id controlling this site (HTTP Basic Auth + IP allow/deny).
    /// Empty == publicly accessible.
    #[serde(default)]
    pub(crate) access_id: String,
}

fn default_true() -> bool {
    true
}

/// A custom path rule layered on a proxy site: forward a path prefix to a
/// host[:port] over http/https. Form-driven (no raw nginx config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct Location {
    /// The location prefix, e.g. "/api". Must start with '/'.
    pub(crate) path: String,
    /// Upstream scheme: "http" | "https". Empty == http.
    #[serde(default)]
    pub(crate) scheme: String,
    /// Upstream host[:port].
    #[serde(default)]
    pub(crate) target: String,
    /// Enable WebSocket upgrade headers for this path.
    #[serde(default)]
    pub(crate) websockets: bool,
    /// Upstream kind: "host" (target host:port) | "container" (docker
    /// container). Empty == host (backward compatible).
    #[serde(default)]
    pub(crate) kind: String,
    /// Docker container name (when `kind == "container"`).
    #[serde(default)]
    pub(crate) container: String,
    /// Container port to proxy to (when `kind == "container"`).
    #[serde(default)]
    pub(crate) container_port: i64,
}

/// A stored access list. Passwords are kept only as nginx-htpasswd hashes
/// (`{SHA}…`), never in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessList {
    pub(crate) id: String,
    pub(crate) name: String,
    /// "any" | "all" — how auth and IP rules combine (nginx `satisfy`).
    #[serde(default)]
    pub(crate) satisfy: String,
    /// Forward the client's Authorization header to the upstream (else strip).
    #[serde(default)]
    pub(crate) pass_auth: bool,
    #[serde(default)]
    pub(crate) users: Vec<AccessUser>,
    #[serde(default)]
    pub(crate) clients: Vec<AccessClient>,
}

/// A basic-auth credential: the username and its precomputed htpasswd hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessUser {
    pub(crate) username: String,
    /// nginx-compatible hash, e.g. `{SHA}base64(sha1(password))`.
    #[serde(default)]
    pub(crate) hash: String,
}

/// An allow/deny rule against a client address (IP, CIDR, or "all").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AccessClient {
    /// "allow" | "deny".
    pub(crate) directive: String,
    /// IP / CIDR / "all".
    pub(crate) address: String,
}

/// Default-site behaviour for requests matching no managed server_name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DefaultSite {
    /// "404" | "welcome" | "444" | "redirect".
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) redirect_url: String,
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
    pub(crate) default_site: DefaultSite,
}

/// nginx http/server tuning knobs (persisted in `webtuning.json`). Values
/// mirror nginx's own defaults. The server-context ones are injected into each
/// managed site's server block (so they override per-site without clashing with
/// the distro nginx.conf's http-level directives); `server_names_hash_bucket_size`
/// is http-only and written to a guarded http include.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HttpTuning {
    #[serde(default = "d_snhbs")]
    pub(crate) server_names_hash_bucket_size: u32,
    #[serde(default = "d_gzip_on")]
    pub(crate) gzip: bool,
    #[serde(default = "d_ghdr")]
    pub(crate) client_header_buffer_size: String,
    #[serde(default = "d_gmin")]
    pub(crate) gzip_min_length: u32,
    #[serde(default = "d_cmbs")]
    pub(crate) client_max_body_size: String,
    #[serde(default = "d_gcl")]
    pub(crate) gzip_comp_level: u8,
    #[serde(default = "d_kat")]
    pub(crate) keepalive_timeout: u32,
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

/// Optional http/server tuning inputs from a `set_tuning` request. `None` means
/// "keep the current value". Pure transport-free shape consumed by
/// [`super::merge_http_tuning`].
#[derive(Default)]
pub(crate) struct HttpTuningInput {
    pub(crate) server_names_hash_bucket_size: Option<u32>,
    pub(crate) gzip: Option<bool>,
    pub(crate) client_header_buffer_size: Option<String>,
    pub(crate) gzip_min_length: Option<u32>,
    pub(crate) client_max_body_size: Option<String>,
    pub(crate) gzip_comp_level: Option<u8>,
    pub(crate) keepalive_timeout: Option<u32>,
}
