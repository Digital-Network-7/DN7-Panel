//! The in-process runtime configuration — the typed route table that the edge
//! server serves requests from. This is the in-memory replacement for the
//! generated `dn7-<id>.conf` files: `build::build_runtime` projects the panel's
//! persisted `Site`/`AccessList`/`DefaultSite`/`HttpTuning` model into this
//! shape, `validate` checks it (the in-process `nginx -t`), and `store` swaps it
//! atomically (the in-process `nginx -s reload`).
//!
//! It is deliberately immutable: a [`RuntimeConfig`] is built, validated, then
//! published behind an `ArcSwap`. In-flight requests keep serving from the
//! `Arc` they loaded; new requests pick up the next snapshot. That is the whole
//! zero-dropped-connection reload story (see [`super::store`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ipnet::IpNet;

/// A fully-built, validated, immutable serving configuration. Published behind
/// an `ArcSwap`; never mutated after construction.
#[derive(Default)]
pub(crate) struct RuntimeConfig {
    /// Exact `server_name` → route, keyed by lowercased host. A site whose
    /// `server_name` lists several hosts is indexed under each.
    pub(crate) hosts: HashMap<String, Arc<ServerRoute>>,
    /// Wildcard `*.example.com` routes, stored as the bare suffix
    /// (`.example.com`) so a Host lookup can match by suffix. Checked only when
    /// an exact host miss occurs; longest suffix wins.
    pub(crate) wildcards: Vec<(String, Arc<ServerRoute>)>,
    /// What to do for a request whose Host matches no managed route.
    pub(crate) default_site: DefaultRoute,
    /// http/server tuning knobs (gzip, body-size cap, keepalive…).
    pub(crate) tuning: Tuning,
    /// SNI → certificate material for TLS termination.
    pub(crate) certs: CertStore,
}

impl RuntimeConfig {
    /// Resolve the [`ServerRoute`] for a request `Host` (already lowercased,
    /// port stripped): exact match first, then the longest matching wildcard
    /// suffix. `None` falls through to [`Self::default_site`].
    pub(crate) fn route_for(&self, host: &str) -> Option<&Arc<ServerRoute>> {
        if let Some(r) = self.hosts.get(host) {
            return Some(r);
        }
        // Longest suffix wins so `*.a.example.com` beats `*.example.com`.
        self.wildcards
            .iter()
            .filter(|(suffix, _)| wildcard_matches(host, suffix))
            .max_by_key(|(suffix, _)| suffix.len())
            .map(|(_, r)| r)
    }
}

/// nginx single-label wildcard semantics: `*.example.com` (stored as the suffix
/// `.example.com`) matches `foo.example.com` but NOT `foo.bar.example.com` — the
/// label in front of the suffix must be non-empty and contain no further dot.
/// Without this a `*.example.com` cert/route would over-match deeper subdomains.
pub(crate) fn wildcard_matches(host: &str, suffix: &str) -> bool {
    match host.strip_suffix(suffix) {
        Some(prefix) => !prefix.is_empty() && !prefix.contains('.'),
        None => false,
    }
}

/// One managed virtual server (the in-memory form of an nginx `server` block,
/// covering both its :80 and :443 behaviour).
pub(crate) struct ServerRoute {
    pub(crate) id: String,
    pub(crate) server_names: Vec<String>,
    /// TLS is configured (a usable cert was found at build time). When false the
    /// site only ever serves plain HTTP regardless of the operator's `ssl` flag
    /// (mirrors `degrade_if_cert_missing`).
    pub(crate) ssl: bool,
    /// Redirect plain-HTTP requests to HTTPS (301). Only meaningful with `ssl`.
    pub(crate) force_ssl: bool,
    /// `Strict-Transport-Security` header to attach to HTTPS responses.
    pub(crate) hsts: Option<Hsts>,
    /// Apply the query-string exploit-blocking rules (`BLOCK_EXPLOITS`).
    pub(crate) block_attacks: bool,
    /// Trusted front-proxy real-IP recovery (`set_real_ip_from` + XFF).
    pub(crate) trust_proxy: Option<TrustProxy>,
    /// Access control (HTTP Basic + IP allow/deny) gating every request.
    pub(crate) access: Option<Arc<AccessControl>>,
    /// What this server serves: a proxy upstream, a static root, or a 503 stub.
    pub(crate) kind: RouteKind,
    /// Custom per-path rules layered on top of the main handler, sorted by
    /// prefix length descending so the most specific prefix matches first.
    pub(crate) locations: Vec<LocationRoute>,
    /// Extra response headers parsed from an allowlisted `extra_conf`
    /// (`add_header` only — see `build::extra_headers`).
    pub(crate) extra_headers: Vec<(String, String)>,
}

/// The primary handler kind for a [`ServerRoute`]'s `/` location.
pub(crate) enum RouteKind {
    /// Reverse proxy to an upstream.
    Proxy(ProxyTarget),
    /// Serve files from a document root.
    Static(StaticRoot),
    /// Fail closed with 503 (upstream unresolvable — the maintenance stub).
    Maintenance,
}

/// A custom path rule (NPM-style "custom location"): forward a path prefix to an
/// upstream, independent of the site's main handler.
pub(crate) struct LocationRoute {
    /// The location prefix, e.g. `/api`. Always starts with `/`.
    pub(crate) path: String,
    pub(crate) target: ProxyTarget,
}

/// A reverse-proxy destination plus its per-location proxy behaviour.
pub(crate) struct ProxyTarget {
    /// Upstream scheme: `http` | `https`.
    pub(crate) scheme: String,
    /// Where to connect. Container upstreams resolve lazily at request time so a
    /// container IP/port drift heals without a reload.
    pub(crate) upstream: Upstream,
    /// Honour HTTP `Upgrade` (WebSocket) on this path.
    pub(crate) websockets: bool,
    /// Long-cache static assets matched under this proxy (sets `Cache-Control`).
    pub(crate) cache_assets: bool,
    /// Strip the client `Authorization` header before forwarding upstream
    /// (access list with Pass-Auth off).
    pub(crate) strip_auth: bool,
}

/// A reverse-proxy upstream address.
#[derive(Clone)]
pub(crate) enum Upstream {
    /// A fixed `host:port` (proxy_host, or a container with a stable published
    /// host port resolved at build time).
    Fixed(String),
    /// A Docker container resolved at request time via the daemon (host mode):
    /// prefer its published loopback port, else its bridge IP.
    Container { name: String, port: i64 },
}

/// A static document root.
pub(crate) struct StaticRoot {
    /// Absolute filesystem directory to serve from.
    pub(crate) root: PathBuf,
    /// Long-cache static assets (sets `expires`/`Cache-Control`).
    pub(crate) cache_assets: bool,
}

/// HTTP Basic Auth users + IP allow/deny rules + how they combine (`satisfy`).
pub(crate) struct AccessControl {
    /// `satisfy all` (both auth and IP must pass) vs `satisfy any` (either).
    pub(crate) satisfy_all: bool,
    /// `username` → htpasswd hash (apr1 `$apr1$…` or `{SHA}…`).
    pub(crate) users: Vec<(String, String)>,
    /// allow/deny rules, evaluated in order (first match wins, nginx semantics).
    pub(crate) rules: Vec<AclRule>,
    /// The Basic-Auth realm shown in the `WWW-Authenticate` challenge.
    pub(crate) realm: String,
}

impl AccessControl {
    pub(crate) fn has_auth(&self) -> bool {
        !self.users.is_empty()
    }
    pub(crate) fn has_acl(&self) -> bool {
        !self.rules.is_empty()
    }
}

/// One `allow`/`deny` rule against a client address.
pub(crate) struct AclRule {
    /// true = allow, false = deny.
    pub(crate) allow: bool,
    pub(crate) net: AclNet,
}

/// The address matcher for an [`AclRule`].
pub(crate) enum AclNet {
    /// `allow all` / `deny all`.
    All,
    /// A single IP.
    Ip(IpAddr),
    /// A CIDR network.
    Net(IpNet),
}

impl AclNet {
    pub(crate) fn matches(&self, ip: IpAddr) -> bool {
        match self {
            AclNet::All => true,
            AclNet::Ip(a) => *a == ip,
            AclNet::Net(n) => n.contains(&ip),
        }
    }
}

/// Trusted front-proxy real-IP recovery config (`real_ip` module).
pub(crate) struct TrustProxy {
    /// Sources we trust to set `X-Forwarded-For` (`set_real_ip_from`). Never
    /// `0.0.0.0/0`; an empty operator list falls back to private/loopback only.
    pub(crate) sources: Vec<IpNet>,
    /// `real_ip_recursive on` — walk the XFF chain right-to-left skipping
    /// trusted hops.
    pub(crate) recursive: bool,
}

impl TrustProxy {
    /// Whether `ip` is one of the trusted proxy sources.
    pub(crate) fn trusts(&self, ip: IpAddr) -> bool {
        self.sources.iter().any(|n| n.contains(&ip))
    }
}

/// `Strict-Transport-Security` parameters.
pub(crate) struct Hsts {
    pub(crate) max_age: u64,
    pub(crate) include_sub: bool,
}

impl Hsts {
    pub(crate) fn header_value(&self) -> String {
        if self.include_sub {
            format!("max-age={}; includeSubDomains", self.max_age)
        } else {
            format!("max-age={}", self.max_age)
        }
    }
}

/// What a request matching no managed `server_name` gets (`DefaultSite`).
#[derive(Default)]
pub(crate) enum DefaultRoute {
    /// `404` — the default.
    #[default]
    NotFound,
    /// `welcome` — a small 200 landing page.
    Welcome,
    /// `444` — drop the connection with no response.
    Drop,
    /// `redirect` — 301 to a fixed URL.
    Redirect(String),
}

/// http/server tuning knobs that affect request handling.
pub(crate) struct Tuning {
    pub(crate) gzip: bool,
    pub(crate) gzip_min_length: u32,
    pub(crate) gzip_comp_level: u8,
    /// Max request body in bytes (`client_max_body_size`; 0 = unlimited).
    pub(crate) client_max_body_size: u64,
    /// Keepalive idle timeout (seconds), carried for completeness. Note: the edge
    /// already reaps an idle keepalive connection via the HTTP/1 header-read
    /// timeout — hyper arms that deadline when it starts waiting for the *next*
    /// request on a kept-alive connection, so a connection that sends nothing is
    /// closed within `HEADER_READ_TIMEOUT` (tighter than nginx's default), and
    /// TCP keepalive catches dead peers. This knob is therefore not separately
    /// wired into the listener.
    #[allow(dead_code)] // carried from HttpTuning; idle reaping is via the header-read timeout
    pub(crate) keepalive_timeout: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            gzip: true,
            gzip_min_length: 20,
            gzip_comp_level: 1,
            client_max_body_size: 1024 * 1024 * 1024, // 1024m, mirrors HttpTuning default
            keepalive_timeout: 60,
        }
    }
}

/// Resolved TLS certificate material, indexed by SNI hostname. Built once per
/// reload from the on-disk PEM the panel manages.
#[derive(Default)]
pub(crate) struct CertStore {
    /// Exact host → signing key + chain.
    pub(crate) by_host: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    /// Wildcard suffix (`.example.com`) → cert, for `*.example.com` certs.
    pub(crate) wildcards: Vec<(String, Arc<rustls::sign::CertifiedKey>)>,
    /// Fallback cert for unmatched SNI (the `default.crt` catch-all).
    pub(crate) default: Option<Arc<rustls::sign::CertifiedKey>>,
}

impl CertStore {
    /// Pick the certificate for an SNI hostname: exact, then longest wildcard
    /// suffix, then the default. `None` → the TLS handshake has no cert to offer.
    pub(crate) fn resolve(&self, sni: Option<&str>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(host) = sni {
            let host = host.to_ascii_lowercase();
            if let Some(ck) = self.by_host.get(&host) {
                return Some(ck.clone());
            }
            if let Some((_, ck)) = self
                .wildcards
                .iter()
                .filter(|(suffix, _)| wildcard_matches(&host, suffix))
                .max_by_key(|(suffix, _)| suffix.len())
            {
                return Some(ck.clone());
            }
        }
        self.default.clone()
    }
}
