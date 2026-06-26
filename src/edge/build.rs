//! `build_runtime`: project the panel's persisted model (`Site` / `AccessList` /
//! `DefaultSite` / `HttpTuning`) into the immutable [`RuntimeConfig`] the edge
//! server serves from. This is the in-process replacement for the `confgen::*`
//! text generation — instead of writing `dn7-<id>.conf`, we build typed routes.
//!
//! It is a pure, synchronous transform (no I/O except reading the cert PEM the
//! panel already wrote to disk), so a reload is build → validate → swap with no
//! external process. Upstreams are kept as *specs* (`Upstream::Container` stays
//! unresolved) and resolved lazily at request time, so a container IP/port drift
//! heals without a rebuild.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ipnet::IpNet;

use crate::core::website::{AccessList, DefaultSite, HttpTuning, Site};

use super::config::*;

/// Everything `build_runtime` needs, gathered by the reload seam inside
/// `infra::nginx` (which owns the manifest loaders and the state-dir paths).
pub(crate) struct ReloadInput {
    pub(crate) sites: Vec<Site>,
    pub(crate) access: Vec<AccessList>,
    pub(crate) default_site: DefaultSite,
    pub(crate) tuning: HttpTuning,
    /// Directory the per-site/named/default cert PEM files live in.
    pub(crate) cert_dir: PathBuf,
    /// Directory upload-mode static roots live under (`<www>/<root>`).
    pub(crate) www_dir: PathBuf,
}

/// Build (and structurally de-duplicate) the route table. Returns an
/// `nginx -t`-style error string on a `server_name` collision (the same host
/// claimed by two sites), mirroring nginx's duplicate-server refusal.
pub(crate) fn build_runtime(input: &ReloadInput) -> Result<RuntimeConfig, String> {
    let access_by_id: HashMap<&str, &AccessList> =
        input.access.iter().map(|a| (a.id.as_str(), a)).collect();

    let mut cfg = RuntimeConfig {
        tuning: build_tuning(&input.tuning),
        default_site: build_default(&input.default_site),
        ..RuntimeConfig::default()
    };

    // Load the catch-all default cert (presented for unmatched SNI) if present.
    cfg.certs.default = load_certified_key(
        &input.cert_dir.join("default.crt"),
        &input.cert_dir.join("default.key"),
    );

    for site in &input.sites {
        let access = if site.access_id.is_empty() {
            None
        } else {
            access_by_id.get(site.access_id.as_str()).copied()
        }
        .map(|a| Arc::new(build_access(a)));
        let strip_auth = access
            .as_ref()
            .map(|_| {
                access_by_id
                    .get(site.access_id.as_str())
                    .map(|a| !a.pass_auth)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        // TLS only if the operator asked for it AND usable cert material exists
        // (mirrors `degrade_if_cert_missing`: one cert-less site must not break
        // the whole reload).
        let cert = if site.ssl {
            load_site_cert(input, site)
        } else {
            None
        };
        let ssl = cert.is_some();

        let route = Arc::new(ServerRoute {
            id: site.id.clone(),
            server_names: split_names(&site.server_name),
            ssl,
            force_ssl: ssl && site.force_ssl,
            // NOTE: HTTP/2 is advertised globally via the TLS listener's ALPN
            // (`h2`,`http/1.1`) and the client opts in, so the per-site `http2`
            // toggle isn't honored per-vhost (a documented minor divergence from
            // nginx's per-server `http2` directive).
            hsts: (ssl && site.hsts).then_some(Hsts {
                max_age: 63_072_000,
                include_sub: site.hsts_sub,
            }),
            block_attacks: site.block_attacks,
            trust_proxy: site.trust_proxy.then(|| build_trust_proxy(site)),
            access,
            kind: build_kind(input, site, strip_auth),
            locations: build_locations(site, strip_auth),
            extra_headers: extra_headers(&site.extra_conf),
        });

        // Index the cert (if any) under each of the site's hostnames.
        if let Some(ck) = cert {
            for name in &route.server_names {
                index_cert(&mut cfg.certs, name, ck.clone());
            }
        }

        // Index the route under each hostname, refusing a collision the way
        // `nginx -t` refuses a duplicate server_name on the same listener.
        for name in &route.server_names {
            let key = name.to_ascii_lowercase();
            if let Some(suffix) = key.strip_prefix("*.") {
                let suffix = format!(".{suffix}");
                if cfg.wildcards.iter().any(|(s, _)| s == &suffix) {
                    return Err(format!("conflicting server name \"{name}\" (wildcard)"));
                }
                cfg.wildcards.push((suffix, route.clone()));
            } else {
                if cfg.hosts.contains_key(&key) {
                    return Err(format!("conflicting server name \"{name}\""));
                }
                cfg.hosts.insert(key, route.clone());
            }
        }
    }

    Ok(cfg)
}

/// Split a (possibly multi-host) `server_name` into individual hostnames.
fn split_names(server_name: &str) -> Vec<String> {
    server_name
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Index a cert under a hostname (exact or `*.suffix` wildcard).
fn index_cert(store: &mut CertStore, name: &str, ck: Arc<rustls::sign::CertifiedKey>) {
    let key = name.to_ascii_lowercase();
    if let Some(suffix) = key.strip_prefix("*.") {
        store.wildcards.push((format!(".{suffix}"), ck));
    } else {
        store.by_host.insert(key, ck);
    }
}

/// The primary `/` handler for a site.
fn build_kind(input: &ReloadInput, site: &Site, strip_auth: bool) -> RouteKind {
    match site.kind.as_str() {
        "proxy_host" | "proxy_container" => RouteKind::Proxy(ProxyTarget {
            scheme: norm_scheme(&site.scheme),
            upstream: site_upstream(site),
            websockets: site.websockets,
            cache_assets: site.cache,
            strip_auth,
        }),
        "static" => {
            let root = if site.local_root.is_empty() {
                input.www_dir.join(&site.root)
            } else {
                PathBuf::from(&site.local_root)
            };
            RouteKind::Static(StaticRoot {
                root,
                cache_assets: site.cache,
            })
        }
        // Unknown kind: fail closed rather than serve something unintended.
        _ => RouteKind::Maintenance,
    }
}

/// Custom per-path rules, skipping a `/` rule on a proxy site (the main handler
/// already owns `/`), sorted most-specific-prefix first.
fn build_locations(site: &Site, strip_auth: bool) -> Vec<LocationRoute> {
    let is_proxy = matches!(site.kind.as_str(), "proxy_host" | "proxy_container");
    let mut out: Vec<LocationRoute> = site
        .locations
        .iter()
        .filter(|l| !(l.path == "/" && is_proxy))
        .map(|l| LocationRoute {
            path: l.path.clone(),
            target: ProxyTarget {
                scheme: norm_scheme(&l.scheme),
                upstream: if l.kind == "container" {
                    Upstream::Container {
                        name: l.container.clone(),
                        port: l.container_port,
                    }
                } else {
                    Upstream::Fixed(with_scheme_port(&l.target, &l.scheme))
                },
                websockets: l.websockets,
                cache_assets: false,
                strip_auth,
            },
        })
        .collect();
    // Longest prefix first, so the router's first match is the most specific.
    out.sort_by_key(|l| std::cmp::Reverse(l.path.len()));
    out
}

/// The main upstream spec for a proxy site.
fn site_upstream(site: &Site) -> Upstream {
    match site.kind.as_str() {
        "proxy_container" => Upstream::Container {
            name: site.container.clone(),
            port: site.container_port,
        },
        // proxy_host: a fixed host[:port].
        _ => Upstream::Fixed(with_scheme_port(&site.target_url, &site.scheme)),
    }
}

/// Translate an [`AccessList`] into the runtime [`AccessControl`].
fn build_access(a: &AccessList) -> AccessControl {
    let rules = a
        .clients
        .iter()
        .filter_map(|c| {
            let net = parse_acl_net(&c.address)?;
            Some(AclRule {
                allow: c.directive != "deny",
                net,
            })
        })
        .collect();
    AccessControl {
        satisfy_all: a.satisfy == "all",
        users: a
            .users
            .iter()
            .filter(|u| !u.hash.is_empty())
            .map(|u| (u.username.clone(), u.hash.clone()))
            .collect(),
        rules,
        realm: a.name.clone(),
    }
}

/// Build the trusted-proxy real-IP config: the operator's CIDR list, or the
/// private/loopback fallback (never the whole internet) when none are set.
fn build_trust_proxy(site: &Site) -> TrustProxy {
    let explicit: Vec<IpNet> = site
        .trust_proxy_cidrs
        .split_whitespace()
        .filter_map(parse_net)
        .collect();
    let sources = if explicit.is_empty() {
        [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
    } else {
        explicit
    };
    TrustProxy {
        sources,
        recursive: true,
    }
}

/// Parse an allow/deny address into a matcher.
fn parse_acl_net(addr: &str) -> Option<AclNet> {
    let a = addr.trim();
    if a == "all" {
        return Some(AclNet::All);
    }
    if a.contains('/') {
        return a.parse::<IpNet>().ok().map(AclNet::Net);
    }
    a.parse::<IpAddr>().ok().map(AclNet::Ip)
}

/// Parse a CIDR, accepting a bare IP as a host route (`/32` or `/128`).
fn parse_net(tok: &str) -> Option<IpNet> {
    let t = tok.trim();
    if let Ok(n) = t.parse::<IpNet>() {
        return Some(n);
    }
    match t.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Some(IpNet::V4(ipnet::Ipv4Net::new(v4, 32).ok()?)),
        Ok(IpAddr::V6(v6)) => Some(IpNet::V6(ipnet::Ipv6Net::new(v6, 128).ok()?)),
        Err(_) => None,
    }
}

/// Parse the `add_header Name "Value";` lines out of an `extra_conf` blob. MVP
/// honours only `add_header` (the one extra directive with a clean in-process
/// meaning); anything else in `extra_conf` is ignored (see the extra_conf
/// product decision in the MVP plan).
fn extra_headers(extra: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in extra.lines() {
        let l = line.trim().trim_end_matches(';').trim();
        if let Some(rest) = l.strip_prefix("add_header ") {
            let rest = rest.trim();
            // name then a (possibly quoted) value.
            if let Some((name, value)) = rest.split_once(char::is_whitespace) {
                let value = value.trim().trim_matches('"');
                if !name.is_empty() && !value.is_empty() {
                    out.push((name.to_string(), value.to_string()));
                }
            }
        }
    }
    out
}

fn build_tuning(t: &HttpTuning) -> Tuning {
    Tuning {
        gzip: t.gzip,
        gzip_min_length: t.gzip_min_length,
        gzip_comp_level: t.gzip_comp_level,
        client_max_body_size: parse_size(&t.client_max_body_size).unwrap_or(1024 * 1024 * 1024),
        keepalive_timeout: t.keepalive_timeout,
    }
}

fn build_default(d: &DefaultSite) -> DefaultRoute {
    match d.mode.as_str() {
        "welcome" => DefaultRoute::Welcome,
        "444" => DefaultRoute::Drop,
        "redirect" => DefaultRoute::Redirect(d.redirect_url.clone()),
        _ => DefaultRoute::NotFound,
    }
}

/// Parse an nginx-style size (`1024m`, `32k`, `512`) into bytes.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1024),
        'm' => (&s[..s.len() - 1], 1024 * 1024),
        'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s.as_str(), 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Normalise a proxy scheme to `http`/`https` (empty == http).
fn norm_scheme(s: &str) -> String {
    if s == "https" {
        "https".into()
    } else {
        "http".into()
    }
}

/// Build `host:port`, defaulting the port to 80 (http) or 443 (https). Mirrors
/// `confgen::with_scheme_port`.
fn with_scheme_port(host: &str, scheme: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else if scheme == "https" {
        format!("{host}:443")
    } else {
        format!("{host}:80")
    }
}

/// The per-site cert pair (`<id>.crt`/`<id>.key`) or a referenced named cert
/// (`cert-<name>.crt`/`.key`), parsed into a rustls signing key. `None` when the
/// material is missing/unparseable (the site then degrades to plain HTTP).
fn load_site_cert(input: &ReloadInput, site: &Site) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let (crt, key) = if site.cert_name.is_empty() {
        (
            input.cert_dir.join(format!("{}.crt", site.id)),
            input.cert_dir.join(format!("{}.key", site.id)),
        )
    } else {
        (
            input.cert_dir.join(format!("cert-{}.crt", site.cert_name)),
            input.cert_dir.join(format!("cert-{}.key", site.cert_name)),
        )
    };
    load_certified_key(&crt, &key)
}

/// Read a PEM cert chain + private key and assemble a rustls [`CertifiedKey`]
/// using the ring provider (the one pinned by the panel's musl-static build).
/// `None` on any read/parse error so a bad cert degrades one site, not the run.
pub(crate) fn load_certified_key(
    crt: &std::path::Path,
    key: &std::path::Path,
) -> Option<Arc<rustls::sign::CertifiedKey>> {
    let crt_pem = std::fs::read(crt).ok()?;
    let key_pem = std::fs::read(key).ok()?;
    let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &crt_pem[..])
            .collect::<Result<_, _>>()
            .ok()?;
    if chain.is_empty() {
        return None;
    }
    let key_der = rustls_pemfile::private_key(&mut &key_pem[..]).ok()??;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key_der).ok()?;
    Some(Arc::new(rustls::sign::CertifiedKey::new(chain, signing)))
}
