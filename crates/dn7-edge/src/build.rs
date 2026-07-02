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
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;

use ipnet::IpNet;

use crate::model::{AccessList, DefaultSite, HttpTuning, Site};

use super::config::*;

/// Everything `build_runtime` needs, gathered by the reload seam inside
/// `infra::website` (which owns the manifest loaders and the state-dir paths).
pub struct ReloadInput {
    pub sites: Vec<Site>,
    pub access: Vec<AccessList>,
    pub default_site: DefaultSite,
    pub tuning: HttpTuning,
    /// Directory the per-site/named/default cert PEM files live in.
    pub cert_dir: PathBuf,
    /// Directory upload-mode static roots live under (`<www>/<root>`).
    pub www_dir: PathBuf,
    /// The managed console route the edge fronts (the panel itself).
    pub console: ConsoleParams,
}

/// Inputs for the synthesized console route (the panel, reverse-proxied by the
/// edge). The upstream is always the fixed loopback console
/// (`127.0.0.1:CONSOLE_LOOPBACK_PORT`).
pub struct ConsoleParams {
    /// Operator-chosen external address (IP or domain). Empty before the wizard.
    pub external_address: String,
    /// `"none"` | `"selfsigned"` | `"le"` — drives the console route's TLS.
    pub https_mode: String,
    /// When false (uninitialized), the console is ALSO the catch-all so the
    /// wizard answers any host on a fresh box.
    pub initialized: bool,
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
            let ck = load_site_cert(input, site);
            // Degrade one cert-less site to plaintext, but LOUDLY: an ssl=true
            // site whose cert is missing/unparseable silently drops to HTTP (and
            // force_ssl/HSTS go false with it), so make the downgrade observable
            // the way the ACL path warns on a bad rule instead of failing open.
            if ck.is_none() {
                tracing::warn!(
                    site = %site.id,
                    host = %primary_host(&site.server_name),
                    cert = %if site.cert_name.is_empty() {
                        format!("{}.crt/.key", site.id)
                    } else {
                        format!("cert-{}.crt/.key", site.cert_name)
                    },
                    "edge build: site requests SSL but its cert is missing or unparseable; \
                     serving it as plaintext HTTP (no TLS, no force-SSL redirect)"
                );
            }
            ck
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
            rate_limit: build_rate_limit(site),
            conn_per_ip: site.conn_per_ip,
            ip_acl: build_ip_acl(site),
            hotlink: build_hotlink(site),
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

    inject_console_route(&mut cfg, input);
    Ok(cfg)
}

/// Synthesize the managed console route — a reverse proxy to the loopback
/// console (the panel itself). It's reachable at the operator's
/// `external_address` (with TLS when configured), plus `localhost`/`127.0.0.1`
/// so an SSH tunnel still reaches the console even if `:80` is contended.
/// Before the panel is initialized it's ALSO the catch-all (`console_fallback`)
/// so the init wizard answers ANY host on a fresh box. The console wins over a
/// user site that collides on these names — it's how the box is managed.
fn inject_console_route(cfg: &mut RuntimeConfig, input: &ReloadInput) {
    // /api/terminal + container-exec ride WS upgrades. Built fresh per route
    // (ProxyTarget isn't Clone), all pointing at the loopback console.
    let mk_target = || ProxyTarget {
        scheme: "http".to_string(),
        upstream: Upstream::Fixed(format!("127.0.0.1:{CONSOLE_LOOPBACK_PORT}")),
        websockets: true,
        cache_assets: false,
        strip_auth: false,
    };
    let console_route = |ssl: bool, force_ssl: bool, names: Vec<String>| {
        Arc::new(ServerRoute {
            id: "__console__".to_string(),
            server_names: names,
            ssl,
            force_ssl,
            hsts: force_ssl.then_some(Hsts {
                max_age: 63_072_000,
                include_sub: false,
            }),
            block_attacks: false,
            trust_proxy: None,
            access: None,
            kind: RouteKind::Proxy(mk_target()),
            locations: Vec::new(),
            extra_headers: Vec::new(),
            rate_limit: None,
            conn_per_ip: 0,
            ip_acl: None,
            hotlink: None,
        })
    };

    // A PLAIN-HTTP route for the loopback host keys — the SSH-tunnel fallback
    // when :80 is contended. Never TLS: there is no cert for `localhost`/
    // `127.0.0.1` (marking the route `ssl` there would make `validate` demand a
    // cert that doesn't resolve and abort the whole reload). It doubles as the
    // uninitialized catch-all, so the wizard rides http on any Host.
    let loopback = console_route(
        false,
        false,
        vec!["localhost".to_string(), "127.0.0.1".to_string()],
    );
    cfg.hosts.insert("localhost".to_string(), loopback.clone());
    cfg.hosts.insert("127.0.0.1".to_string(), loopback.clone());

    // The named, TLS-capable console route at the operator's external address
    // (skipped when there's no address, or it IS a loopback name). The cert is
    // indexed under that address, so an `ssl` route here actually resolves.
    // Only ENFORCE https once setup is done: during init the wizard loads over
    // http (the banner's init URLs); if step 1 enables a self-signed cert, an
    // http->https redirect would break step 2's fetch (the browser rejects the
    // untrusted cert on an XHR). So redirect + HSTS wait for `initialized`.
    // A bare IPv6 literal (`2001:db8::1`) is accepted at init time, but a browser
    // can only open it bracketed (`http://[2001:db8::1]/`) and the router derives
    // the route key from that bracketed Host. Canonicalize to the bracketed form
    // here so the stored host key matches what the router will produce.
    let ext = bracket_if_ipv6(&input.console.external_address.trim().to_ascii_lowercase());
    if !ext.is_empty() && ext != "localhost" && ext != "127.0.0.1" {
        let cert = (input.console.https_mode != "none")
            .then(|| {
                load_certified_key(
                    &input.cert_dir.join("cert-console.crt"),
                    &input.cert_dir.join("cert-console.key"),
                )
            })
            .flatten();
        let ssl = cert.is_some();
        let enforce_ssl = ssl && input.console.initialized;
        if let Some(ck) = cert {
            index_cert(&mut cfg.certs, &ext, ck);
        }
        let named = console_route(ssl, enforce_ssl, vec![ext.clone()]);
        cfg.hosts.insert(ext, named);
    }

    // While UNINITIALIZED the console is the catch-all (the plain loopback route)
    // so any Host reaches the token-gated wizard. Once initialized it answers
    // only on its configured external address (+ localhost/127.0.0.1).
    if !input.console.initialized {
        cfg.console_fallback = Some(loopback);
    }
}

/// Split a (possibly multi-host) `server_name` into individual hostnames.
fn split_names(server_name: &str) -> Vec<String> {
    server_name
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// The first hostname of a (possibly multi-host) `server_name`, for log context.
/// `"?"` when the field is blank so a warn line always names *something*.
fn primary_host(server_name: &str) -> &str {
    server_name.split_whitespace().next().unwrap_or("?")
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
///
/// An `allow`/`deny` entry that fails to parse is NOT silently dropped: dropping
/// (say) a terminating `deny all` would collapse the list back to nginx's
/// default-allow and quietly open the site — a fail-OPEN. Instead we fail CLOSED
/// — replace the whole rule set with a single `deny all` and log it — so a
/// corrupt ACL denies rather than admits. (The panel now rejects invalid rules
/// at save time; this is the defense-in-depth backstop for anything that still
/// reaches the builder.)
fn build_access(a: &AccessList) -> AccessControl {
    let mut rules = Vec::with_capacity(a.clients.len());
    let mut fail_closed = false;
    for c in &a.clients {
        match parse_acl_net(&c.address) {
            Some(net) => rules.push(AclRule {
                allow: c.directive != "deny",
                net,
            }),
            None => {
                tracing::warn!(
                    access = %a.id,
                    address = %c.address,
                    "edge build: unparseable ACL address; failing the access list closed (deny all)"
                );
                fail_closed = true;
            }
        }
    }
    // Any unparseable entry → deny everything (never weaken a broken rule into an
    // allow). The single `deny all` short-circuits `ip_allowed` for every client.
    if fail_closed {
        rules = vec![AclRule {
            allow: false,
            net: AclNet::All,
        }];
    }
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

/// Project the site's advanced rate-limit / auto-ban knobs into the edge route.
/// `None` when neither is configured, so the hot path skips the check entirely.
fn build_rate_limit(site: &Site) -> Option<RateLimit> {
    if site.rate_limit_rps == 0 && site.autoban_threshold == 0 && site.bandwidth_kbps == 0 {
        return None;
    }
    Some(RateLimit {
        req_per_sec: site.rate_limit_rps,
        burst: site.rate_limit_burst,
        bytes_per_sec: site.bandwidth_kbps as u64 * 1024,
        autoban_threshold: site.autoban_threshold,
        autoban_window: site.autoban_window,
        autoban_minutes: site.autoban_minutes,
    })
}

/// Project the site's inline IP allow/deny knob (the "高级功能" IP-ACL) into a
/// parsed [`IpAcl`], so the hot path never re-parses. `None` when there's no
/// usable filter: an empty mode, an unrecognised mode, or a list that parses to
/// no nets. Addresses are comma/space/newline-separated IPs or CIDRs.
///
/// An UNPARSEABLE entry is dropped (not fail-closed) — unlike the shared access
/// list, this inline filter is the simpler "block these / allow only these" knob,
/// and a lone bad token shouldn't silently 403 an allow-list operator out of
/// their own site or (in deny mode) is simply one net that won't be blocked. The
/// panel validates entries at save time; this is best-effort at the edge.
fn build_ip_acl(site: &Site) -> Option<IpAcl> {
    let allow = match site.ip_acl_mode.trim() {
        "allow" => true,
        "deny" => false,
        _ => return None, // empty / unknown mode → no filtering
    };
    let nets: Vec<AclNet> = site
        .ip_acl_list
        .split([',', ' ', '\t', '\n', '\r'])
        .filter(|t| !t.trim().is_empty())
        .filter_map(parse_acl_net)
        .collect();
    if nets.is_empty() {
        return None;
    }
    Some(IpAcl { allow, nets })
}

/// Project the site's anti-hotlinking knob into a parsed [`Hotlink`] of allowed
/// referer host patterns. `None` when the list is empty (protection disabled).
/// Patterns are comma/space/newline-separated; each is lowercased and stripped of
/// any `scheme://` and path so an operator can paste either `example.com` or
/// `https://example.com/` (both mean the same allowed host).
fn build_hotlink(site: &Site) -> Option<Hotlink> {
    let allowed: Vec<String> = site
        .hotlink_referers
        .split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        // Reuse `referer_host` so `https://a.com/x`, `a.com:443`, and `a.com` all
        // normalise to the bare host we compare a request's Referer against. A
        // leading-dot wildcard (`.a.com`) is preserved (it has no host to parse).
        .filter_map(|t| {
            if let Some(suffix) = t.strip_prefix('.') {
                Some(format!(".{}", suffix.to_ascii_lowercase()))
            } else {
                referer_host(t)
            }
        })
        .collect();
    if allowed.is_empty() {
        return None;
    }
    Some(Hotlink { allowed })
}

/// Build the trusted-proxy real-IP config: the operator's CIDR list, or the
/// private/loopback fallback (never the whole internet) when none are set.
fn build_trust_proxy(site: &Site) -> TrustProxy {
    let explicit: Vec<IpNet> = site
        .trust_proxy_cidrs
        .split_whitespace()
        .filter_map(parse_net)
        // Never trust a default route (`0.0.0.0/0` / `::/0`): it would trust
        // every peer and let any client forge X-Forwarded-For, defeating the
        // real-IP/ACL logic. Dropping it falls back to the private/loopback set.
        .filter(|n| n.prefix_len() != 0)
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

/// Canonicalize a bare IPv6 literal to its bracketed form (`2001:db8::1` →
/// `[2001:db8::1]`) so it matches the Host a browser sends and the key the router
/// derives. A hostname, an IPv4 literal, or an already-bracketed literal is
/// returned unchanged.
pub(crate) fn bracket_if_ipv6(host: &str) -> String {
    if !host.starts_with('[') && host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Build `host:port`, defaulting the port to 80 (http) or 443 (https). Mirrors
/// `confgen::with_scheme_port`.
///
/// A bare IPv6 literal is full of colons, so `contains(':')` can't tell "already
/// has a port" from "is an IPv6 address" — it would wrongly leave `::1`
/// portless (and unbracketed, so unusable as an authority). We detect a real
/// port instead: a bracketed literal has one only after the `]`
/// (`[::1]:443`), and any other host has one only when there's exactly one
/// colon (`example.com:8080` / `10.0.0.1:80`). Anything unbracketed with more
/// than one colon is a bare IPv6 literal (with or without a would-be port we
/// can't safely split off), so we bracket the WHOLE thing and append the
/// default — `2001:db8::1` → `[2001:db8::1]:80`.
fn with_scheme_port(host: &str, scheme: &str) -> String {
    let default_port = if scheme == "https" { 443 } else { 80 };
    let has_port = if let Some(after) = host.rsplit_once(']') {
        // Bracketed literal: a port exists only as a `:NNNN` suffix after `]`.
        after.1.starts_with(':')
    } else {
        // Unbracketed: a single colon is a `host:port`; several colons is a bare
        // IPv6 literal with no separable port.
        host.matches(':').count() == 1
    };
    if has_port {
        host.to_string()
    } else if host.matches(':').count() > 1 && !host.starts_with('[') {
        // Unbracketed with multiple colons — a bare IPv6 literal with no port we
        // can tell apart. Bracket the whole thing so the authority is valid
        // rather than splitting on the last colon and swallowing the address.
        format!("[{host}]:{default_port}")
    } else {
        format!("{host}:{default_port}")
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
