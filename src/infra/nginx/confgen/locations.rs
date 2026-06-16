//! location-block rendering (proxy/static/custom path rules).
use super::*;

/// The location block(s) for a site's forwarding kind, plus any NPM-style
/// options (block-exploits / asset caching / websockets) and custom path rules.
/// Async because a `proxy_container` site in host mode must resolve the
/// container's IP (the host's nginx can't resolve a container name).
pub(crate) async fn render_location(lo: &Layout, site: &Site, strip_auth: bool) -> Result<String> {
    let mut out = String::new();

    // Optional: block common exploit patterns (server-scoped, before locations).
    if site.block_attacks {
        out.push_str(BLOCK_EXPLOITS);
    }

    // When trusting an upstream proxy, forward its declared protocol instead of
    // our own connection scheme.
    let fwd = if site.trust_proxy {
        "$dn7_fwd_proto"
    } else {
        "$scheme"
    };
    match site.kind.as_str() {
        "proxy_host" | "proxy_container" => {
            out.push_str(&render_proxy_locations(lo, site, fwd, strip_auth).await?);
        }
        "static" => out.push_str(&render_static_locations(lo, site)),
        _ => {}
    }
    out.push_str(&render_custom_locations(site, fwd, strip_auth).await?);
    Ok(out)
}

/// Proxy-site location blocks: the main `/` upstream, plus an optional
/// long-cache block for static assets (still proxied upstream).
async fn render_proxy_locations(
    lo: &Layout,
    site: &Site,
    fwd: &str,
    strip_auth: bool,
) -> Result<String> {
    let upstream = resolve_upstream(lo, site).await?;
    let mut out = proxy_location(&ProxyLocation {
        path: "/",
        scheme: &site.scheme,
        upstream: &upstream,
        websockets: site.websockets,
        cache: false,
        fwd_proto: fwd,
        strip_auth,
    });
    if site.cache {
        out.push_str(&proxy_location(&ProxyLocation {
            path: &format!("~* \\.({ASSET_EXT})$"),
            scheme: &site.scheme,
            upstream: &upstream,
            websockets: site.websockets,
            cache: true,
            fwd_proto: fwd,
            strip_auth,
        }));
    }
    Ok(out)
}

/// Static-site location blocks: document root + try_files, plus an optional
/// asset-cache block.
fn render_static_locations(lo: &Layout, site: &Site) -> String {
    let root = if site.local_root.is_empty() {
        format!("{}/{}", lo.www_ref, site.root)
    } else {
        site.local_root.clone()
    };
    let mut out = format!(
        "    root {root};\n    index index.html index.htm;\n\n    location / {{\n        try_files $uri $uri/ =404;\n    }}\n"
    );
    if site.cache {
        out.push_str(&format!(
            "    location ~* \\.({ASSET_EXT})$ {{\n        expires 7d;\n        add_header Cache-Control \"public, max-age=604800\";\n        try_files $uri =404;\n    }}\n"
        ));
    }
    out
}

/// NPM-style custom path rules: forward a prefix upstream. Skips a "/" rule when
/// the main block already proxies "/" (a duplicate location fails `nginx -t`).
async fn render_custom_locations(site: &Site, fwd: &str, strip_auth: bool) -> Result<String> {
    let is_proxy = matches!(site.kind.as_str(), "proxy_host" | "proxy_container");
    let mut out = String::new();
    for l in &site.locations {
        if l.path == "/" && is_proxy {
            continue;
        }
        let upstream = if l.kind == "container" {
            resolve_container_upstream(&l.container, l.container_port).await?
        } else {
            with_scheme_port(&l.target, &l.scheme)
        };
        out.push_str(&proxy_location(&ProxyLocation {
            path: &l.path,
            scheme: &l.scheme,
            upstream: &upstream,
            websockets: l.websockets,
            cache: false,
            fwd_proto: fwd,
            strip_auth,
        }));
    }
    Ok(out)
}

/// Common static-asset extensions for the "cache assets" option.
pub(crate) const ASSET_EXT: &str =
    "css|js|jpe?g|png|gif|ico|svg|webp|avif|woff2?|ttf|otf|eot|mp4|webm|mp3|map";

/// A modest set of "block common exploits" rules (query-string based), placed
/// at the top of the server block. Returns 403 on obvious probing patterns.
pub(crate) const BLOCK_EXPLOITS: &str = "    # block common exploits\n\
    if ($query_string ~* \"(<|%3C).*script.*(>|%3E)\") { return 403; }\n\
    if ($query_string ~* \"GLOBALS(=|\\[|%[0-9A-Z]{0,2})\") { return 403; }\n\
    if ($query_string ~* \"_REQUEST(=|\\[|%[0-9A-Z]{0,2})\") { return 403; }\n\
    if ($query_string ~* \"proc/self/environ\") { return 403; }\n\
    if ($query_string ~* \"base64_(en|de)code\\(.*\\)\") { return 403; }\n\n";

/// Inputs for one reverse-proxy `location` block (bundled to keep
/// `proxy_location` within the param-count limit).
pub(crate) struct ProxyLocation<'a> {
    pub(crate) path: &'a str,
    pub(crate) scheme: &'a str,
    pub(crate) upstream: &'a str,
    pub(crate) websockets: bool,
    /// Adds long `expires` for static assets.
    pub(crate) cache: bool,
    pub(crate) fwd_proto: &'a str,
    /// Don't forward the Basic-Auth header upstream (access list, Pass-Auth off).
    pub(crate) strip_auth: bool,
}

/// A reverse-proxy location with sane forwarded headers.
pub(crate) fn proxy_location(p: &ProxyLocation) -> String {
    let mut b = String::new();
    b.push_str(&format!("    location {} {{\n", p.path));
    b.push_str(&format!(
        "        proxy_pass {}://{};\n",
        p.scheme, p.upstream
    ));
    b.push_str("        proxy_set_header Host $host;\n");
    b.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
    b.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    b.push_str(&format!(
        "        proxy_set_header X-Forwarded-Proto {};\n",
        p.fwd_proto
    ));
    if p.strip_auth {
        b.push_str("        proxy_set_header Authorization \"\";\n");
    }
    if p.websockets {
        b.push_str("        proxy_http_version 1.1;\n");
        b.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
        b.push_str("        proxy_set_header Connection $dn7_conn_upgrade;\n");
    }
    if p.cache {
        b.push_str("        expires 7d;\n");
        b.push_str("        add_header Cache-Control \"public\";\n");
    }
    b.push_str("    }\n");
    b
}

/// Build `host:port` from a host token + scheme, defaulting the port to 80
/// (http) or 443 (https) when none is given.
pub(crate) fn with_scheme_port(host: &str, scheme: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else if scheme == "https" {
        format!("{host}:443")
    } else {
        format!("{host}:80")
    }
}
