//! nginx config generation (all values pre-validated) (split from nginx.rs).
use super::*;

// Config generation. All values are pre-validated, so they're safe to embed.
// ---------------------------------------------------------------------------

/// Inline nginx locations that answer the ACME HTTP-01 challenge directly from
/// config (`return 200 "<keyAuthorization>"`). Serving the response inline —
/// rather than from a webroot file — means issuance never depends on a webroot
/// the nginx worker can read (file perms, SELinux context, path), which is the
/// usual cause of "domain validation failed" on existing/host nginx setups.
pub(crate) fn acme_challenge_locations(acme: &[(String, String)]) -> String {
    let mut s = String::new();
    for (token, keyauth) in acme {
        s.push_str(&format!(
            "\n    location = /.well-known/acme-challenge/{token} {{\n        auth_basic off;\n        allow all;\n        default_type text/plain;\n        return 200 \"{keyauth}\";\n    }}\n"
        ));
    }
    s
}

/// Generate the nginx server block(s) for a site and write the conf file. When
/// `acme` is non-empty, the port-80 block also answers those HTTP-01 challenges
/// inline (used during Let's Encrypt issuance).
pub(crate) async fn write_site_conf(
    lo: &Layout,
    site: &Site,
    acme: &[(String, String)],
) -> Result<()> {
    // Resolve the assigned access list (if any) and build its directives.
    let access = if site.access_id.is_empty() {
        None
    } else {
        load_access().into_iter().find(|a| a.id == site.access_id)
    };
    let strip_auth = access.as_ref().map(|a| !a.pass_auth).unwrap_or(false);
    let auth = render_auth_block(access.as_ref());

    let body = render_location(lo, site, strip_auth).await?;
    let server_name = &site.server_name;
    let acme_loc = acme_challenge_locations(acme);

    let mut conf = String::new();
    let extra = render_extra_conf(&site.extra_conf);
    let tuning = render_tuning_block();
    if site.ssl {
        let (crt, key) = if site.cert_name.is_empty() {
            (
                format!("{}/{}.crt", lo.cert_ref, site.id),
                format!("{}/{}.key", lo.cert_ref, site.id),
            )
        } else {
            // Referenced standalone named cert.
            (
                format!("{}/cert-{}.crt", lo.cert_ref, site.cert_name),
                format!("{}/cert-{}.key", lo.cert_ref, site.cert_name),
            )
        };
        // HTTP block: redirect to HTTPS (Force SSL) or serve the site over HTTP
        // too. The ACME challenge is always answered first.
        if site.force_ssl {
            conf.push_str(&format!(
                "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\
                 \n    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\n"
            ));
        } else {
            conf.push_str(&format!(
                "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\n{tuning}{auth}{extra}{body}}}\n\n"
            ));
        }
        // HTTPS block.
        let listen443 = if site.http2 {
            "listen 443 ssl http2;"
        } else {
            "listen 443 ssl;"
        };
        let mut sec = String::new();
        if site.trust_proxy {
            // Honour a trusted front proxy / CDN's real-client + protocol headers.
            sec.push_str(
                "    set_real_ip_from 0.0.0.0/0;\n    set_real_ip_from ::/0;\n\
                 \x20   real_ip_header X-Forwarded-For;\n    real_ip_recursive on;\n",
            );
        }
        if site.hsts {
            let sub = if site.hsts_sub {
                "; includeSubDomains"
            } else {
                ""
            };
            sec.push_str(&format!(
                "    add_header Strict-Transport-Security \"max-age=63072000{sub}\" always;\n"
            ));
        }
        conf.push_str(&format!(
            "server {{\n    {listen443}\n    server_name {server_name};\n\
             \n    ssl_certificate {crt};\n    ssl_certificate_key {key};\n{sec}\
             \n{tuning}{auth}{extra}{body}}}\n"
        ));
    } else {
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\n{tuning}{auth}{extra}{body}}}\n"
        ));
    }

    std::fs::create_dir_all(&lo.confd)?;
    std::fs::write(conf_path(lo, &site.id), conf)?;
    Ok(())
}

/// Build the server-level access-control directives for an access list:
/// `satisfy`, `allow`/`deny` rules, and `auth_basic` + `auth_basic_user_file`.
/// Returns an empty string when the list is absent or has no rules.
pub(crate) fn render_auth_block(access: Option<&AccessList>) -> String {
    let a = match access {
        Some(a) => a,
        None => return String::new(),
    };
    let has_auth = !a.users.is_empty();
    let has_clients = !a.clients.is_empty();
    if !has_auth && !has_clients {
        return String::new();
    }
    let mut s = String::from("\n");
    // `satisfy` only matters when both factors are present, but it's harmless
    // otherwise and makes the intent explicit.
    if has_auth && has_clients {
        let mode = if a.satisfy == "all" { "all" } else { "any" };
        s.push_str(&format!("    satisfy {mode};\n"));
    }
    if has_clients {
        for c in &a.clients {
            let dir = if c.directive == "deny" {
                "deny"
            } else {
                "allow"
            };
            s.push_str(&format!("    {dir} {};\n", c.address));
        }
    }
    if has_auth {
        s.push_str(&format!(
            "    auth_basic \"{}\";\n",
            a.name.replace('"', "")
        ));
        s.push_str(&format!(
            "    auth_basic_user_file {};\n",
            htpasswd_path(&a.id).display()
        ));
    }
    s.push('\n');
    s
}

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

    let is_proxy = matches!(site.kind.as_str(), "proxy_host" | "proxy_container");
    // When trusting an upstream proxy, forward its declared protocol instead of
    // our own connection scheme.
    let fwd = if site.trust_proxy {
        "$dn7_fwd_proto"
    } else {
        "$scheme"
    };
    match site.kind.as_str() {
        "proxy_host" | "proxy_container" => {
            let upstream = resolve_upstream(lo, site).await?;
            out.push_str(&proxy_location(
                "/",
                &site.scheme,
                &upstream,
                site.websockets,
                false,
                fwd,
                strip_auth,
            ));
            // Optional: long-cache static assets (still proxied upstream).
            if site.cache {
                out.push_str(&proxy_location(
                    &format!("~* \\.({ASSET_EXT})$"),
                    &site.scheme,
                    &upstream,
                    site.websockets,
                    true,
                    fwd,
                    strip_auth,
                ));
            }
        }
        "static" => {
            let root = if site.local_root.is_empty() {
                format!("{}/{}", lo.www_ref, site.root)
            } else {
                site.local_root.clone()
            };
            out.push_str(&format!(
                "    root {root};\n    index index.html index.htm;\n\n    location / {{\n        try_files $uri $uri/ =404;\n    }}\n"
            ));
            if site.cache {
                out.push_str(&format!(
                    "    location ~* \\.({ASSET_EXT})$ {{\n        expires 7d;\n        add_header Cache-Control \"public, max-age=604800\";\n        try_files $uri =404;\n    }}\n"
                ));
            }
        }
        _ => {}
    }

    // Custom path rules (NPM-style custom locations): forward a prefix upstream.
    // Skip a rule whose path is "/" when the main block already serves "/" as a
    // proxy (it would duplicate the location and fail `nginx -t`).
    for l in &site.locations {
        if l.path == "/" && is_proxy {
            continue;
        }
        let upstream = if l.kind == "container" {
            resolve_container_upstream(&l.container, l.container_port).await?
        } else {
            with_scheme_port(&l.target, &l.scheme)
        };
        out.push_str(&proxy_location(
            &l.path,
            &l.scheme,
            &upstream,
            l.websockets,
            false,
            fwd,
            strip_auth,
        ));
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

/// A reverse-proxy location with sane forwarded headers. `cache` adds long
/// expires for static assets; `websockets` adds the upgrade headers.
pub(crate) fn proxy_location(
    path: &str,
    scheme: &str,
    upstream: &str,
    websockets: bool,
    cache: bool,
    fwd_proto: &str,
    strip_auth: bool,
) -> String {
    let mut b = String::new();
    b.push_str(&format!("    location {path} {{\n"));
    b.push_str(&format!("        proxy_pass {scheme}://{upstream};\n"));
    b.push_str("        proxy_set_header Host $host;\n");
    b.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
    b.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    b.push_str(&format!(
        "        proxy_set_header X-Forwarded-Proto {fwd_proto};\n"
    ));
    // Access list with "Pass Auth" off: don't leak the Basic-Auth header upstream.
    if strip_auth {
        b.push_str("        proxy_set_header Authorization \"\";\n");
    }
    if websockets {
        b.push_str("        proxy_http_version 1.1;\n");
        b.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
        b.push_str("        proxy_set_header Connection $dn7_conn_upgrade;\n");
    }
    if cache {
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
