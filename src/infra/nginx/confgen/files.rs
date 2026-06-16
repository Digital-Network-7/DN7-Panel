//! Server-block assembly + conf file writing (per-site + 503 stub).
use super::*;

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
        let (crt, key) = cert_paths(lo, site);
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
        let sec = render_ssl_security(site);
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

    // Async fs so the conf write doesn't block the tokio worker (this runs from
    // every nginx admin handler).
    tokio::fs::create_dir_all(&lo.confd).await?;
    tokio::fs::write(conf_path(lo, &site.id), conf).await?;
    Ok(())
}

/// Write a *maintenance stub* conf for a site whose upstream cannot be resolved
/// (e.g. a `proxy_container` site whose backing container was deleted). The stub
/// keeps the site's `server_name` (and TLS, if a cert is present) but answers
/// every request with `503` instead of proxying.
///
/// This is the safety net for the "stale container IP" class of bug: when the
/// real upstream is gone, Docker may recycle its old IP for an *unrelated*
/// container — so re-emitting the previous `proxy_pass <ip>` would silently
/// forward traffic to the wrong service. Returning 503 fails closed instead.
pub(crate) async fn write_unavailable_conf(lo: &Layout, site: &Site) -> Result<()> {
    let server_name = &site.server_name;
    let tuning = render_tuning_block();
    // 503 body kept tiny + explicit so an operator hitting the domain sees why.
    let stub = "    location / {\n        return 503;\n    }\n";

    let mut conf = String::new();
    // Only claim TLS when the cert files actually exist on disk; otherwise a
    // `listen 443 ssl` with no cert would fail `nginx -t` and take the whole
    // reload down — defeating the purpose of failing closed for one site.
    let have_cert = site.ssl && cert_file_on_disk(lo, site);

    if have_cert {
        let (crt, key) = cert_paths(lo, site);
        // Port 80: redirect to HTTPS so the stub behaves like the real site.
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n\
             \n    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\n"
        ));
        let listen443 = if site.http2 {
            "listen 443 ssl http2;"
        } else {
            "listen 443 ssl;"
        };
        conf.push_str(&format!(
            "server {{\n    {listen443}\n    server_name {server_name};\n\
             \n    ssl_certificate {crt};\n    ssl_certificate_key {key};\n\
             \n{tuning}{stub}}}\n"
        ));
    } else {
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n\n{tuning}{stub}}}\n"
        ));
    }

    // Async fs so the conf write doesn't block the tokio worker (this runs from
    // every nginx admin handler).
    tokio::fs::create_dir_all(&lo.confd).await?;
    tokio::fs::write(conf_path(lo, &site.id), conf).await?;
    Ok(())
}

/// Whether the cert + key files a site references actually exist on disk.
fn cert_file_on_disk(lo: &Layout, site: &Site) -> bool {
    if site.cert_name.is_empty() {
        lo.cert_store.join(format!("{}.crt", site.id)).exists()
            && lo.cert_store.join(format!("{}.key", site.id)).exists()
    } else {
        named_crt_file(lo, &site.cert_name).exists()
    }
}

/// The on-disk cert + key paths nginx reads for a site: the per-site pair, or a
/// referenced standalone named cert.
fn cert_paths(lo: &Layout, site: &Site) -> (String, String) {
    if site.cert_name.is_empty() {
        (
            format!("{}/{}.crt", lo.cert_ref, site.id),
            format!("{}/{}.key", lo.cert_ref, site.id),
        )
    } else {
        (
            format!("{}/cert-{}.crt", lo.cert_ref, site.cert_name),
            format!("{}/cert-{}.key", lo.cert_ref, site.cert_name),
        )
    }
}
