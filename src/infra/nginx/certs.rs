//! Certificates: self-signed + Lets Encrypt issuance (split from nginx.rs).
use super::*;

mod acme;
use acme::*;

// Certificates.
// ---------------------------------------------------------------------------

/// Write user-supplied cert + key to the cert store (manual mode).
pub(crate) fn write_cert_files(
    lo: &Layout,
    site: &Site,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(lo.cert_store.join(format!("{}.crt", site.id)), cert_pem)?;
    write_key_file(&lo.cert_store.join(format!("{}.key", site.id)), key_pem)?;
    Ok(())
}

/// Write a private key file with owner-only (0600) permissions from creation,
/// so it never lands world-readable even briefly (default umask would make a
/// plain `write` 0644). All private-key writes go through here.
pub(crate) fn write_key_file(path: &std::path::Path, pem: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, pem)?;
    }
    // `.mode()` only applies on create; chmod covers a pre-existing looser file.
    set_key_perms(path);
    Ok(())
}

/// Generate a self-signed cert/key pair for the site's primary host using
/// pure-Rust `rcgen` (no `openssl` dependency). Writes into the host cert store
/// that the host nginx reads from.
pub(crate) async fn gen_self_signed(lo: &Layout, site: &Site) -> Result<()> {
    let host = primary_host(&site.server_name);
    let host = if host == "_" {
        "localhost".to_string()
    } else {
        host
    };
    let crt_path = lo.cert_store.join(format!("{}.crt", site.id));
    let key_path = lo.cert_store.join(format!("{}.key", site.id));
    gen_self_signed_to(&crt_path, &key_path, &host).await
}

/// Generate a self-signed cert/key pair for `host` and write them to the given
/// paths. Shared by per-site and standalone-named cert generation.
pub(crate) async fn gen_self_signed_to(
    crt_path: &std::path::Path,
    key_path: &std::path::Path,
    host: &str,
) -> Result<()> {
    if let Some(dir) = crt_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let host = if host.is_empty() || host == "_" {
        "localhost".to_string()
    } else {
        host.to_string()
    };

    let mut params = rcgen::CertificateParams::new(vec![host.clone()])
        .map_err(|e| anyhow!("生成证书参数失败：{e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.clone());
    // 10-year validity (self-signed; the browser will warn regardless).
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(3650 * 24 * 3600)).into();

    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("签发自签证书失败：{e}"))?;

    std::fs::write(crt_path, cert.pem())?;
    write_key_file(key_path, &key_pair.serialize_pem())?;
    Ok(())
}

/// Best-effort: restrict a private key file to owner-only (0600).
pub(crate) fn set_key_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Issue a Let's Encrypt cert via the ACME HTTP-01 challenge, detached. The flow:
///   1. serve the challenge inline from an HTTP conf for the domain,
///   2. run the ACME order + validation,
///   3. install the issued cert into our cert store,
///   4. rewrite the conf with SSL and reload.
pub(crate) async fn start_cert_issue(lo: Layout, site: Site) -> Result<Value> {
    let op_id = new_op_id();
    let target = primary_host(&site.server_name);
    op_create(&op_id, "cert", &target);
    let op_id_ret = op_id.clone();
    tokio::spawn(async move {
        match issue_le(&op_id, &lo, &site).await {
            Ok(()) => {
                op_push(&op_id, &pmsg("ng.cert_done_https", &[]));
                op_finish(&op_id, "done", "");
            }
            Err(e) => op_finish(&op_id, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": op_id_ret, "target": target }))
}

pub(crate) async fn issue_le(op_id: &str, lo: &Layout, site: &Site) -> Result<()> {
    let host = primary_host(&site.server_name);
    if host.is_empty() || host == "_" || host.contains('*') {
        return Err(anyhow!("ERR_CODE:nginx.le_need_domain_specific"));
    }

    // Pin this site's conf id for the issuance window so a concurrent
    // cleanup_orphan_confs (the site isn't in sites.json yet) can't delete the
    // challenge block out from under HTTP-01 validation.
    let _issuing = IssuingGuard::new(&site.id);

    // Steps 1-5: serve the HTTP-01 challenge inline from the site's HTTP conf
    // (no webroot — so it works regardless of file perms / SELinux), then run
    // the ACME dance. The `serve` callback writes the conf + reloads once the
    // challenge tokens are known.
    op_push(op_id, &pmsg("ng.prep_http", &[]));
    let (cert_chain_pem, key_pem) = {
        let lo2 = lo.clone();
        let mut http_site = site.clone();
        http_site.ssl = false;
        acme_http01(op_id, &host, move |chals| async move {
            write_site_conf(&lo2, &http_site, &chals).await?;
            validate_and_reload(&lo2).await
        })
        .await?
    };

    // Persist the issued chain + key into the certificate library (a named
    // cert), so the cert shows up under SSL certificate management and is
    // covered by the named-cert auto-renewal loop. Scope the manifest RMW under
    // state_lock (lost-update guard vs. operator cert ops / the renewal loop),
    // then DROP it before attach_named_cert_to_site (which re-acquires the same
    // non-reentrant lock for the sites RMW).
    let cert_name = {
        let _state = state_lock().lock().await;
        let mut certs = load_named_certs();
        let cert_name = unique_le_cert_name(&certs, &host, &site.id);
        std::fs::create_dir_all(&lo.cert_store)?;
        std::fs::write(named_crt_file(lo, &cert_name), cert_chain_pem)?;
        write_key_file(&named_key_file(lo, &cert_name), &key_pem)?;
        certs.retain(|c| c.name != cert_name);
        certs.push(NamedCert {
            name: cert_name.clone(),
            domain: host.clone(),
            cert_mode: "le".to_string(),
        });
        save_named_certs(&certs)?;
        cert_name
    };

    // Point the site at the library cert and rewrite with SSL + reload.
    op_push(op_id, &pmsg("ng.enable_https", &[]));
    attach_named_cert_to_site(lo, site, cert_name).await
}

/// The name to store an LE cert for `host` under: reuse an existing same-domain
/// entry's name, else derive a unique one from the host (falling back to
/// `le-<site_id>` when the host isn't a valid cert-name token).
fn unique_le_cert_name(certs: &[NamedCert], host: &str, site_id: &str) -> String {
    if let Some(c) = certs.iter().find(|c| c.domain.eq_ignore_ascii_case(host)) {
        return c.name.clone();
    }
    let base = if valid_cert_name(host) {
        host.to_string()
    } else {
        format!("le-{site_id}")
    };
    let mut name = base.clone();
    let mut i = 1;
    while certs.iter().any(|c| c.name == name) {
        name = format!("{base}-{i}");
        i += 1;
    }
    name
}

/// Point `site` at a named cert, then rewrite its conf with SSL on, reload, and
/// persist the updated site.
async fn attach_named_cert_to_site(lo: &Layout, site: &Site, cert_name: String) -> Result<()> {
    let _state = state_lock().lock().await; // serialize sites RMW (no lost update)
    let mut site = site.clone();
    site.cert_mode = "named".to_string();
    site.cert_name = cert_name;
    write_site_conf(lo, &site, &[]).await?;
    validate_and_reload(lo).await?;
    let mut sites = load_sites();
    sites.retain(|s| s.id != site.id);
    sites.push(site);
    save_sites(&sites)?;
    Ok(())
}

/// Issue a standalone Let's Encrypt cert (detached). Serves the HTTP-01
/// challenge from a temporary HTTP-only conf for `domain`, then writes the
/// issued chain/key into the named cert store and records the manifest.
pub(crate) fn start_named_cert_issue(lo: Layout, name: String, domain: String) -> Result<Value> {
    let op_id = new_op_id();
    let target = primary_host(&domain);
    op_create(&op_id, "cert", &target);
    let op_id_ret = op_id.clone();
    tokio::spawn(async move {
        match issue_le_named(&op_id, &lo, &name, &domain).await {
            Ok(()) => {
                op_push(&op_id, &pmsg("ng.cert_done", &[]));
                op_finish(&op_id, "done", "");
            }
            Err(e) => op_finish(&op_id, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": op_id_ret, "target": target }))
}

pub(crate) async fn issue_le_named(
    op_id: &str,
    lo: &Layout,
    name: &str,
    domain: &str,
) -> Result<()> {
    let host = primary_host(domain);
    if host.is_empty() || host == "_" || host.contains('*') {
        return Err(anyhow!("ERR_CODE:nginx.le_need_domain_specific"));
    }

    // Steps 1-5: serve the HTTP-01 challenge from a temporary conf for this
    // domain (challenges answered inline — no webroot), then run the ACME dance.
    op_push(op_id, &pmsg("ng.prep_http", &[]));
    let conf_id = format!("acme-{name}");
    // Pin the temp challenge conf for the issuance window so cleanup can't
    // delete it mid-validation.
    let _issuing = IssuingGuard::new(&conf_id);
    let conf_file = conf_path(lo, &conf_id);
    let dance = {
        let lo2 = lo.clone();
        let host2 = host.clone();
        let conf_file2 = conf_file.clone();
        acme_http01(op_id, &host, move |chals| async move {
            let conf = format!(
                "server {{\n    listen 80;\n    server_name {host2};\n{loc}\
                 \n    location / {{\n        return 404;\n    }}\n}}\n",
                loc = acme_challenge_locations(&chals)
            );
            std::fs::create_dir_all(&lo2.confd)?;
            std::fs::write(&conf_file2, conf)?;
            validate_and_reload(&lo2).await
        })
        .await
    };

    // Always drop the temporary challenge conf afterwards.
    let _ = std::fs::remove_file(&conf_file);
    let _ = validate_and_reload(lo).await;

    let (cert_chain_pem, key_pem) = dance?;

    // Persist into the named cert store + manifest (serialized vs. operator cert
    // ops / the renewal loop — lost-update guard on certs.json).
    std::fs::write(named_crt_file(lo, name), cert_chain_pem)?;
    write_key_file(&named_key_file(lo, name), &key_pem)?;
    {
        let _state = state_lock().lock().await;
        let mut certs = load_named_certs();
        certs.retain(|c| c.name != name);
        certs.push(NamedCert {
            name: name.to_string(),
            domain: domain.to_string(),
            cert_mode: "le".to_string(),
        });
        save_named_certs(&certs)?;
    }
    Ok(())
}
