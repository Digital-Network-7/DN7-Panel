//! Site CRUD: add / remove / update, incl. per-site cert preparation (split from sites.rs).
use super::*;

/// Add a site. For SSL with Let's Encrypt, issuance runs detached (returns an
/// op_id); otherwise the site is generated + validated synchronously.
pub(crate) async fn add_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    cleanup_orphan_confs(&lo);
    let site = site_from_req(req)?;
    if server_name_taken(&site.server_name, &site.id) {
        return Err(anyhow!("ERR_CODE:nginx.duplicate_domain"));
    }

    // Prepare certs.
    if site.ssl {
        if !site.cert_name.is_empty() {
            // Reference an existing standalone named cert — must already exist.
            if !named_crt_file(&lo, &site.cert_name).exists() {
                return Err(anyhow!("引用的证书「{}」不存在", site.cert_name));
            }
        } else {
            match site.cert_mode.as_str() {
                "self" => {
                    gen_self_signed(&lo, &site).await?;
                }
                "manual" => {
                    let cert = req.cert_pem.as_deref().unwrap_or("");
                    let key = req.key_pem.as_deref().unwrap_or("");
                    if cert.trim().is_empty() || key.trim().is_empty() {
                        return Err(anyhow!("ERR_CODE:nginx.need_cert_key"));
                    }
                    write_cert_files(&lo, &site, cert, key)?;
                }
                "le" => {
                    // Detached: write an HTTP-only site first so the ACME http-01
                    // challenge can be served, then issue, then rewrite with SSL.
                    return start_cert_issue(lo, site).await;
                }
                _ => {}
            }
        }
    }

    // Generate + validate.
    write_site_conf(&lo, &site, &[]).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back the conf we just wrote.
        let _ = std::fs::remove_file(conf_path(&lo, &site.id));
        return Err(e);
    }

    let mut sites = load_sites();
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(json!({ "site": site }))
}

pub(crate) async fn remove_site(cmd: &RemoveSite) -> Result<Value> {
    let lo = layout()?;
    let site_id = cmd
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_site_id"))?;
    let mut sites = load_sites();
    let before = sites.len();
    let removed: Vec<Site> = sites.iter().filter(|s| s.id == site_id).cloned().collect();
    sites.retain(|s| s.id != site_id);
    if sites.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.site_not_found"));
    }
    let _ = std::fs::remove_file(conf_path(&lo, site_id));
    // Clean up cert files for removed sites (best-effort).
    for s in &removed {
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.crt", s.id)));
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.key", s.id)));
    }
    save_sites(&sites)?;
    let _ = validate_and_reload(&lo).await;
    Ok(json!({ "removed": site_id }))
}

/// Edit an existing site in place (same id). Mirrors `add_site`'s validation +
/// cert handling, but reuses the existing id and rolls back to the previous
/// config on a validation failure. To avoid needless churn (and Let's Encrypt
/// rate limits), an existing cert is reused when the SSL mode/host is unchanged
/// and a cert is already present; manual mode keeps the stored cert when no new
/// PEM is supplied.
pub(crate) async fn update_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site_id = req
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_site_id"))?;
    let mut sites = load_sites();
    let old = sites
        .iter()
        .find(|s| s.id == site_id)
        .cloned()
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.site_not_found"))?;

    let mut site = site_from_req(req)?;
    site.id = old.id.clone();
    if server_name_taken(&site.server_name, &site.id) {
        return Err(anyhow!("ERR_CODE:nginx.duplicate_domain"));
    }
    cleanup_orphan_confs(&lo);

    // Prepare the cert (write manual files / regenerate self-signed as needed).
    // A Let's Encrypt (re)issue runs detached, so return its op immediately.
    if let CertPrep::ReissueLe = prepare_site_cert(&lo, req, &old, &site).await? {
        return start_cert_issue(lo, site).await;
    }

    write_site_conf(&lo, &site, &[]).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back to the previous configuration.
        let _ = write_site_conf(&lo, &old, &[]).await;
        let _ = validate_and_reload(&lo).await;
        return Err(e);
    }
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(json!({ "site": site }))
}

/// Outcome of preparing a site's certificate before writing its conf.
pub(crate) enum CertPrep {
    /// The cert is ready on disk (manual written / self-signed (re)generated /
    /// an existing cert reused) — proceed to write the conf synchronously.
    Ready,
    /// A Let's Encrypt issue/renewal is required; the caller must start it
    /// detached and return immediately.
    ReissueLe,
}

/// Ensure the per-site certificate exists for an SSL site update: write manual
/// cert files, regenerate a self-signed pair, or decide a Let's Encrypt reissue
/// is needed. No-op for non-SSL sites or sites referencing a named cert.
pub(crate) async fn prepare_site_cert(
    lo: &Layout,
    req: &Req,
    old: &Site,
    site: &Site,
) -> Result<CertPrep> {
    if !site.ssl {
        return Ok(CertPrep::Ready);
    }
    if !site.cert_name.is_empty() {
        if !named_crt_file(lo, &site.cert_name).exists() {
            return Err(anyhow!("ERR_CODE:nginx.cert_not_found"));
        }
        return Ok(CertPrep::Ready);
    }
    let have = lo.cert_store.join(format!("{}.crt", site.id)).exists()
        && lo.cert_store.join(format!("{}.key", site.id)).exists();
    match site.cert_mode.as_str() {
        "manual" => {
            let cert = req.cert_pem.as_deref().unwrap_or("");
            let key = req.key_pem.as_deref().unwrap_or("");
            if !cert.trim().is_empty() && !key.trim().is_empty() {
                write_cert_files(lo, site, cert, key)?;
            } else if !have {
                return Err(anyhow!("ERR_CODE:nginx.need_cert_key"));
            }
        }
        "le" => {
            // Reissue when there's no usable cert, the mode/cert changed, or the
            // primary domain changed; otherwise reuse the existing LE cert.
            let host_changed = primary_host(&old.server_name) != primary_host(&site.server_name);
            if !have || old.cert_mode != "le" || !old.cert_name.is_empty() || host_changed {
                return Ok(CertPrep::ReissueLe);
            }
        }
        "self" if !have || old.cert_mode != "self" || !old.cert_name.is_empty() => {
            gen_self_signed(lo, site).await?;
        }
        _ => {}
    }
    Ok(CertPrep::Ready)
}
