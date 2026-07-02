//! Site CRUD: add / remove / update, incl. per-site cert preparation (split from sites.rs).
use super::*;

/// Add a site. For SSL with Let's Encrypt, issuance runs detached (returns an
/// op_id); otherwise the site is generated + validated synchronously.
pub(crate) async fn add_site(form: &SiteForm) -> Result<Value> {
    let _state = state_lock().lock().await; // serialize sites RMW (no lost update)
    let lo = layout()?;
    let site = site_from_req(form)?;
    if server_name_taken(&site.server_name, &site.id) {
        return Err(website_err(WebsiteError::DuplicateDomain));
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
                    let cert = form.cert_pem.as_deref().unwrap_or("");
                    let key = form.key_pem.as_deref().unwrap_or("");
                    if cert.trim().is_empty() || key.trim().is_empty() {
                        return Err(website_err(WebsiteError::NeedCertKey));
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

    // Persist the manifest, then rebuild the edge route table from it — rolling
    // back the manifest if the new model is rejected. Strict load: refuse to add
    // (quarantining the bad file) if sites.json is corrupt, rather than dropping
    // every existing site by RMW-ing an empty default over it.
    let mut sites = load_sites_strict()?;
    sites.push(site.clone());
    save_sites(&sites)?;
    if let Err(e) = validate_and_reload(&lo).await {
        sites.retain(|s| s.id != site.id);
        save_sites(&sites)?;
        let _ = validate_and_reload(&lo).await;
        return Err(e);
    }
    Ok(json!({ "site": site }))
}

pub(crate) async fn remove_site(cmd: &RemoveSite) -> Result<Value> {
    let _state = state_lock().lock().await; // serialize sites RMW (no lost update)
    let lo = layout()?;
    let site_id = cmd
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| website_err(WebsiteError::MissingSiteId))?;
    // Strict load: a corrupt sites.json is quarantined + refused, never RMW'd
    // away (which would silently drop every other site on a single removal).
    let mut sites = load_sites_strict()?;
    let before = sites.len();
    let removed: Vec<Site> = sites.iter().filter(|s| s.id == site_id).cloned().collect();
    sites.retain(|s| s.id != site_id);
    if sites.len() == before {
        return Err(website_err(WebsiteError::SiteNotFound));
    }
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
pub(crate) async fn update_site(form: &SiteForm) -> Result<Value> {
    let _state = state_lock().lock().await; // serialize sites RMW (no lost update)
    let lo = layout()?;
    let site_id = form
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| website_err(WebsiteError::MissingSiteId))?;
    // Strict load: a corrupt sites.json is quarantined + refused, never RMW'd
    // away (which would silently drop every other site on a single edit).
    let mut sites = load_sites_strict()?;
    let old = sites
        .iter()
        .find(|s| s.id == site_id)
        .cloned()
        .ok_or_else(|| website_err(WebsiteError::SiteNotFound))?;

    let mut site = site_from_req(form)?;
    site.id = old.id.clone();
    if server_name_taken(&site.server_name, &site.id) {
        return Err(website_err(WebsiteError::DuplicateDomain));
    }

    // Snapshot the existing per-site cert files BEFORE prepare_site_cert may
    // overwrite them (manual/self modes write <id>.crt/.key), so a failed reload
    // can restore the cert to match the rolled-back manifest — otherwise the old
    // site config would be left pointing at the new cert material.
    let crt_path = lo.cert_store.join(format!("{}.crt", site.id));
    let key_path = lo.cert_store.join(format!("{}.key", site.id));
    let crt_bak = std::fs::read_to_string(&crt_path).ok();
    let key_bak = std::fs::read_to_string(&key_path).ok();

    // Prepare the cert (write manual files / regenerate self-signed as needed).
    // A Let's Encrypt (re)issue runs detached, so return its op immediately.
    if let CertPrep::ReissueLe = prepare_site_cert(&lo, form, &old, &site).await? {
        return start_cert_issue(lo, site).await;
    }

    // Persist the replaced manifest, then rebuild the edge route table from it —
    // restoring the previous site on failure.
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    save_sites(&sites)?;
    if let Err(e) = validate_and_reload(&lo).await {
        sites.retain(|s| s.id != old.id);
        sites.push(old.clone());
        save_sites(&sites)?;
        // Restore (or remove) the per-site cert files to match the old manifest.
        match &crt_bak {
            Some(pem) => {
                let _ = std::fs::write(&crt_path, pem);
            }
            None => {
                let _ = std::fs::remove_file(&crt_path);
            }
        }
        match &key_bak {
            Some(pem) => {
                let _ = write_key_file(&key_path, pem);
            }
            None => {
                let _ = std::fs::remove_file(&key_path);
            }
        }
        let _ = validate_and_reload(&lo).await;
        return Err(e);
    }
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
    form: &SiteForm,
    old: &Site,
    site: &Site,
) -> Result<CertPrep> {
    if !site.ssl {
        return Ok(CertPrep::Ready);
    }
    if !site.cert_name.is_empty() {
        if !named_crt_file(lo, &site.cert_name).exists() {
            return Err(website_err(WebsiteError::CertNotFound));
        }
        return Ok(CertPrep::Ready);
    }
    let have = lo.cert_store.join(format!("{}.crt", site.id)).exists()
        && lo.cert_store.join(format!("{}.key", site.id)).exists();
    match site.cert_mode.as_str() {
        "manual" => {
            let cert = form.cert_pem.as_deref().unwrap_or("");
            let key = form.key_pem.as_deref().unwrap_or("");
            if !cert.trim().is_empty() && !key.trim().is_empty() {
                write_cert_files(lo, site, cert, key)?;
            } else if !have {
                return Err(website_err(WebsiteError::NeedCertKey));
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
