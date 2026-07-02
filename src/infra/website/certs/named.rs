//! Standalone named certificates: create / list / delete (split from nginx.rs).
use super::*;

// Standalone named certificates: create / list / delete, independent of sites.
// ---------------------------------------------------------------------------

/// List standalone certs from the manifest, with on-disk presence + expiry.
pub(crate) async fn list_named_certs() -> Result<Value> {
    let lo = layout()?;
    let certs = load_named_certs();
    let in_use = sites_using_certs();
    let mut out = Vec::new();
    for c in &certs {
        let crt = named_crt_file(&lo, &c.name);
        let has_cert = crt.exists();
        let not_after = if has_cert {
            std::fs::read_to_string(&crt)
                .ok()
                .and_then(|pem| parse_cert_not_after(&pem))
                .unwrap_or_default()
        } else {
            String::new()
        };
        out.push(json!({
            "name": c.name,
            "domain": c.domain,
            "cert_mode": c.cert_mode,
            "key_type": if c.key_type.is_empty() { "ecdsa-p256" } else { c.key_type.as_str() },
            "has_cert": has_cert,
            "not_after": not_after,
            "used_by": in_use.get(&c.name).cloned().unwrap_or_default(),
        }));
    }
    Ok(json!({ "certs": out }))
}

/// server_names of sites currently referencing each named cert.
pub(crate) fn sites_using_certs() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for s in load_sites() {
        if !s.cert_name.is_empty() {
            map.entry(s.cert_name).or_default().push(s.server_name);
        }
    }
    map
}

/// Create a standalone named certificate. Modes:
///   - "self":   self-signed for `domain` (synchronous)
///   - "manual": cert_pem + key_pem (synchronous)
///   - "le":     Let's Encrypt for `domain` (detached → returns {op_id})
pub(crate) async fn create_cert(cmd: &CreateCert) -> Result<Value> {
    let lo = layout()?;
    let mode = cmd.cert_mode.as_deref().unwrap_or("self");
    if !matches!(mode, "self" | "le" | "manual") {
        return Err(website_err(WebsiteError::UnknownCertMode));
    }
    let key_type = norm_key_type(cmd.key_type.as_deref().unwrap_or(""));
    // Serialize the manifest read-modify-write against the background renewal
    // loop and other cert ops (lost-update guard on certs.json).
    let _state = state_lock().lock().await;
    let mut certs = load_named_certs();
    let (domain, name) = derive_cert_name(cmd, &certs)?;

    match mode {
        "self" => {
            let host = primary_host(&domain);
            gen_self_signed_to(
                &named_crt_file(&lo, &name),
                &named_key_file(&lo, &name),
                &host,
                &key_type,
            )
            .await?;
        }
        "manual" => write_manual_cert(&lo, cmd, &name)?,
        // Let's Encrypt issuance runs detached and records the manifest itself.
        "le" => return start_named_cert_issue(lo, name, domain, key_type),
        _ => {}
    }

    certs.push(NamedCert {
        name: name.clone(),
        domain,
        cert_mode: mode.to_string(),
        key_type,
    });
    save_named_certs(&certs)?;
    Ok(json!({ "name": name }))
}

/// Validate the requested cert domain and derive its (unique) storage name.
/// Certs are identified by their domain — there's no separate name — so this
/// also enforces one certificate per domain. Returns `(domain, name)`.
fn derive_cert_name(cmd: &CreateCert, certs: &[NamedCert]) -> Result<(String, String)> {
    let domain = cmd
        .server_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if domain.is_empty() {
        return Err(website_err(WebsiteError::NeedCertDomain));
    }
    if !valid_server_name(&domain) {
        return Err(website_err(WebsiteError::BadDomain));
    }
    let name = cert_name_from_domain(&domain);
    if !valid_cert_name(&name) {
        return Err(website_err(WebsiteError::BadCertNameChars));
    }
    if certs
        .iter()
        .any(|c| c.name == name || (!c.domain.is_empty() && c.domain.eq_ignore_ascii_case(&domain)))
    {
        return Err(website_err(WebsiteError::CertDomainExists));
    }
    Ok((domain, name))
}

/// Write a user-supplied (manual) cert + key pair into the named cert store.
fn write_manual_cert(lo: &Layout, cmd: &CreateCert, name: &str) -> Result<()> {
    let cert = cmd.cert_pem.as_deref().unwrap_or("");
    let key = cmd.key_pem.as_deref().unwrap_or("");
    if cert.trim().is_empty() || key.trim().is_empty() {
        return Err(website_err(WebsiteError::NeedCertKey));
    }
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(named_crt_file(lo, name), cert)?;
    write_key_file(&named_key_file(lo, name), key)?;
    Ok(())
}

/// Renew a named cert in place: re-issue (LE) or regenerate (self-signed).
/// Manual certs have no automated renewal.
pub(crate) async fn renew_cert(cmd: &RenewCert) -> Result<Value> {
    let lo = layout()?;
    let name = cmd
        .cert_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| website_err(WebsiteError::MissingCertName))?;
    let cert = load_named_certs()
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| website_err(WebsiteError::CertNotFound))?;
    match cert.cert_mode.as_str() {
        "le" => start_named_cert_issue(
            lo,
            cert.name.clone(),
            cert.domain.clone(),
            cert.key_type.clone(),
        ),
        "self" => {
            if cert.domain.is_empty() {
                return Err(website_err(WebsiteError::NeedCertDomain));
            }
            let host = primary_host(&cert.domain);
            gen_self_signed_to(
                &named_crt_file(&lo, &cert.name),
                &named_key_file(&lo, &cert.name),
                &host,
                &cert.key_type,
            )
            .await?;
            let _ = validate_and_reload(&lo).await;
            Ok(json!({ "renewed": cert.name }))
        }
        _ => Err(website_err(WebsiteError::ManualNoRenew)),
    }
}

/// Delete a standalone named certificate. Refuses while a site still uses it.
pub(crate) async fn delete_cert(cmd: &DeleteCert) -> Result<Value> {
    let lo = layout()?;
    let name = cmd
        .cert_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| website_err(WebsiteError::MissingCertName))?;
    // Hold the lock across the usage check AND the delete, so a concurrent
    // add_site/update_site can't start referencing the cert between the "in use?"
    // check and its removal (TOCTOU → orphaned live-site cert).
    let _state = state_lock().lock().await;
    let in_use = sites_using_certs();
    if let Some(sites) = in_use.get(name) {
        if !sites.is_empty() {
            return Err(anyhow!("证书仍被站点使用：{}", sites.join("、")));
        }
    }
    let mut certs = load_named_certs();
    let before = certs.len();
    certs.retain(|c| c.name != name);
    if certs.len() == before {
        return Err(website_err(WebsiteError::CertNotFound));
    }
    let _ = std::fs::remove_file(named_crt_file(&lo, name));
    let _ = std::fs::remove_file(named_key_file(&lo, name));
    save_named_certs(&certs)?;
    Ok(json!({ "deleted": name }))
}
