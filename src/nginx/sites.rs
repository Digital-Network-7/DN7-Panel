//! Sites: add / remove / generate config / reload (split from nginx.rs).
use super::*;

pub(crate) fn valid_local_root(p: &str) -> Result<String> {
    let path = std::path::Path::new(p);
    if !path.is_absolute() {
        return Err(anyhow!("ERR_CODE:nginx.local_root_abs"));
    }
    let canon =
        std::fs::canonicalize(path).map_err(|_| anyhow!("ERR_CODE:nginx.local_root_missing"))?;
    if !canon.is_dir() {
        return Err(anyhow!("ERR_CODE:nginx.local_root_not_dir"));
    }
    let s = canon.to_string_lossy().to_string();
    const DENY: [&str; 6] = ["/", "/etc", "/root", "/proc", "/sys", "/boot"];
    if DENY.iter().any(|d| s == *d) {
        return Err(anyhow!("ERR_CODE:nginx.local_root_denied"));
    }
    Ok(s)
}

/// Build a site from the request, validating every field.
pub(crate) fn site_from_req(req: &Req) -> Result<Site> {
    let server_name = req
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_domain"))?
        .to_string();
    if !valid_server_name(&server_name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_domain"));
    }
    let kind = req.kind.as_deref().unwrap_or("proxy_host").to_string();
    let ssl = req.ssl.unwrap_or(false);
    let cert_mode = req.cert_mode.as_deref().unwrap_or("self").to_string();
    let cert_name = req
        .cert_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !cert_name.is_empty() && !valid_cert_name(&cert_name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_cert_name"));
    }

    let mut site = Site {
        id: new_site_id(),
        server_name,
        kind: kind.clone(),
        target_url: String::new(),
        container: String::new(),
        container_port: 0,
        root: String::new(),
        local_root: String::new(),
        ssl,
        cert_mode: cert_mode.clone(),
        cert_name: cert_name.clone(),
        scheme: norm_scheme(req.scheme.as_deref()),
        cache: req.cache.unwrap_or(false),
        block_attacks: req.block_attacks.unwrap_or(false),
        websockets: req.websockets.unwrap_or(true),
        force_ssl: req.force_ssl.unwrap_or(true),
        http2: req.http2.unwrap_or(true),
        hsts: req.hsts.unwrap_or(false),
        hsts_sub: req.hsts_sub.unwrap_or(false),
        trust_proxy: req.trust_proxy.unwrap_or(false),
        locations: Vec::new(),
        extra_conf: String::new(),
        access_id: String::new(),
    };

    apply_site_kind(&mut site, req)?;

    // Validate + normalize any custom path rules.
    if let Some(locs) = &req.locations {
        site.locations = validate_locations(locs)?;
    }

    // Optional raw nginx directives (validated structurally here; nginx -t is
    // the final gate when the conf is written).
    let extra = req.extra_conf.as_deref().unwrap_or("").trim();
    validate_extra_conf(extra)?;
    site.extra_conf = extra.to_string();

    site.access_id = resolve_access_ref(req)?;

    if ssl && !matches!(cert_mode.as_str(), "self" | "le" | "manual" | "named") {
        return Err(anyhow!("ERR_CODE:nginx.unknown_cert_mode"));
    }
    Ok(site)
}

/// Set the kind-specific destination fields (proxy target / container+port /
/// static root) on a site from the request, validating each.
fn apply_site_kind(site: &mut Site, req: &Req) -> Result<()> {
    match site.kind.as_str() {
        "proxy_host" => {
            let t = req
                .target_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_target"))?;
            if !valid_host_token(t) {
                return Err(anyhow!("ERR_CODE:nginx.bad_target"));
            }
            site.target_url = t.to_string();
        }
        "proxy_container" => {
            let c = req
                .container
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_container"))?;
            if !valid_container_name(c) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container"));
            }
            let port = req.container_port.unwrap_or(0);
            if !valid_port(port) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container_port"));
            }
            site.container = c.to_string();
            site.container_port = port;
        }
        "static" => {
            // Two sources: an existing absolute host directory (local_root), or
            // a panel-managed upload dir under <www>/<root>.
            let local = req
                .local_root
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            if let Some(p) = local {
                site.local_root = valid_local_root(p)?;
            } else {
                let r = req
                    .root
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_static_dir"))?;
                if !valid_root_segment(r) {
                    return Err(anyhow!("ERR_CODE:nginx.bad_static_dir_name"));
                }
                site.root = r.to_string();
            }
        }
        _ => return Err(anyhow!("ERR_CODE:nginx.unknown_site_kind")),
    }
    Ok(())
}

/// Resolve + validate the optional access-list reference (must exist when set).
fn resolve_access_ref(req: &Req) -> Result<String> {
    let access_id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !access_id.is_empty() && !load_access().iter().any(|a| a.id == access_id) {
        return Err(anyhow!("ERR_CODE:nginx.access_not_found"));
    }
    Ok(access_id)
}

/// Validate + normalize a list of custom path rules.
pub(crate) fn validate_locations(locs: &[Location]) -> Result<Vec<Location>> {
    let mut out = Vec::new();
    for l in locs {
        let path = l.path.trim();
        let kind = if l.kind.trim() == "container" {
            "container"
        } else {
            "host"
        };
        if kind == "container" {
            let container = l.container.trim();
            // Skip fully-empty rows.
            if path.is_empty() && container.is_empty() {
                continue;
            }
            if !valid_location_path(path) {
                return Err(anyhow!("路径规则需以 / 开头且不含空格等特殊字符：{path}"));
            }
            if !valid_container_name(container) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container"));
            }
            if !valid_port(l.container_port) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container_port"));
            }
            out.push(Location {
                path: path.to_string(),
                scheme: norm_scheme(Some(&l.scheme)),
                target: String::new(),
                websockets: l.websockets,
                kind: "container".to_string(),
                container: container.to_string(),
                container_port: l.container_port,
            });
        } else {
            let target = l.target.trim();
            // Skip fully-empty rows (UI may submit blank trailing rows).
            if path.is_empty() && target.is_empty() {
                continue;
            }
            if !valid_location_path(path) {
                return Err(anyhow!("路径规则需以 / 开头且不含空格等特殊字符：{path}"));
            }
            if !valid_host_token(target) {
                return Err(anyhow!("路径规则目标格式不正确（host[:port]）：{target}"));
            }
            out.push(Location {
                path: path.to_string(),
                scheme: norm_scheme(Some(&l.scheme)),
                target: target.to_string(),
                websockets: l.websockets,
                kind: "host".to_string(),
                container: String::new(),
                container_port: 0,
            });
        }
    }
    if out.len() > 50 {
        return Err(anyhow!("ERR_CODE:nginx.too_many_rules"));
    }
    Ok(out)
}

/// Structural validation of raw custom nginx directives. The authoritative
/// syntax check is `nginx -t` (run when the conf is written, with rollback on
/// failure); here we only reject oversized input and stray control characters.
pub(crate) fn validate_extra_conf(s: &str) -> Result<()> {
    if s.len() > 20000 {
        return Err(anyhow!("ERR_CODE:nginx.extra_conf_too_long"));
    }
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(anyhow!("ERR_CODE:nginx.extra_conf_bad"));
    }
    Ok(())
}

/// Indent raw custom directives into the server block. Empty when blank.
pub(crate) fn render_extra_conf(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    let mut s = String::from("\n    # custom configuration\n");
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            s.push('\n');
        } else {
            s.push_str("    ");
            s.push_str(line);
            s.push('\n');
        }
    }
    s
}

pub(crate) fn new_site_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}{}",
        std::process::id() % 100000,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Remove panel-owned conf files that could shadow a fresh write: temporary
/// ACME challenge confs (always disposable) and orphaned `dn7-<id>.conf` files
/// whose site no longer exists (leftovers from an interrupted attempt). A stale
/// conf with the same `server_name` loading before the live one makes nginx
/// answer from the wrong block — which breaks HTTP-01 validation (404).
pub(crate) fn cleanup_orphan_confs(lo: &Layout) {
    use std::collections::HashSet;
    // Determine live site ids safely. If sites.json exists but can't be read or
    // parsed, do NOT treat every conf as an orphan (that would delete all site
    // configs) — skip cleanup this round.
    let path = sites_file();
    let live: HashSet<String> = if path.exists() {
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<Site>>(&s).ok())
        {
            Some(sites) => sites.into_iter().map(|s| s.id).collect(),
            None => return, // unreadable/corrupt — be safe, remove nothing
        }
    } else {
        HashSet::new() // no sites file → any dn7-*.conf is a genuine orphan
    };
    let rd = match std::fs::read_dir(&lo.confd) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(id) = name
            .strip_prefix("dn7-")
            .and_then(|s| s.strip_suffix(".conf"))
        {
            if !live.contains(id) {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if name.starts_with("acme-") && name.ends_with(".conf") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// True if another managed site (≠ `exclude_id`) already uses `server_name` —
/// two server blocks with the same name on :80 conflict (nginx serves the
/// first-loaded one), which silently breaks the other site + its HTTP-01.
pub(crate) fn server_name_taken(server_name: &str, exclude_id: &str) -> bool {
    load_sites()
        .iter()
        .any(|s| s.id != exclude_id && s.server_name == server_name)
}

/// Regenerate every managed site's conf from the *current* template and reload
/// once. Called at panel startup so a config written by an older build (e.g.
/// the legacy `http2 on;` directive that older nginx rejects) is healed
/// automatically after an upgrade — instead of lingering and failing `nginx -t`
/// for every subsequent operation. Best-effort: an SSL site whose cert file is
/// missing is regenerated as plain HTTP so one broken site can't fail the whole
/// `nginx -t`; per-site write errors (e.g. a container IP unresolvable while
/// Docker is still starting) are logged and skipped.
pub async fn resync_confs() {
    if !is_setup() {
        return;
    }
    let lo = match layout() {
        Ok(l) => l,
        Err(_) => return,
    };
    cleanup_orphan_confs(&lo);
    // Re-emit every access list's htpasswd file. Older builds wrote these under
    // the panel's private tree (which the nginx worker can't read → 500); this
    // moves them to /etc/nginx/dn7-access and the conf rewrite below repoints
    // auth_basic_user_file at the new path — fully healing the 500 on upgrade.
    for list in load_access() {
        if let Err(e) = write_htpasswd(&list) {
            tracing::warn!(access = %list.id, "htpasswd resync failed: {e}");
        }
    }
    let mut wrote = false;
    for mut site in load_sites() {
        if site.ssl {
            let have = if site.cert_name.is_empty() {
                lo.cert_store.join(format!("{}.crt", site.id)).exists()
                    && lo.cert_store.join(format!("{}.key", site.id)).exists()
            } else {
                named_crt_file(&lo, &site.cert_name).exists()
            };
            if !have {
                site.ssl = false; // degrade to HTTP so the regenerated conf stays valid
            }
        }
        match write_site_conf(&lo, &site, &[]).await {
            Ok(()) => wrote = true,
            Err(e) => tracing::warn!(site = %site.server_name, "resync conf failed: {e}"),
        }
    }
    // Re-apply the default-site catch-all if it has been configured.
    if websettings_file().exists() {
        if let Err(e) = write_default_conf(&lo, &load_webglobal()).await {
            tracing::warn!("default-site conf resync failed: {e}");
        } else {
            wrote = true;
        }
    }
    // Re-apply the http-context tuning include (server_names_hash_bucket_size).
    write_tuning_conf();
    if wrote {
        if let Err(e) = validate_and_reload(&lo).await {
            tracing::warn!("nginx conf resync reload failed: {e}");
        } else {
            tracing::info!("nginx site confs resynced to current template");
        }
    }
}

/// Days from `date` ("YYYY-MM-DD") until today (negative once past).
pub(crate) fn days_until(date: &str) -> Option<i64> {
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    // Howard Hinnant's days_from_civil (days since 1970-01-01).
    let yy = if m <= 2 { y - 1 } else { y };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let target = era * 146097 + doe - 719468;
    let now = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86400) as i64;
    Some(target - now)
}

/// True if the cert PEM at `path` exists, parses, and is within `within_days`
/// of expiry. A missing/unparseable cert returns false so we never hammer
/// Let's Encrypt for a cert that was never successfully issued.
pub(crate) fn cert_due(path: &std::path::Path, within_days: i64) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|p| cert_not_after(&p))
        .and_then(|date| days_until(&date))
        .map(|n| n < within_days)
        .unwrap_or(false)
}

/// Renew per-site and standalone Let's Encrypt / self-signed certificates that
/// are near expiry. Manual certs are user-supplied and never auto-renewed.
pub async fn renew_due_certs() {
    if !is_setup() {
        return;
    }
    let lo = match layout() {
        Ok(l) => l,
        Err(_) => return,
    };
    const WITHIN: i64 = 30; // LE certs last 90d; renew comfortably before expiry.
    renew_due_site_certs(&lo, WITHIN).await;
    renew_due_named_certs(&lo, WITHIN).await;
}

/// Auto-renew per-site certs (LE reissue / self-signed regenerate) that expire
/// within `within` days. Named-cert and manual sites are skipped here.
async fn renew_due_site_certs(lo: &Layout, within: i64) {
    for site in load_sites() {
        if !site.ssl || !site.cert_name.is_empty() {
            continue; // named certs handled separately; manual isn't auto-renewed
        }
        let crt = lo.cert_store.join(format!("{}.crt", site.id));
        if !cert_due(&crt, within) {
            continue;
        }
        match site.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&site.server_name));
                match issue_le(&op_id, lo, &site).await {
                    Ok(()) => {
                        op_finish(&op_id, "done", "");
                        tracing::info!(site = %site.server_name, "auto-renewed Let's Encrypt certificate");
                    }
                    Err(e) => {
                        op_finish(&op_id, "error", &e.to_string());
                        tracing::warn!(site = %site.server_name, "cert auto-renew failed: {e}");
                    }
                }
            }
            "self" => {
                if gen_self_signed(lo, &site).await.is_ok() {
                    let _ = write_site_conf(lo, &site, &[]).await;
                    let _ = validate_and_reload(lo).await;
                }
            }
            _ => {}
        }
    }
}

/// Auto-renew standalone named certs that expire within `within` days. Sites
/// reference these cert files directly, so nginx is reloaded after each renewal.
async fn renew_due_named_certs(lo: &Layout, within: i64) {
    for c in load_named_certs() {
        if c.domain.is_empty() {
            continue;
        }
        let crt = named_crt_file(lo, &c.name);
        if !cert_due(&crt, within) {
            continue;
        }
        match c.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&c.domain));
                match issue_le_named(&op_id, lo, &c.name, &c.domain).await {
                    Ok(()) => op_finish(&op_id, "done", ""),
                    Err(e) => op_finish(&op_id, "error", &e.to_string()),
                }
            }
            "self" => {
                let host = primary_host(&c.domain);
                let _ = gen_self_signed_to(
                    &named_crt_file(lo, &c.name),
                    &named_key_file(lo, &c.name),
                    &host,
                )
                .await;
            }
            _ => continue,
        }
        let _ = validate_and_reload(lo).await;
    }
}

/// Background loop: renew certs nearing expiry. First pass ~10 min after start,
/// then daily — so a 90-day Let's Encrypt cert renews well before it lapses.
pub fn spawn_cert_renewal() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        loop {
            renew_due_certs().await;
            tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
        }
    });
}

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

pub(crate) async fn remove_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site_id = req
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
enum CertPrep {
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
async fn prepare_site_cert(lo: &Layout, req: &Req, old: &Site, site: &Site) -> Result<CertPrep> {
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
        "self" => {
            if !have || old.cert_mode != "self" || !old.cert_name.is_empty() {
                gen_self_signed(lo, site).await?;
            }
        }
        _ => {}
    }
    Ok(CertPrep::Ready)
}
