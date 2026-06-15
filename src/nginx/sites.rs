//! Sites: add / remove / generate config / reload (split from nginx.rs).
use super::*;

mod crud;
mod renew;
pub(crate) use crud::*;
pub(crate) use renew::*;

/// Validate + normalize a trusted front-proxy IP/CIDR list (comma / space /
/// newline separated). Each token must be a bare IP or `IP/prefix` CIDR; this
/// both prevents nginx-config injection and stops operators from accidentally
/// trusting an over-broad range. Returns the cleaned, space-separated list.
pub(crate) fn sanitize_trusted_cidrs(input: &str) -> Result<String> {
    let mut out = Vec::new();
    for tok in input.split([',', ' ', '\t', '\n', '\r']) {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        let valid = if let Some((addr, prefix)) = t.split_once('/') {
            addr.parse::<std::net::IpAddr>().is_ok()
                && prefix.parse::<u8>().is_ok_and(|p| match addr.parse() {
                    Ok(std::net::IpAddr::V4(_)) => p <= 32,
                    Ok(std::net::IpAddr::V6(_)) => p <= 128,
                    Err(_) => false,
                })
        } else {
            t.parse::<std::net::IpAddr>().is_ok()
        };
        if !valid {
            return Err(anyhow!("ERR_CODE:nginx.bad_trust_cidr"));
        }
        out.push(t.to_string());
    }
    Ok(out.join(" "))
}

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
        trust_proxy_cidrs: sanitize_trusted_cidrs(
            req.trust_proxy_cidrs.as_deref().unwrap_or(""),
        )?,
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
        if let Some(loc) = validate_one_location(l)? {
            out.push(loc);
        }
    }
    if out.len() > 50 {
        return Err(anyhow!("ERR_CODE:nginx.too_many_rules"));
    }
    Ok(out)
}

/// Validate + normalize a single custom path rule. Returns `Ok(None)` for a
/// fully-empty row (the UI may submit blank trailing rows), `Ok(Some(loc))` for
/// a valid rule, or an error describing the first invalid field.
fn validate_one_location(l: &Location) -> Result<Option<Location>> {
    let path = l.path.trim();
    if l.kind.trim() == "container" {
        let container = l.container.trim();
        if path.is_empty() && container.is_empty() {
            return Ok(None);
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
        Ok(Some(Location {
            path: path.to_string(),
            scheme: norm_scheme(Some(&l.scheme)),
            target: String::new(),
            websockets: l.websockets,
            kind: "container".to_string(),
            container: container.to_string(),
            container_port: l.container_port,
        }))
    } else {
        let target = l.target.trim();
        if path.is_empty() && target.is_empty() {
            return Ok(None);
        }
        if !valid_location_path(path) {
            return Err(anyhow!("路径规则需以 / 开头且不含空格等特殊字符：{path}"));
        }
        if !valid_host_token(target) {
            return Err(anyhow!("路径规则目标格式不正确（host[:port]）：{target}"));
        }
        Ok(Some(Location {
            path: path.to_string(),
            scheme: norm_scheme(Some(&l.scheme)),
            target: target.to_string(),
            websockets: l.websockets,
            kind: "host".to_string(),
            container: String::new(),
            container_port: 0,
        }))
    }
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
