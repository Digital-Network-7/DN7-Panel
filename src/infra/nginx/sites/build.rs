//! Site construction from a request + field validators (pure-ish).
use super::*;

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
            return Err(nginx_err(NginxError::BadTrustCidr));
        }
        out.push(t.to_string());
    }
    Ok(out.join(" "))
}

pub(crate) fn valid_local_root(p: &str) -> Result<String> {
    let path = std::path::Path::new(p);
    if !path.is_absolute() {
        return Err(nginx_err(NginxError::LocalRootAbs));
    }
    let canon = std::fs::canonicalize(path).map_err(|_| nginx_err(NginxError::LocalRootMissing))?;
    if !canon.is_dir() {
        return Err(nginx_err(NginxError::LocalRootNotDir));
    }
    let s = canon.to_string_lossy().to_string();
    const DENY: [&str; 6] = ["/", "/etc", "/root", "/proc", "/sys", "/boot"];
    if DENY.iter().any(|d| s == *d) {
        return Err(nginx_err(NginxError::LocalRootDenied));
    }
    Ok(s)
}

/// Build a site from the request, validating every field.
pub(crate) fn site_from_req(form: &SiteForm) -> Result<Site> {
    let server_name = form
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| nginx_err(NginxError::NeedDomain))?
        .to_string();
    if !valid_server_name(&server_name) {
        return Err(nginx_err(NginxError::BadDomain));
    }
    let kind = form.kind.as_deref().unwrap_or("proxy_host").to_string();
    let ssl = form.ssl.unwrap_or(false);
    let cert_mode = form.cert_mode.as_deref().unwrap_or("self").to_string();
    let cert_name = form
        .cert_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !cert_name.is_empty() && !valid_cert_name(&cert_name) {
        return Err(nginx_err(NginxError::BadCertName));
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
        scheme: norm_scheme(form.scheme.as_deref()),
        cache: form.cache.unwrap_or(false),
        block_attacks: form.block_attacks.unwrap_or(false),
        websockets: form.websockets.unwrap_or(true),
        force_ssl: form.force_ssl.unwrap_or(true),
        http2: form.http2.unwrap_or(true),
        hsts: form.hsts.unwrap_or(false),
        hsts_sub: form.hsts_sub.unwrap_or(false),
        trust_proxy: form.trust_proxy.unwrap_or(false),
        trust_proxy_cidrs: sanitize_trusted_cidrs(form.trust_proxy_cidrs.as_deref().unwrap_or(""))?,
        locations: Vec::new(),
        extra_conf: String::new(),
        access_id: String::new(),
    };

    apply_site_kind(&mut site, form)?;

    // Validate + normalize any custom path rules.
    if let Some(locs) = &form.locations {
        site.locations = validate_locations(locs)?;
    }

    // Optional raw nginx directives (validated structurally here; nginx -t is
    // the final gate when the conf is written).
    let extra = form.extra_conf.as_deref().unwrap_or("").trim();
    validate_extra_conf(extra)?;
    site.extra_conf = extra.to_string();

    site.access_id = resolve_access_ref(form)?;

    if ssl && !matches!(cert_mode.as_str(), "self" | "le" | "manual" | "named") {
        return Err(nginx_err(NginxError::UnknownCertMode));
    }
    Ok(site)
}

/// Set the kind-specific destination fields (proxy target / container+port /
/// static root) on a site from the request, validating each.
fn apply_site_kind(site: &mut Site, form: &SiteForm) -> Result<()> {
    match site.kind.as_str() {
        "proxy_host" => apply_proxy_host(site, form),
        "proxy_container" => apply_proxy_container(site, form),
        "static" => apply_static(site, form),
        _ => Err(nginx_err(NginxError::UnknownSiteKind)),
    }
}

/// `proxy_host`: validate + set the upstream host[:port] target.
fn apply_proxy_host(site: &mut Site, form: &SiteForm) -> Result<()> {
    let t = form
        .target_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| nginx_err(NginxError::NeedTarget))?;
    if !valid_host_token(t) {
        return Err(nginx_err(NginxError::BadTarget));
    }
    site.target_url = t.to_string();
    Ok(())
}

/// `proxy_container`: validate + set the upstream container name + port.
fn apply_proxy_container(site: &mut Site, form: &SiteForm) -> Result<()> {
    let c = form
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| nginx_err(NginxError::NeedContainer))?;
    if !valid_container_name(c) {
        return Err(nginx_err(NginxError::BadContainer));
    }
    let port = form.container_port.unwrap_or(0);
    if !valid_port(port) {
        return Err(nginx_err(NginxError::BadContainerPort));
    }
    site.container = c.to_string();
    site.container_port = port;
    Ok(())
}

/// `static`: an existing absolute host dir (`local_root`), or a panel-managed
/// upload dir under `<www>/<root>`.
fn apply_static(site: &mut Site, form: &SiteForm) -> Result<()> {
    let local = form
        .local_root
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(p) = local {
        site.local_root = valid_local_root(p)?;
    } else {
        let r = form
            .root
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| nginx_err(NginxError::NeedStaticDir))?;
        if !valid_root_segment(r) {
            return Err(nginx_err(NginxError::BadStaticDirName));
        }
        site.root = r.to_string();
    }
    Ok(())
}

/// Resolve + validate the optional access-list reference (must exist when set).
fn resolve_access_ref(form: &SiteForm) -> Result<String> {
    let access_id = form
        .access_id
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !access_id.is_empty() && !load_access().iter().any(|a| a.id == access_id) {
        return Err(nginx_err(NginxError::AccessNotFound));
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
        return Err(nginx_err(NginxError::TooManyRules));
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
            return Err(nginx_err(NginxError::BadContainer));
        }
        if !valid_port(l.container_port) {
            return Err(nginx_err(NginxError::BadContainerPort));
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
        return Err(nginx_err(NginxError::ExtraConfTooLong));
    }
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(nginx_err(NginxError::ExtraConfBad));
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
