//! Access lists + default-site settings (split from nginx.rs).
use super::*;

// Access lists: list / create-or-update / delete, plus default-site settings.
// ---------------------------------------------------------------------------

/// server_names of sites currently using each access list id.
pub(crate) fn sites_using_access() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for s in load_sites() {
        if !s.access_id.is_empty() {
            map.entry(s.access_id).or_default().push(s.server_name);
        }
    }
    map
}

/// List access lists (without password hashes), with usage info.
pub(crate) async fn list_access() -> Result<Value> {
    let lists = load_access();
    let in_use = sites_using_access();
    let out: Vec<Value> = lists
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "name": a.name,
                "satisfy": if a.satisfy == "all" { "all" } else { "any" },
                "pass_auth": a.pass_auth,
                "users": a.users.iter().map(|u| json!({ "username": u.username })).collect::<Vec<_>>(),
                "clients": a.clients,
                "used_by": in_use.get(&a.id).cloned().unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({ "access": out }))
}

/// Create (no access_id) or update (existing access_id) an access list.
pub(crate) async fn save_access_op(req: &Req) -> Result<Value> {
    let _ = layout()?; // require setup
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_access_name"))?
        .to_string();
    if !valid_access_name(&name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_access_name"));
    }
    let satisfy = match req.satisfy.as_deref().unwrap_or("any") {
        "all" => "all",
        _ => "any",
    }
    .to_string();
    let pass_auth = req.pass_auth.unwrap_or(false);

    // Validate clients.
    let clients = build_access_clients(req)?;

    let mut lists = load_access();
    let existing_id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let old = existing_id
        .as_ref()
        .and_then(|id| lists.iter().find(|a| &a.id == id).cloned());

    // Build the user list: a provided password (re)hashes; an empty password on
    // an existing username reuses the stored hash.
    let users = build_access_users(req, old.as_ref())?;

    let id = existing_id.clone().unwrap_or_else(new_access_id);
    let list = AccessList {
        id: id.clone(),
        name,
        satisfy,
        pass_auth,
        users,
        clients,
    };
    write_htpasswd(&list)?;
    // Persist into the manifest (replace or append).
    lists.retain(|a| a.id != id);
    lists.push(list);
    save_access(&lists)?;

    // Rewrite the confs of any sites using this list, then reload.
    rewrite_sites_using_access(&id).await?;
    Ok(json!({ "id": id }))
}

/// Validate the access list's IP allow/deny client rules from the request.
fn build_access_clients(req: &Req) -> Result<Vec<AccessClient>> {
    let mut clients = Vec::new();
    for c in req.clients.clone().unwrap_or_default() {
        let dir = if c.directive == "deny" {
            "deny"
        } else {
            "allow"
        };
        if !valid_client_address(&c.address) {
            return Err(anyhow!("ERR_CODE:nginx.bad_client_addr"));
        }
        clients.push(AccessClient {
            directive: dir.to_string(),
            address: c.address.trim().to_string(),
        });
    }
    Ok(clients)
}

/// Build the access list's basic-auth users: a provided password (re)hashes;
/// an empty password on an existing username reuses its stored hash (`old`).
fn build_access_users(req: &Req, old: Option<&AccessList>) -> Result<Vec<AccessUser>> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for u in req.users.clone().unwrap_or_default() {
        let username = u.username.trim().to_string();
        if username.is_empty() {
            continue;
        }
        if !valid_auth_username(&username) {
            return Err(anyhow!("ERR_CODE:nginx.bad_auth_user"));
        }
        if !seen.insert(username.clone()) {
            return Err(anyhow!("ERR_CODE:nginx.dup_auth_user"));
        }
        let hash = if !u.password.is_empty() {
            if u.password.len() > 128 {
                return Err(anyhow!("ERR_CODE:nginx.bad_auth_pw"));
            }
            htpasswd_hash(&u.password)
        } else {
            old.and_then(|o| o.users.iter().find(|x| x.username == username))
                .map(|x| x.hash.clone())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_auth_pw"))?
        };
        users.push(AccessUser { username, hash });
    }
    Ok(users)
}

/// Delete an access list (refused while a site still uses it).
pub(crate) async fn delete_access_op(req: &Req) -> Result<Value> {
    let id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_access_id"))?;
    let in_use = sites_using_access();
    if let Some(sites) = in_use.get(id) {
        if !sites.is_empty() {
            return Err(anyhow!("访问列表仍被站点使用：{}", sites.join("、")));
        }
    }
    let mut lists = load_access();
    let before = lists.len();
    lists.retain(|a| a.id != id);
    if lists.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.access_not_found"));
    }
    save_access(&lists)?;
    let _ = std::fs::remove_file(htpasswd_path(id));
    let _ = std::fs::remove_file(access_dir().join(format!("{id}.htpasswd")));
    Ok(json!({ "deleted": id }))
}

/// Rewrite + reload the confs of every site referencing `access_id`.
pub(crate) async fn rewrite_sites_using_access(access_id: &str) -> Result<()> {
    let lo = layout()?;
    let mut touched = false;
    for site in load_sites() {
        if site.access_id == access_id {
            // Skip SSL sites whose cert is missing (keeps nginx -t valid).
            let mut s = site.clone();
            if s.ssl {
                let have = if s.cert_name.is_empty() {
                    lo.cert_store.join(format!("{}.crt", s.id)).exists()
                } else {
                    named_crt_file(&lo, &s.cert_name).exists()
                };
                if !have {
                    s.ssl = false;
                }
            }
            if let Err(e) = write_site_conf(&lo, &s, &[]).await {
                tracing::warn!(site = %s.server_name, "access rewrite failed: {e}");
            } else {
                touched = true;
            }
        }
    }
    if touched {
        validate_and_reload(&lo).await?;
    }
    Ok(())
}

/// Current website settings (default-site behaviour + http/server tuning).
pub(crate) async fn get_web_settings() -> Result<Value> {
    let g = load_webglobal();
    let t = load_tuning_opt().unwrap_or_default();
    Ok(json!({
        "default_site": { "mode": g.default_site.mode, "redirect_url": g.default_site.redirect_url },
        "configured": websettings_file().exists(),
        "tuning": {
            "server_names_hash_bucket_size": t.server_names_hash_bucket_size,
            "gzip": t.gzip,
            "client_header_buffer_size": t.client_header_buffer_size,
            "gzip_min_length": t.gzip_min_length,
            "client_max_body_size": t.client_max_body_size,
            "gzip_comp_level": t.gzip_comp_level,
            "keepalive_timeout": t.keepalive_timeout,
        },
        "tuning_configured": webtuning_file().exists(),
    }))
}

/// Save http/server tuning and re-apply it (rewrite all managed site confs +
/// the http include), then reload.
pub(crate) async fn set_tuning(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let cur = load_tuning_opt().unwrap_or_default();
    let snhbs = req
        .server_names_hash_bucket_size
        .unwrap_or(cur.server_names_hash_bucket_size);
    if ![32u32, 64, 128, 256, 512].contains(&snhbs) {
        return Err(anyhow!("ERR_CODE:nginx.bad_hash_bucket"));
    }
    let gcl = req.gzip_comp_level.unwrap_or(cur.gzip_comp_level);
    if !(1..=9).contains(&gcl) {
        return Err(anyhow!("ERR_CODE:nginx.bad_comp_level"));
    }
    let gmin = req.gzip_min_length.unwrap_or(cur.gzip_min_length);
    if gmin > 10_000_000 {
        return Err(anyhow!("ERR_CODE:nginx.bad_min_length"));
    }
    let kat = req.keepalive_timeout.unwrap_or(cur.keepalive_timeout);
    if kat > 86_400 {
        return Err(anyhow!("ERR_CODE:nginx.bad_keepalive"));
    }
    let chdr = req
        .client_header_buffer_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_header_buffer_size)
        .to_string();
    let cmbs = req
        .client_max_body_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_max_body_size)
        .to_string();
    if !valid_size_value(&chdr) || !valid_size_value(&cmbs) {
        return Err(anyhow!("ERR_CODE:nginx.bad_size_value"));
    }
    let t = HttpTuning {
        server_names_hash_bucket_size: snhbs,
        gzip: req.gzip.unwrap_or(cur.gzip),
        client_header_buffer_size: chdr,
        gzip_min_length: gmin,
        client_max_body_size: cmbs,
        gzip_comp_level: gcl,
        keepalive_timeout: kat,
    };
    save_tuning(&t)?;
    write_tuning_conf();
    // Tuning is injected per-server, so rewrite every managed site conf.
    for site in load_sites() {
        let mut s = site.clone();
        if s.ssl {
            let have = if s.cert_name.is_empty() {
                lo.cert_store.join(format!("{}.crt", s.id)).exists()
            } else {
                named_crt_file(&lo, &s.cert_name).exists()
            };
            if !have {
                s.ssl = false;
            }
        }
        let _ = write_site_conf(&lo, &s, &[]).await;
    }
    validate_and_reload(&lo).await?;
    Ok(json!({ "ok": true }))
}

/// Save the default-site behaviour and (re)write the catch-all conf.
pub(crate) async fn set_default_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let mode = match req.default_mode.as_deref().unwrap_or("404") {
        m @ ("404" | "welcome" | "444" | "redirect") => m.to_string(),
        _ => return Err(anyhow!("ERR_CODE:nginx.bad_default_mode")),
    };
    let redirect_url = req
        .redirect_url
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if mode == "redirect" && !valid_redirect_url(&redirect_url) {
        return Err(anyhow!("ERR_CODE:nginx.bad_redirect_url"));
    }
    let g = WebGlobal {
        default_site: DefaultSite { mode, redirect_url },
    };
    save_webglobal(&g)?;
    write_default_conf(&lo, &g).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back: remove the default conf so nginx stays valid.
        let _ = std::fs::remove_file(default_conf_path());
        let _ = reload().await;
        return Err(e);
    }
    Ok(json!({ "ok": true }))
}

// `valid_redirect_url` lives in the `validate` submodule.
pub(crate) fn default_conf_path() -> std::path::PathBuf {
    std::path::Path::new(HOST_CONFD).join("00-dn7-default.conf")
}

/// The per-mode response directives for the default (catch-all) server.
pub(crate) fn default_behavior(g: &WebGlobal) -> String {
    match g.default_site.mode.as_str() {
        "redirect" => format!("    return 301 {};\n", g.default_site.redirect_url),
        "444" => "    return 444;\n".to_string(),
        "welcome" => "    default_type text/html;\n    return 200 \"<!doctype html><html lang=en><head><meta charset=utf-8><title>DN7 Panel</title></head><body style='font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;color:#333'><h1 style='margin:0 0 8px'>It works</h1><p style='color:#888'>This server is managed by DN7 Panel.</p></body></html>\";\n".to_string(),
        _ => "    return 404;\n".to_string(),
    }
}

/// Write the catch-all default-server conf (HTTP + HTTPS) per the saved
/// settings, generating a self-signed default cert for the HTTPS listener.
pub(crate) async fn write_default_conf(lo: &Layout, g: &WebGlobal) -> Result<()> {
    // The distro nginx ships its own default vhost (e.g. Debian/Ubuntu
    // `/etc/nginx/sites-enabled/default`) which ALSO marks `default_server` —
    // two default servers on the same port make `nginx -t` fail with
    // "a duplicate default server". Disable it so our catch-all can win.
    disable_distro_default_site();

    let behavior = default_behavior(g);
    // Default cert for the 443 catch-all (so unmatched SNI doesn't fall through
    // to the first real site's certificate).
    let crt = lo.cert_store.join("default.crt");
    let key = lo.cert_store.join("default.key");
    if !crt.exists() || !key.exists() {
        gen_self_signed_to(&crt, &key, "localhost").await?;
    }
    let crt_ref = format!("{}/default.crt", lo.cert_ref);
    let key_ref = format!("{}/default.key", lo.cert_ref);
    // Match the per-site 443 listen options (`ssl http2`) so nginx doesn't warn
    // "protocol options redefined" for the shared :443 socket.
    let conf = format!(
        "server {{\n    listen 80 default_server;\n    server_name _;\n{behavior}}}\n\n\
         server {{\n    listen 443 ssl http2 default_server;\n    server_name _;\n\
         \x20   ssl_certificate {crt_ref};\n    ssl_certificate_key {key_ref};\n{behavior}}}\n"
    );
    std::fs::create_dir_all(HOST_CONFD)?;
    std::fs::write(default_conf_path(), conf)?;
    Ok(())
}

/// Disable a distro's bundled default vhost (which carries its own
/// `default_server`) by moving it OUT of nginx's include dirs into a stash
/// directory, so the panel's catch-all is the only default server. Reversible:
/// the file is moved, not deleted. Best-effort.
///
/// Note: the file must leave the directory entirely. Debian's nginx includes
/// `sites-enabled/*` (no extension filter), so merely renaming a file in place
/// (e.g. `default` -> `default.dn7-disabled`) keeps it loaded and still trips
/// "a duplicate default server". We also sweep up any such leftovers from an
/// earlier in-place rename.
pub(crate) fn disable_distro_default_site() {
    let stash_dir = std::path::Path::new("/etc/nginx/dn7-disabled");
    let stash = |path: &std::path::Path| {
        // symlink_metadata so we also catch (and move) a symlink, even dangling.
        if path.symlink_metadata().is_err() {
            return;
        }
        if std::fs::create_dir_all(stash_dir).is_err() {
            return;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("default");
        let aside = stash_dir.join(name);
        if std::fs::rename(path, &aside).is_ok() {
            tracing::info!("disabled distro nginx default site: {path:?} -> {aside:?}");
        }
    };
    for p in [
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/conf.d/default.conf",
    ] {
        stash(std::path::Path::new(p));
    }
    // Clean up leftovers from the earlier in-place rename: a `*.dn7-disabled`
    // file still living under sites-enabled/ is matched by the `*` include and
    // re-introduces the duplicate default server.
    if let Ok(rd) = std::fs::read_dir("/etc/nginx/sites-enabled") {
        for ent in rd.flatten() {
            let p = ent.path();
            let is_disabled = p
                .file_name()
                .and_then(|s| s.to_str())
                .map(|n| n.ends_with(".dn7-disabled"))
                .unwrap_or(false);
            if is_disabled {
                stash(&p);
            }
        }
    }
}

/// Best-effort parse of a PEM cert's notAfter (expiry) as an ISO date string.
/// Implemented in the `certparse` submodule (minimal ASN.1 walk).
pub(crate) fn cert_not_after(pem: &str) -> Option<String> {
    certparse::cert_not_after(pem)
}

/// Reload nginx (`nginx -s reload`).
pub(crate) async fn reload() -> Result<()> {
    let lo = layout()?;
    validate_and_reload(&lo).await
}

/// `nginx -t` then `nginx -s reload`. Errors carry nginx's own message so a bad
/// generated config is visible.
pub(crate) async fn validate_and_reload(_lo: &Layout) -> Result<()> {
    let (ok, _o, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())
        ));
    }
    let (ok, _o, e) = run("nginx", &["-s", "reload"]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
    }
    Ok(())
}

/// Resolve a container's first reachable IPv4 address from the Docker daemon
/// (used in **host mode**, where the host's nginx can't resolve a container
/// *name* — only an IP works). Returns the IP from a user-defined network if
/// present, else the default bridge IP, else None.
pub(crate) async fn container_ip(target: &str) -> Option<String> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let networks = inspect.network_settings.and_then(|n| n.networks)?;
    // Prefer a user-defined network's IP; fall back to the bridge.
    let mut bridge_ip: Option<String> = None;
    for (name, ep) in networks {
        let ip = ep.ip_address.filter(|s| !s.is_empty());
        match ip {
            Some(ip) if name == "bridge" => bridge_ip = Some(ip),
            Some(ip) => return Some(ip), // user-defined network IP preferred
            None => {}
        }
    }
    bridge_ip
}

/// In **host mode**, find the host port that publishes the container's
/// `container_port` (so the host's nginx can proxy to `127.0.0.1:<host_port>`,
/// which is stable across container restarts — unlike the container IP). Returns
/// None when that port isn't published to the host.
pub(crate) async fn published_host_port(target: &str, container_port: i64) -> Option<u16> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let ports = inspect.network_settings.and_then(|n| n.ports)?;
    // Docker keys ports like "3000/tcp" -> [{HostIp, HostPort}, ...].
    let key_tcp = format!("{container_port}/tcp");
    let key_udp = format!("{container_port}/udp");
    for (key, binds) in ports {
        if key != key_tcp && key != key_udp {
            continue;
        }
        if let Some(binds) = binds {
            for b in binds {
                if let Some(hp) = b.host_port.and_then(|p| p.parse::<u16>().ok()) {
                    return Some(hp);
                }
            }
        }
    }
    None
}

/// Resolve the proxy upstream (`host:port`) for a site:
///  - **proxy_host**: the user-supplied host[:port] as-is.
///  - **proxy_container**: the host's nginx can't resolve a container name.
///    Prefer the published host port (`127.0.0.1:<hostport>`, stable across
///    restarts); otherwise fall back to the container's bridge IP.
pub(crate) async fn resolve_upstream(_lo: &Layout, site: &Site) -> Result<String> {
    match site.kind.as_str() {
        "proxy_host" => Ok(with_scheme_port(&site.target_url, &site.scheme)),
        "proxy_container" => resolve_container_upstream(&site.container, site.container_port).await,
        _ => Ok(String::new()),
    }
}

/// Resolve a container's `host:port` upstream for the host nginx: prefer the
/// published host port (`127.0.0.1:<hostport>`, restart-stable), otherwise fall
/// back to the container's bridge IP.
pub(crate) async fn resolve_container_upstream(
    container: &str,
    container_port: i64,
) -> Result<String> {
    if let Some(hp) = published_host_port(container, container_port).await {
        Ok(format!("127.0.0.1:{hp}"))
    } else {
        let ip = container_ip(container).await.ok_or_else(|| {
            anyhow!(
                "容器 {} 未映射端口 {} 到宿主机，且无法解析其 IP；请为容器发布该端口后重试",
                container,
                container_port
            )
        })?;
        Ok(format!("{ip}:{container_port}"))
    }
}
