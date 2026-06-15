//! Default (catch-all) site config + distro-default disabling (split from access.rs).
use super::*;

/// Persist an already-validated default-site entity and (re)write the catch-all
/// conf, then reload — rolling back the conf if nginx rejects it. The
/// validation/build is owned by `domain::nginx::build_default_site`; this is the
/// side-effecting adapter for the `app::nginx` use-case.
pub(crate) async fn apply_default_site(g: &WebGlobal) -> Result<Value> {
    let lo = layout()?;
    save_webglobal(g)?;
    write_default_conf(&lo, g).await?;
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
