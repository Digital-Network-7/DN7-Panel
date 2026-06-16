//! Conf resync / orphan cleanup / server_name conflict detection.
use super::*;

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
            // Skip a conf whose site has an in-flight LE issuance: it isn't in
            // sites.json yet but its challenge block must survive validation.
            if !live.contains(id) && !is_issuing(id) {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if let Some(id) = name
            .strip_prefix("acme-")
            .and_then(|s| s.strip_suffix(".conf"))
        {
            // Named-cert challenge conf — disposable, but not while its issuance
            // is still running (keyed by the conf id `acme-<name>`).
            if !is_issuing(&format!("acme-{id}")) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// True if another managed site (≠ `exclude_id`) already serves any of the
/// hostnames in `server_name`. A `server_name` may list several space-separated
/// hosts, so an exact full-string compare misses partial overlap: sites
/// `"a.com b.com"` and `"b.com c.com"` both claim `b.com` on :80, where nginx
/// silently serves whichever block loads first and breaks the other site (and
/// its HTTP-01). Compare per host, case-insensitively.
pub(crate) fn server_name_taken(server_name: &str, exclude_id: &str) -> bool {
    let wanted: std::collections::HashSet<String> = host_tokens(server_name);
    if wanted.is_empty() {
        return false;
    }
    load_sites().iter().any(|s| {
        s.id != exclude_id
            && host_tokens(&s.server_name)
                .iter()
                .any(|h| wanted.contains(h))
    })
}

/// Split a `server_name` field into its individual lowercase hostnames.
pub(crate) fn host_tokens(server_name: &str) -> std::collections::HashSet<String> {
    server_name
        .split_whitespace()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
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
            Err(e) => {
                // The upstream couldn't be resolved — most commonly a
                // `proxy_container` site whose backing container was deleted.
                // Do NOT leave the previous conf in place: Docker may have
                // recycled the gone container's IP for an unrelated container,
                // so the stale `proxy_pass <ip>` would silently forward traffic
                // to the wrong service. Fail closed with a 503 maintenance stub.
                tracing::warn!(
                    site = %site.server_name,
                    "upstream unresolved, writing 503 maintenance stub: {e}"
                );
                match write_unavailable_conf(&lo, &site).await {
                    Ok(()) => wrote = true,
                    Err(e2) => {
                        // Even the stub failed — remove any stale conf so we
                        // never serve a misrouted upstream. Better a 404 from
                        // the default site than traffic sent to the wrong place.
                        tracing::warn!(
                            site = %site.server_name,
                            "stub conf write failed, removing stale conf: {e2}"
                        );
                        let _ = std::fs::remove_file(conf_path(&lo, &site.id));
                        wrote = true;
                    }
                }
            }
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

/// Fire-and-forget a conf re-sync after a Docker container topology change
/// (remove / rename). A `proxy_container` site whose upstream just disappeared
/// is rewritten to a 503 stub by [`resync_confs`] so it can never proxy to a
/// recycled container IP. Spawned detached so the triggering Docker op returns
/// promptly; `resync_confs` already serialises itself via the sites state lock.
pub fn resync_after_container_change() {
    tokio::spawn(async {
        resync_confs().await;
    });
}

/// Background guard: periodically re-sync site confs so a `proxy_container`
/// upstream whose IP drifted (container recreated) is re-resolved, and a site
/// whose container vanished without a panel-driven remove still fails closed.
/// Low frequency — the event-driven [`resync_after_container_change`] handles
/// the common cases; this only backstops out-of-band Docker changes.
pub fn spawn_upstream_resync() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            resync_confs().await;
        }
    });
}
