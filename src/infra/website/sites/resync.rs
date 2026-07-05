//! Conf resync (reload from the manifest) + server_name conflict detection.
use super::*;

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
    // Reserved by the panel's OWN console — its external address + the loopback
    // names. A hosted site claiming one of these would be silently shadowed by
    // the console route on the edge (the console wins), so treat it as taken
    // instead of letting the site quietly break.
    if console_reserved(&wanted) {
        return true;
    }
    load_sites().iter().any(|s| {
        s.id != exclude_id
            && host_tokens(&s.server_name)
                .iter()
                .any(|h| wanted.contains(h))
    })
}

/// Whether any wanted host is reserved by the console (its `external_address` or
/// the loopback names the console route always claims).
fn console_reserved(wanted: &std::collections::HashSet<String>) -> bool {
    if wanted.contains("localhost") || wanted.contains("127.0.0.1") {
        return true;
    }
    crate::infra::store::settings::load()
        .map(|ws| {
            let ext = ws.external_address.trim().to_ascii_lowercase();
            if ext.is_empty() {
                return false;
            }
            // Reserve BOTH the bare and the bracketed IPv6 form: the edge keys the
            // console route by the bracketed host, but the address may be stored /
            // entered bare, so match either. (Identical for a hostname / IPv4.)
            let bracketed = if !ext.starts_with('[') && ext.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{ext}]")
            } else {
                ext.clone()
            };
            wanted.contains(&ext) || wanted.contains(&bracketed)
        })
        .unwrap_or(false)
}

/// Split a `server_name` field into its individual lowercase hostnames.
pub(crate) fn host_tokens(server_name: &str) -> std::collections::HashSet<String> {
    server_name
        .split_whitespace()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// Rebuild the edge server's route table from the current manifests. Called at
/// panel startup and after a Docker container topology change so a
/// `proxy_container` upstream whose IP drifted (recreate) is re-resolved — the
/// edge resolves container upstreams lazily at request time, and serves a 503
/// when an upstream is unresolvable, so there's no stale-config or misrouted-IP
/// risk to heal here; a single reload from the manifest suffices.
pub async fn resync_confs() {
    if !is_setup() {
        return;
    }
    let lo = match layout() {
        Ok(l) => l,
        Err(_) => return,
    };
    if let Err(e) = validate_and_reload(&lo).await {
        tracing::warn!("edge route-table resync failed: {e}");
    } else {
        tracing::info!("edge route table resynced from manifests");
    }
}

/// Fire-and-forget a route-table re-sync after a Docker container topology
/// change (remove / rename). The edge resolves `proxy_container` upstreams
/// lazily and serves 503 when one is unresolvable, so a vanished container can
/// never be misrouted. Spawned detached so the triggering Docker op returns
/// promptly.
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
