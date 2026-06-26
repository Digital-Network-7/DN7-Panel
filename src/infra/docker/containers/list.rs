//! Container listing rows + published-port formatting.
use super::*;

pub(crate) async fn list_containers() -> Result<Value> {
    let dkr = dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;

    // Probe shell availability for all running containers concurrently rather
    // than sequentially — each probe waits up to ~500ms, so for N running
    // containers this turns ~N*500ms into ~500ms total. Results are cached by
    // image id (shell availability is a property of the image, invariant for a
    // container's life), so repeated UI polls of an unchanged list skip the
    // exec probe entirely.
    let shell_futs = containers.iter().map(|c| {
        let dkr = dkr.clone();
        let id = c.id.clone().unwrap_or_default();
        // Key the cache on the image id when known; fall back to the container id.
        let cache_key = c
            .image_id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| id.clone());
        let running = c.state.as_deref() == Some("running");
        async move {
            if !running {
                return false;
            }
            if let Some(cached) = shell_cache_get(&cache_key) {
                return cached;
            }
            let has = container_has_shell(&dkr, &id).await;
            shell_cache_put(&cache_key, has);
            has
        }
    });
    let shells = futures::future::join_all(shell_futs).await;

    let mut items = Vec::new();
    for (c, has_shell) in containers.into_iter().zip(shells) {
        items.push(container_row(c, has_shell));
    }
    Ok(json!({ "containers": items }))
}

/// Build one container list row (id/name/state/ports/ips/managed/…) from a
/// docker `ContainerSummary` and its probed shell availability.
fn container_row(c: bollard::models::ContainerSummary, has_shell: bool) -> Value {
    let id = c.id.clone().unwrap_or_default();
    let short_id = id.chars().take(12).collect::<String>();
    let name = c
        .names
        .as_ref()
        .and_then(|n| n.first())
        .map(|s| s.trim_start_matches('/').to_string())
        .unwrap_or_default();
    let state = c.state.clone().unwrap_or_default();
    // DN7 Panel-managed service containers (the managed MySQL service) are marked so the UI
    // can show "内置" and hide direct controls (the panel also refuses ops on
    // them — see `managed_container_guard`).
    let has_mysql_label = c
        .labels
        .as_ref()
        .map(|l| l.contains_key("dn7.mysql"))
        .unwrap_or(false);
    let managed = name == crate::infra::mysql::CONTAINER || has_mysql_label;
    // Every attached network's IPv4, formatted "ip (network)". A container can
    // have several NICs, so the UI shows one per line. Sorted by network name.
    let mut ip_list: Vec<String> = Vec::new();
    if let Some(nets) = c
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
    {
        let mut entries: Vec<(String, String)> = nets
            .iter()
            .filter_map(|(nname, e)| {
                e.ip_address
                    .clone()
                    .filter(|s| !s.is_empty())
                    .map(|ip| (nname.clone(), ip))
            })
            .collect();
        entries.sort_by_key(|e| e.0.clone());
        ip_list = entries
            .into_iter()
            .map(|(nname, ip)| format!("{ip} ({nname})"))
            .collect();
    }
    let ip = ip_list.first().cloned().unwrap_or_default();
    // A human description from OCI image labels (best-effort; often empty).
    let description = c
        .labels
        .as_ref()
        .and_then(|l| {
            l.get("org.opencontainers.image.description")
                .or_else(|| l.get("org.opencontainers.image.title"))
                .cloned()
        })
        .unwrap_or_default();
    // Uptime/duration text (running: "Up 2 hours"; otherwise empty).
    let uptime = if state == "running" {
        c.status.clone().unwrap_or_default()
    } else {
        String::new()
    };
    json!({
        "id": short_id,
        "name": name,
        "image": c.image.clone().unwrap_or_default(),
        "state": state,
        "status": c.status.clone().unwrap_or_default(),
        "ports": fmt_ports(&c.ports),
        "ip": ip,
        "ips": ip_list,
        "description": description,
        "uptime": uptime,
        "has_shell": has_shell,
        "managed": managed,
    })
}

/// Format published ports like docker ps (e.g. "0.0.0.0:8080->80/tcp").
pub(crate) fn fmt_ports(ports: &Option<Vec<bollard::models::Port>>) -> String {
    let mut out: Vec<String> = Vec::new();
    if let Some(ports) = ports {
        for p in ports {
            let proto = p
                .typ
                .map(|t| format!("{t:?}").to_lowercase())
                .unwrap_or_else(|| "tcp".into());
            match (p.public_port, &p.ip) {
                (Some(pub_port), Some(ip)) => {
                    out.push(format!("{ip}:{pub_port}->{}/{proto}", p.private_port))
                }
                (Some(pub_port), None) => {
                    out.push(format!("{pub_port}->{}/{proto}", p.private_port))
                }
                _ => out.push(format!("{}/{proto}", p.private_port)),
            }
        }
    }
    out.sort();
    out.dedup();
    out.join(", ")
}
