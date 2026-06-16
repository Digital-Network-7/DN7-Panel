//! Single-container inspect + inspect-port-map formatting.
use super::*;

pub(crate) async fn inspect_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let c = dkr
        .inspect_container(&r, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;

    let name = c
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let state = c
        .state
        .as_ref()
        .and_then(|s| s.status.map(|st| format!("{st:?}").to_lowercase()))
        .unwrap_or_default();
    let running = c.state.as_ref().and_then(|s| s.running).unwrap_or(false);
    let exit_code = c.state.as_ref().and_then(|s| s.exit_code).unwrap_or(0);
    let restart_count = c.restart_count.unwrap_or(0);
    let image = c
        .config
        .as_ref()
        .and_then(|cf| cf.image.clone())
        .unwrap_or_default();
    let restart_policy = c
        .host_config
        .as_ref()
        .and_then(|h| h.restart_policy.as_ref())
        .and_then(|rp| rp.name.map(|n| format!("{n:?}").to_lowercase()))
        .unwrap_or_default();
    let created = c.created.clone().unwrap_or_default();
    let started_at = c
        .state
        .as_ref()
        .and_then(|s| s.started_at.clone())
        .unwrap_or_default();

    // Published ports from the network settings.
    let ports = c
        .network_settings
        .as_ref()
        .and_then(|n| n.ports.as_ref())
        .map(fmt_port_map)
        .unwrap_or_default();

    let has_shell = if running {
        container_has_shell(&dkr, &r).await
    } else {
        false
    };

    Ok(json!({
        "id": r,
        "name": name,
        "image": image,
        "state": state,
        "running": running,
        "restart_policy": restart_policy,
        "created": created,
        "started_at": started_at,
        "exit_code": exit_code,
        "restart_count": restart_count,
        "ports": ports,
        "has_shell": has_shell,
    }))
}

/// Format a container inspect PortMap into a docker-ps-like summary.
pub(crate) fn fmt_port_map(
    pm: &HashMap<String, Option<Vec<bollard::models::PortBinding>>>,
) -> String {
    let mut out: Vec<String> = Vec::new();
    for (container_port, bindings) in pm {
        if let Some(bindings) = bindings {
            for b in bindings {
                let host_ip = b.host_ip.clone().unwrap_or_default();
                let host_port = b.host_port.clone().unwrap_or_default();
                if host_port.is_empty() {
                    out.push(container_port.clone());
                } else if host_ip.is_empty() {
                    out.push(format!("{host_port}->{container_port}"));
                } else {
                    out.push(format!("{host_ip}:{host_port}->{container_port}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out.join(", ")
}
