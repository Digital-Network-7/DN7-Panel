//! Network listing, IP pool, rename (split from docker.rs).
use super::*;

pub(crate) async fn list_networks() -> Result<Value> {
    let dkr = dkr()?;
    let nets = dkr
        .list_networks::<String>(None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut items = Vec::new();
    for n in nets {
        let id =
            n.id.clone()
                .unwrap_or_default()
                .chars()
                .take(12)
                .collect::<String>();
        // First IPv4 subnet from the IPAM config (so the UI can suggest a
        // static address when joining this network).
        let subnet = n
            .ipam
            .as_ref()
            .and_then(|i| i.config.as_ref())
            .and_then(|cfgs| cfgs.iter().find_map(|c| c.subnet.clone()))
            .filter(|s| s.contains('.'))
            .unwrap_or_default();
        items.push(json!({
            "id": id,
            "name": n.name.clone().unwrap_or_default(),
            "driver": n.driver.clone().unwrap_or_default(),
            "scope": n.scope.clone().unwrap_or_default(),
            "subnet": subnet,
        }));
    }
    Ok(json!({ "networks": items }))
}

/// True for Docker's predefined networks (can't be renamed/removed).
pub(crate) fn net_predefined(name: &str) -> bool {
    matches!(name, "bridge" | "host" | "none")
}

/// IP pool of a network: subnet/gateway + every attached container's IPv4/MAC.
/// `editable` is true only for user-defined networks that have a subnet (static
/// IPs aren't allowed on the default bridge or host/none).
pub(crate) async fn network_ips(req: &Req) -> Result<Value> {
    let net = need_ref(req)?;
    let dkr = dkr()?;
    let n = dkr
        .inspect_network(
            &net,
            None::<bollard::network::InspectNetworkOptions<String>>,
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let cfg = n.ipam.as_ref().and_then(|i| i.config.as_ref());
    let subnet = cfg
        .and_then(|c| c.iter().find_map(|x| x.subnet.clone()))
        .unwrap_or_default();
    let gateway = cfg
        .and_then(|c| c.iter().find_map(|x| x.gateway.clone()))
        .unwrap_or_default();
    let mut cons = Vec::new();
    if let Some(map) = &n.containers {
        for (id, c) in map {
            let ipv4 = c
                .ipv4_address
                .clone()
                .unwrap_or_default()
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            cons.push(json!({
                "id": id.chars().take(12).collect::<String>(),
                "full_id": id,
                "name": c.name.clone().unwrap_or_default(),
                "ipv4": ipv4,
                "mac": c.mac_address.clone().unwrap_or_default(),
            }));
        }
    }
    cons.sort_by_key(|c| c["name"].as_str().unwrap_or("").to_string());
    let editable = !net_predefined(&net) && !subnet.is_empty();
    Ok(
        json!({ "name": net, "subnet": subnet, "gateway": gateway, "editable": editable, "containers": cons }),
    )
}

/// Change a container's static IPv4 on a network: disconnect, then reconnect
/// with the requested address. On failure we reconnect without a static IP so
/// the container isn't left detached.
pub(crate) async fn set_network_ip(req: &Req) -> Result<Value> {
    use bollard::models::{EndpointIpamConfig, EndpointSettings};
    let container = need_ref(req)?;
    let net = need_network(req)?;
    if net_predefined(&net) {
        return Err(anyhow!("ERR_CODE:docker.net_predefined_ip"));
    }
    let ip = req
        .ipv4
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_ipv4"))?;
    valid_ipv4(ip)?;
    let dkr = dkr()?;
    let _ = dkr
        .disconnect_network(
            &net,
            bollard::network::DisconnectNetworkOptions {
                container: container.clone(),
                force: true,
            },
        )
        .await;
    let cfg = bollard::network::ConnectNetworkOptions {
        container: container.clone(),
        endpoint_config: EndpointSettings {
            ipam_config: Some(EndpointIpamConfig {
                ipv4_address: Some(ip.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    if let Err(e) = dkr.connect_network(&net, cfg).await {
        // Restore connectivity (no static IP) so we don't strand the container.
        let _ = dkr
            .connect_network(
                &net,
                bollard::network::ConnectNetworkOptions {
                    container: container.clone(),
                    endpoint_config: Default::default(),
                },
            )
            .await;
        return Err(anyhow!(friendly_docker_err(&e)));
    }
    Ok(json!({ "ok": true, "ipv4": ip }))
}

/// Docker has no native network rename, so this recreates the network under the
/// new name with the same driver/IPAM/options and re-attaches every container
/// (preserving its IPv4/MAC). To avoid an IPAM subnet clash we remove the old
/// network first, then recreate; on failure we best-effort restore the original.
pub(crate) async fn rename_network(req: &Req) -> Result<Value> {
    use bollard::models::{EndpointIpamConfig, EndpointSettings};
    let old = need_ref(req)?;
    let new = req
        .new_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_network_name"))?;
    validate_name(new)?;
    if net_predefined(&old) {
        return Err(anyhow!("ERR_CODE:docker.network_predefined"));
    }
    if old == new {
        return Ok(json!({ "renamed": new }));
    }
    let dkr = dkr()?;
    let n = dkr
        .inspect_network(
            &old,
            None::<bollard::network::InspectNetworkOptions<String>>,
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;

    let driver = n.driver.clone().unwrap_or_else(|| "bridge".to_string());
    let ipam = n.ipam.clone().unwrap_or_default();
    let options = n.options.clone().unwrap_or_default();
    let labels = n.labels.clone().unwrap_or_default();
    let internal = n.internal.unwrap_or(false);
    let attachable = n.attachable.unwrap_or(false);
    let enable_ipv6 = n.enable_ipv6.unwrap_or(false);
    // (container_id, ipv4, mac)
    let members: Vec<(String, Option<String>, Option<String>)> = n
        .containers
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(id, c)| {
            let ipv4 = c
                .ipv4_address
                .filter(|s| !s.is_empty())
                .map(|s| s.split('/').next().unwrap_or("").to_string())
                .filter(|s| !s.is_empty());
            let mac = c.mac_address.filter(|s| !s.is_empty());
            (id, ipv4, mac)
        })
        .collect();

    let mk_create = |name: &str| bollard::network::CreateNetworkOptions {
        name: name.to_string(),
        check_duplicate: true,
        driver: driver.clone(),
        internal,
        attachable,
        ingress: false,
        ipam: ipam.clone(),
        enable_ipv6,
        options: options.clone(),
        labels: labels.clone(),
    };
    let endpoint = |ipv4: &Option<String>, mac: &Option<String>| EndpointSettings {
        ipam_config: ipv4.clone().map(|ip| EndpointIpamConfig {
            ipv4_address: Some(ip),
            ..Default::default()
        }),
        mac_address: mac.clone(),
        ..Default::default()
    };

    // Detach all containers, then remove the old network (frees the subnet).
    for (id, _, _) in &members {
        let _ = dkr
            .disconnect_network(
                &old,
                bollard::network::DisconnectNetworkOptions {
                    container: id.clone(),
                    force: true,
                },
            )
            .await;
    }
    dkr.remove_network(&old)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;

    // Create the renamed network. On failure, restore the original + members.
    if let Err(e) = dkr.create_network(mk_create(new)).await {
        let _ = dkr.create_network(mk_create(&old)).await;
        for (id, ipv4, mac) in &members {
            let _ = dkr
                .connect_network(
                    &old,
                    bollard::network::ConnectNetworkOptions {
                        container: id.clone(),
                        endpoint_config: endpoint(ipv4, mac),
                    },
                )
                .await;
        }
        return Err(anyhow!(friendly_docker_err(&e)));
    }

    // Re-attach every container to the renamed network.
    for (id, ipv4, mac) in &members {
        let _ = dkr
            .connect_network(
                new,
                bollard::network::ConnectNetworkOptions {
                    container: id.clone(),
                    endpoint_config: endpoint(ipv4, mac),
                },
            )
            .await;
    }
    Ok(json!({ "renamed": new }))
}

/// For one container, report the networks it's attached to and the networks it
/// could still be connected to (so the UI can offer connect/disconnect).
/// Predefined networks (`host`, `none`) aren't offered as attach targets and
/// the predefined ones can't be disconnected when they're the only one — the
/// UI surfaces the panel's docker error in that case rather than guessing.
pub(crate) async fn inspect_container_networks(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let c = dkr
        .inspect_container(&r, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let attached: Vec<String> = c
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // All networks (to compute the "available to connect" set).
    let all = list_networks().await?;
    let mut available = Vec::new();
    if let Some(arr) = all.get("networks").and_then(Value::as_array) {
        for n in arr {
            let name = n.get("name").and_then(Value::as_str).unwrap_or("");
            // Skip ones it's already on and the special "none"/"host" drivers
            // (you don't hot-attach those at runtime).
            if name.is_empty() || attached.iter().any(|a| a == name) {
                continue;
            }
            if name == "none" || name == "host" {
                continue;
            }
            available.push(json!({ "name": name }));
        }
    }

    Ok(json!({ "attached": attached, "available": available }))
}

/// `create_network`: validate name/driver + optional IPv4 IPAM, then create.
pub(crate) async fn create_network_op(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_network_name"))?;
    validate_name(name)?;
    // Driver (whitelisted; default bridge).
    let driver = req
        .driver
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("bridge");
    if !net_driver_allowed(driver) {
        return Err(anyhow!("ERR_CODE:docker.bad_net_driver"));
    }
    // Optional IPv4 IPAM config.
    let subnet = opt_trim(&req.subnet);
    let gateway = opt_trim(&req.gateway);
    let ip_range = opt_trim(&req.ip_range);
    if let Some(s) = subnet.as_deref() {
        valid_cidr(s)?;
    }
    if let Some(g) = gateway.as_deref() {
        valid_ipv4(g)?;
    }
    if let Some(r) = ip_range.as_deref() {
        valid_cidr(r)?;
    }
    // Gateway / range only make sense with a subnet.
    if subnet.is_none() && (gateway.is_some() || ip_range.is_some()) {
        return Err(anyhow!("ERR_CODE:docker.net_range_needs_subnet"));
    }
    let ipam = if subnet.is_some() {
        bollard::models::Ipam {
            config: Some(vec![bollard::models::IpamConfig {
                subnet,
                gateway,
                ip_range,
                ..Default::default()
            }]),
            ..Default::default()
        }
    } else {
        Default::default()
    };
    let opts = bollard::network::CreateNetworkOptions {
        name: name.to_string(),
        driver: driver.to_string(),
        ipam,
        ..Default::default()
    };
    dkr()?
        .create_network(opts)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "created": name }))
}

/// `remove_network`: delete, mapping in-use / predefined failures to clear codes.
pub(crate) async fn remove_network_op(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    if let Err(e) = dkr()?.remove_network(&r).await {
        let raw = e.to_string().to_lowercase();
        let msg = if raw.contains("active endpoints") || raw.contains("in use") {
            "ERR_CODE:docker.network_in_use".to_string()
        } else if raw.contains("predefined") || raw.contains("pre-defined") {
            "ERR_CODE:docker.network_predefined".to_string()
        } else {
            friendly_docker_err(&e)
        };
        return Err(anyhow!(msg));
    }
    Ok(json!({ "removed": r }))
}

/// `connect_network`: attach a container to a network.
pub(crate) async fn connect_network_op(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let net = need_network(req)?;
    let cfg = bollard::network::ConnectNetworkOptions {
        container: r.clone(),
        endpoint_config: Default::default(),
    };
    dkr()?
        .connect_network(&net, cfg)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "connected": net }))
}

/// `disconnect_network`: detach a container from a network.
pub(crate) async fn disconnect_network_op(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let net = need_network(req)?;
    let cfg = bollard::network::DisconnectNetworkOptions {
        container: r.clone(),
        force: false,
    };
    dkr()?
        .disconnect_network(&net, cfg)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "disconnected": net }))
}
