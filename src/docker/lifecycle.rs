//! Lifecycle extras: rename, commit, stats, edit/upgrade prefill (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Lifecycle extras: rename, commit-to-image, stats, edit/upgrade prefill
// ---------------------------------------------------------------------------

/// Rename a container to `new_name` (validated like a create name).
pub(crate) async fn rename_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let name = req
        .new_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_name"))?;
    validate_name(name)?;
    dkr()?
        .rename_container(
            &r,
            bollard::container::RenameContainerOptions {
                name: name.to_string(),
            },
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "renamed": name }))
}

/// Commit a container's current state to a new image (`repo:tag`).
pub(crate) async fn commit_container_op(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let repo = req
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_image_name"))?;
    validate_token(repo)?;
    let tag = req
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("latest");
    validate_token(tag)?;
    let opts = bollard::image::CommitContainerOptions {
        container: r.clone(),
        repo: repo.to_string(),
        tag: tag.to_string(),
        comment: String::new(),
        author: "DN7 Panel".to_string(),
        pause: true,
        changes: None,
    };
    dkr()?
        .commit_container(opts, bollard::container::Config::<String>::default())
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "image": format!("{repo}:{tag}") }))
}

/// One-shot resource stats for a container (CPU %, memory, network, block IO).
pub(crate) async fn container_stats(req: &Req) -> Result<Value> {
    use bollard::container::StatsOptions;
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let mut stream = dkr.stats(
        &r,
        Some(StatsOptions {
            stream: false,
            one_shot: false,
        }),
    );
    let s = match stream.next().await {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Err(anyhow!(friendly_docker_err(&e))),
        None => return Err(anyhow!("ERR_CODE:docker.no_stats")),
    };

    // CPU %: delta(container) / delta(system) * online_cpus * 100 (docker formula).
    let cpu_delta =
        s.cpu_stats.cpu_usage.total_usage as f64 - s.precpu_stats.cpu_usage.total_usage as f64;
    let sys_delta = s.cpu_stats.system_cpu_usage.unwrap_or(0) as f64
        - s.precpu_stats.system_cpu_usage.unwrap_or(0) as f64;
    let online = s.cpu_stats.online_cpus.unwrap_or_else(|| {
        s.cpu_stats
            .cpu_usage
            .percpu_usage
            .as_ref()
            .map(|v| v.len() as u64)
            .unwrap_or(1)
    });
    let cpu_pct = if sys_delta > 0.0 && cpu_delta > 0.0 {
        (cpu_delta / sys_delta) * online as f64 * 100.0
    } else {
        0.0
    };

    // Memory: usage minus page cache (matches `docker stats`), against the limit.
    let mem_usage = s.memory_stats.usage.unwrap_or(0);
    let cache = match &s.memory_stats.stats {
        Some(bollard::container::MemoryStatsStats::V1(v1)) => v1.cache,
        Some(bollard::container::MemoryStatsStats::V2(v2)) => v2.inactive_file,
        None => 0,
    };
    let mem_used = mem_usage.saturating_sub(cache);
    let mem_limit = s.memory_stats.limit.unwrap_or(0);

    // Network: sum across interfaces.
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Some(nets) = &s.networks {
        for n in nets.values() {
            rx += n.rx_bytes;
            tx += n.tx_bytes;
        }
    }

    // Block IO: sum read/write byte counters.
    let (mut blk_r, mut blk_w) = (0u64, 0u64);
    if let Some(entries) = &s.blkio_stats.io_service_bytes_recursive {
        for e in entries {
            match e.op.to_ascii_lowercase().as_str() {
                "read" => blk_r += e.value,
                "write" => blk_w += e.value,
                _ => {}
            }
        }
    }

    Ok(json!({
        "cpu_pct": (cpu_pct * 100.0).round() / 100.0,
        "cpu_online": online,
        "mem_used": mem_used,
        "mem_limit": mem_limit,
        "net_rx": rx,
        "net_tx": tx,
        "blk_read": blk_r,
        "blk_write": blk_w,
    }))
}

/// Return a create-request-shaped JSON body describing an existing container,
/// used to pre-fill the edit/upgrade form and to snapshot config for backups.
pub(crate) async fn container_create_body(dkr: &Docker, reference: &str) -> Result<Value> {
    let c = dkr
        .inspect_container(reference, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let cfg = c.config.clone().unwrap_or_default();
    let hc = c.host_config.clone().unwrap_or_default();
    let name = c
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();

    let ports = inspect_ports(&hc);
    let volumes = inspect_volumes(&hc);
    let restart = inspect_restart(&hc);
    let networks = inspect_networks(c.network_settings.as_ref());

    let cmd = cfg.cmd.as_ref().map(|v| v.join(" ")).unwrap_or_default();
    let cpus = hc
        .nano_cpus
        .filter(|n| *n > 0)
        .map(|n| format!("{:.2}", n as f64 / 1_000_000_000.0))
        .unwrap_or_default();
    let memory = hc.memory.filter(|m| *m > 0).map(|m| m.to_string());

    Ok(json!({
        "op": "create_container",
        "image": cfg.image.clone().unwrap_or_default(),
        "name": name,
        "restart": restart,
        "ports": ports,
        "env": cfg.env.clone().unwrap_or_default(),
        "volumes": volumes,
        "command": cmd,
        "tty": cfg.tty.unwrap_or(false),
        "interactive": cfg.open_stdin.unwrap_or(false),
        "networks": networks,
        "hostname": cfg.hostname.clone().unwrap_or_default(),
        "domainname": cfg.domainname.clone().unwrap_or_default(),
        "dns": hc.dns.clone().unwrap_or_default(),
        "cpu_shares": hc.cpu_shares.unwrap_or(0),
        "cpus": cpus,
        "memory": memory,
        "privileged": hc.privileged.unwrap_or(false),
    }))
}

/// Recreate-form ports from `host_config.port_bindings` ("port/proto" -> binds).
/// A port mapped on both 0.0.0.0 and :: shares one host port — collapse into one
/// row and flag ipv6.
fn inspect_ports(hc: &bollard::models::HostConfig) -> Vec<Value> {
    let mut ports = Vec::new();
    let Some(pb) = &hc.port_bindings else {
        return ports;
    };
    for (key, binds) in pb {
        let (cport, proto) = match key.split_once('/') {
            Some((p, pr)) => (p.parse::<i64>().unwrap_or(0), pr.to_string()),
            None => (key.parse::<i64>().unwrap_or(0), "tcp".to_string()),
        };
        let Some(list) = binds else { continue };
        let mut seen: HashMap<i64, bool> = HashMap::new();
        for b in list {
            if let Some(hp) = b.host_port.as_deref().and_then(|s| s.parse::<i64>().ok()) {
                let is6 = b
                    .host_ip
                    .as_deref()
                    .map(|s| s.contains(':'))
                    .unwrap_or(false);
                let e = seen.entry(hp).or_insert(false);
                *e = *e || is6;
            }
        }
        for (hp, v6) in seen {
            ports.push(json!({ "host": hp, "container": cport, "proto": proto, "ipv6": v6 }));
        }
    }
    ports
}

/// Recreate-form volume rows from `host_config.binds` ("host:container[:ro]").
fn inspect_volumes(hc: &bollard::models::HostConfig) -> Vec<Value> {
    let mut volumes = Vec::new();
    let Some(binds) = &hc.binds else {
        return volumes;
    };
    for b in binds {
        let parts: Vec<&str> = b.split(':').collect();
        if parts.len() >= 2 && parts[0].starts_with('/') {
            volumes.push(json!({
                "host": parts[0],
                "container": parts[1],
                "readonly": parts.get(2).map(|m| *m == "ro").unwrap_or(false),
            }));
        }
    }
    volumes
}

/// Restart-policy name as a recreate-form string.
fn inspect_restart(hc: &bollard::models::HostConfig) -> String {
    hc.restart_policy
        .as_ref()
        .and_then(|p| p.name)
        .map(|n| match n {
            bollard::models::RestartPolicyNameEnum::ALWAYS => "always",
            bollard::models::RestartPolicyNameEnum::NO => "no",
            _ => "unless-stopped",
        })
        .unwrap_or("unless-stopped")
        .to_string()
}

/// Recreate-form network attachments (user-defined networks only; built-in
/// host/none modes can't be recreated this way) with per-endpoint MAC / IPv4.
fn inspect_networks(ns: Option<&bollard::models::NetworkSettings>) -> Vec<Value> {
    let mut networks: Vec<Value> = Vec::new();
    let Some(nets) = ns.and_then(|n| n.networks.as_ref()) else {
        return networks;
    };
    for (nname, ep) in nets {
        if matches!(nname.as_str(), "host" | "none") {
            continue;
        }
        networks.push(json!({
            "network": nname,
            "mac": ep.mac_address.clone().unwrap_or_default(),
            "ipv4": ep
                .ipam_config
                .as_ref()
                .and_then(|i| i.ipv4_address.clone())
                .unwrap_or_default(),
        }));
    }
    networks
}

/// get_container_config op: pre-fill the edit/upgrade form.
pub(crate) async fn get_container_config(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let body = container_create_body(&dkr, &r).await?;
    Ok(json!({ "config": body }))
}
