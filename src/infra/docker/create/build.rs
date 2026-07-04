//! Container creation: validated spec build + create-policy guardrail.
use super::*;
use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};

/// Capability guardrail for the two host-escape create primitives: `privileged`
/// mode and a host/container network namespace. Both default to closed (an
/// unset request gets `privileged=false` / a bridge network) and are allowed
/// **only for the super-admin**, who opts in by explicitly requesting them. A
/// non-super caller requesting either is rejected before the container is built.
/// The bind-mount deny-list is enforced unconditionally in `spec_binds`.
///
/// The *rule* (what counts as a host-escape) lives in `core::docker`; this
/// adapter only supplies the request's facts, applies the super-admin decision,
/// and maps the verdict to the transitional `ERR_CODE:` channel.
pub(crate) fn enforce_create_policy(req: &Req, is_super: bool) -> Result<()> {
    if is_super {
        return Ok(());
    }
    // Every requested network attachment (the multi-net `networks` list + the
    // single `network` field).
    let net_modes = req
        .networks
        .iter()
        .flatten()
        .map(|a| a.network.as_str())
        .chain(req.network.as_deref());
    match crate::core::docker::create_escalation(req.privileged.unwrap_or(false), net_modes) {
        Some(crate::core::docker::CreateEscalation::Privileged) => {
            Err(docker_err(DockerError::PrivilegedRequiresSuper))
        }
        Some(crate::core::docker::CreateEscalation::HostNetwork) => {
            Err(docker_err(DockerError::HostNetworkRequiresSuper))
        }
        None => Ok(()),
    }
}

/// Build a bollard create config from a validated request. Every user value is
/// validated before it lands in the config (no shell, no CLI args).
pub(crate) fn build_create_spec(req: &Req) -> Result<(CreateSpec, String)> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    // Name (optional).
    let mut display_name = String::new();
    let mut name: Option<String> = None;
    if let Some(n) = req.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_name(n)?;
        display_name = n.to_string();
        name = Some(n.to_string());
    }

    // Restart policy (whitelisted; default unless-stopped).
    let restart_policy = spec_restart(req)?;

    // Network attachments (a container can join several). The first is applied
    // on the create call; the rest are connected right after creation.
    let attachments = spec_attachments(req)?;
    let network: Option<String> = attachments.first().map(|a| a.network.clone());

    // Port mappings -> exposed_ports + host port bindings.
    let (exposed, bindings) = spec_ports(req)?;

    // Published ports are meaningless in host/none network mode (host mode
    // already exposes every port; none has no connectivity at all) — reject the
    // combination instead of letting the mapping silently do nothing.
    if !bindings.is_empty() && matches!(network.as_deref(), Some("host") | Some("none")) {
        return Err(docker_err(DockerError::PortsWithHostNet));
    }

    // Environment variables.
    let env = spec_env(req)?;

    // Volume mounts -> binds.
    let binds = spec_binds(req)?;

    // Resource limits (cgroup v2). Validated formats only, capped to the host.
    let (nano_cpus, memory) = spec_cpu_mem(req)?;

    let tty = req.tty.unwrap_or(false);
    // -i: keep STDIN open. Defaults to the same value as -t so a single legacy
    // `tty: true` request still behaves as before (interactive + TTY).
    let interactive = req.interactive.unwrap_or(tty);

    // CPU weight (cpu-shares). Default 1024 (docker's own default). 0 or unset
    // means "leave at default".
    let cpu_shares: Option<i64> = match req.cpu_shares {
        Some(v) if v > 0 => {
            if !(2..=262144).contains(&v) {
                return Err(docker_err(DockerError::CpuSharesRange));
            }
            Some(v)
        }
        _ => None,
    };

    let privileged = req.privileged.unwrap_or(false);

    // DNS servers (validated IPv4 each).
    let dns = spec_dns(req)?;

    // Hostname / domainname (optional).
    let hostname = match opt_trim(&req.hostname) {
        Some(h) => {
            valid_hostname(&h)?;
            Some(h)
        }
        None => None,
    };
    let domainname = match opt_trim(&req.domainname) {
        Some(d) => {
            valid_hostname(&d)?;
            Some(d)
        }
        None => None,
    };

    // Per-endpoint network options for the FIRST attachment (static IPv4 / MAC),
    // applied on the create call. Remaining attachments are connected after.
    let networking_config = spec_networking_config(attachments.first());
    let extra_networks: Vec<NetAttach> = attachments.into_iter().skip(1).collect();

    // Optional command override.
    let cmd: Option<Vec<String>> = match req
        .command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(c) => Some(split_command(c)?),
        None => None,
    };

    let host_config = HostConfig {
        restart_policy: Some(restart_policy),
        binds: if binds.is_empty() { None } else { Some(binds) },
        port_bindings: if bindings.is_empty() {
            None
        } else {
            Some(bindings)
        },
        nano_cpus,
        memory,
        cpu_shares,
        privileged: Some(privileged),
        dns: if dns.is_empty() { None } else { Some(dns) },
        network_mode: network,
        ..Default::default()
    };

    let config = bollard::container::Config {
        image: Some(image.clone()),
        cmd,
        env: if env.is_empty() { None } else { Some(env) },
        tty: Some(tty),
        open_stdin: Some(interactive),
        hostname,
        domainname,
        exposed_ports: if exposed.is_empty() {
            None
        } else {
            Some(exposed)
        },
        host_config: Some(host_config),
        networking_config,
        ..Default::default()
    };

    Ok((
        CreateSpec {
            image,
            name,
            start: req.start.unwrap_or(true),
            config,
            replace: opt_trim(&req.replace),
            extra_networks,
        },
        display_name,
    ))
}

/// Restart policy from the request (whitelisted; default unless-stopped).
/// `on-failure[:N]` carries N through as Docker's maximum-retry-count.
fn spec_restart(req: &Req) -> Result<RestartPolicy> {
    let restart = req
        .restart
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unless-stopped");
    if !restart_allowed(restart) {
        return Err(docker_err(DockerError::BadRestartPolicy));
    }
    let (kind, retries) = match restart.split_once(':') {
        Some((k, n)) => (k, n.parse::<i64>().ok()),
        None => (restart, None),
    };
    Ok(RestartPolicy {
        name: Some(match kind {
            "always" => RestartPolicyNameEnum::ALWAYS,
            "no" => RestartPolicyNameEnum::NO,
            "on-failure" => RestartPolicyNameEnum::ON_FAILURE,
            _ => RestartPolicyNameEnum::UNLESS_STOPPED,
        }),
        maximum_retry_count: retries,
    })
}

/// Validate one `{network, mac?, ipv4?}` attachment into a `NetAttach`.
fn spec_one_attach(
    network: &str,
    mac: &Option<String>,
    ipv4: &Option<String>,
) -> Result<NetAttach> {
    validate_token(network)?;
    let mac = match opt_trim(mac) {
        Some(m) => {
            valid_mac(&m)?;
            Some(m)
        }
        None => None,
    };
    let ipv4 = match opt_trim(ipv4) {
        Some(ip) => {
            valid_ipv4(&ip)?;
            Some(ip)
        }
        None => None,
    };
    Ok(NetAttach {
        network: network.to_string(),
        mac,
        ipv4,
    })
}

/// Network attachments (a container can join several). Prefer the explicit
/// list; fall back to the legacy single network/mac/ipv4 fields. Deduped.
fn spec_attachments(req: &Req) -> Result<Vec<NetAttach>> {
    let mut attachments: Vec<NetAttach> = Vec::new();
    if let Some(list) = &req.networks {
        for a in list {
            let name = a.network.trim();
            if name.is_empty() {
                continue;
            }
            if attachments.iter().any(|x| x.network == name) {
                continue; // dedupe
            }
            attachments.push(spec_one_attach(name, &a.mac, &a.ipv4)?);
        }
    } else if let Some(net) = req
        .network
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        attachments.push(spec_one_attach(net, &req.mac, &req.ipv4)?);
    }
    if attachments.len() > 16 {
        return Err(docker_err(DockerError::TooManyNetworks));
    }
    Ok(attachments)
}

type PortSpec = (
    HashMap<String, HashMap<(), ()>>,
    HashMap<String, Option<Vec<PortBinding>>>,
);

/// Port mappings -> (exposed_ports, host port bindings).
fn spec_ports(req: &Req) -> Result<PortSpec> {
    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    let mut bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    let Some(ports) = &req.ports else {
        return Ok((exposed, bindings));
    };
    if ports.len() > 50 {
        return Err(docker_err(DockerError::TooManyPorts));
    }
    for p in ports {
        if p.host < 1 || p.host > 65535 || p.container < 1 || p.container > 65535 {
            return Err(docker_err(DockerError::PortRange));
        }
        let proto = p.proto.as_deref().unwrap_or("tcp");
        if proto != "tcp" && proto != "udp" {
            return Err(docker_err(DockerError::BadProto));
        }
        let key = format!("{}/{}", p.container, proto);
        exposed.insert(key.clone(), HashMap::new());
        // Default IPv4 wildcard (0.0.0.0) binding; when ipv6 is on, also add an
        // IPv6 wildcard (::) binding for the same host port.
        let mut binds = vec![PortBinding {
            host_ip: None,
            host_port: Some(p.host.to_string()),
        }];
        if p.ipv6.unwrap_or(false) {
            binds.push(PortBinding {
                host_ip: Some("::".to_string()),
                host_port: Some(p.host.to_string()),
            });
        }
        bindings.insert(key, Some(binds));
    }
    Ok((exposed, bindings))
}

/// Validated environment variables.
fn spec_env(req: &Req) -> Result<Vec<String>> {
    let mut env: Vec<String> = Vec::new();
    let Some(envs) = &req.env else { return Ok(env) };
    if envs.len() > 100 {
        return Err(docker_err(DockerError::TooManyEnvs));
    }
    for e in envs {
        let e = e.trim();
        if e.is_empty() {
            continue;
        }
        validate_env(e)?;
        env.push(e.to_string());
    }
    Ok(env)
}

/// Volume mounts -> bind specs ("src:dst[:ro]").
fn spec_binds(req: &Req) -> Result<Vec<String>> {
    let mut binds: Vec<String> = Vec::new();
    let Some(vols) = &req.volumes else {
        return Ok(binds);
    };
    if vols.len() > 50 {
        return Err(docker_err(DockerError::TooManyMounts));
    }
    for v in vols {
        let host = v.host.trim();
        let container = v.container.trim();
        // Source is either an absolute host path (bind mount) or a named docker
        // volume (no leading slash). The container target is always absolute.
        if host.starts_with('/') {
            // Host-compromise gate (deny-list + symlink re-check), shared with
            // create_volume_op so the two bind-source paths can't drift.
            validate_bind_source(host)?;
        } else {
            validate_name(host)?;
        }
        validate_path(container)?;
        binds.push(if v.readonly {
            format!("{host}:{container}:ro")
        } else {
            format!("{host}:{container}")
        });
    }
    Ok(binds)
}

/// CPU (NanoCPUs) and memory (bytes) limits, validated and capped to the host.
fn spec_cpu_mem(req: &Req) -> Result<(Option<i64>, Option<i64>)> {
    let mut nano_cpus: Option<i64> = None;
    let mut memory: Option<i64> = None;
    if let Some(cpus) = req.cpus.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_cpus(cpus)?;
        let host = host_cpus();
        let v: f64 = cpus.parse().unwrap_or(0.0);
        if host > 0 && v > host as f64 {
            return Err(anyhow!("CPU 限制不能超过宿主机核数（{host}）"));
        }
        nano_cpus = Some((v * 1_000_000_000.0) as i64);
    }
    if let Some(mem) = req
        .memory
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_memory(mem)?;
        let host = host_mem_bytes();
        let bytes = mem_to_bytes(mem);
        if host > 0 && bytes > host {
            return Err(docker_err(DockerError::MemOverHost));
        }
        memory = Some(bytes as i64);
    }
    Ok((nano_cpus, memory))
}

/// Validated DNS server list (IPv4 each, capped).
fn spec_dns(req: &Req) -> Result<Vec<String>> {
    let mut dns: Vec<String> = Vec::new();
    let Some(list) = &req.dns else { return Ok(dns) };
    if list.len() > 8 {
        return Err(docker_err(DockerError::TooManyDns));
    }
    for d in list {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        valid_ipv4(d)?;
        dns.push(d.to_string());
    }
    Ok(dns)
}

/// Per-endpoint networking config for the first attachment, when it carries a
/// static IPv4 or MAC (applied on the create call).
fn spec_networking_config(
    first: Option<&NetAttach>,
) -> Option<bollard::container::NetworkingConfig<String>> {
    let a = first?;
    if a.mac.is_none() && a.ipv4.is_none() {
        return None;
    }
    let mut endpoints = HashMap::new();
    endpoints.insert(
        a.network.clone(),
        bollard::models::EndpointSettings {
            ipam_config: a
                .ipv4
                .clone()
                .map(|ip| bollard::models::EndpointIpamConfig {
                    ipv4_address: Some(ip),
                    ..Default::default()
                }),
            mac_address: a.mac.clone(),
            ..Default::default()
        },
    );
    Some(bollard::container::NetworkingConfig {
        endpoints_config: endpoints,
    })
}
