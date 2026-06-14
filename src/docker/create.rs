//! Container creation: spec build + create/recreate (split from docker.rs).
use super::*;

/// Build a bollard create config from a validated request. Every user value is
/// validated before it lands in the config (no shell, no CLI args).
pub(crate) fn build_create_spec(req: &Req) -> Result<(CreateSpec, String)> {
    use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};

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
    let restart = req
        .restart
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unless-stopped");
    if !restart_allowed(restart) {
        return Err(anyhow!("ERR_CODE:docker.bad_restart_policy"));
    }
    let restart_policy = RestartPolicy {
        name: Some(match restart {
            "always" => RestartPolicyNameEnum::ALWAYS,
            "no" => RestartPolicyNameEnum::NO,
            _ => RestartPolicyNameEnum::UNLESS_STOPPED,
        }),
        maximum_retry_count: None,
    };

    // Network attachments (a container can join several). Prefer the explicit
    // list; fall back to the legacy single network/mac/ipv4 fields. Each is
    // validated; the first is applied on the create call (host_config +
    // networking_config), the rest are connected right after creation.
    let mut attachments: Vec<NetAttach> = Vec::new();
    if let Some(list) = &req.networks {
        for a in list {
            let name = a.network.trim();
            if name.is_empty() {
                continue;
            }
            validate_token(name)?;
            let mac = match opt_trim(&a.mac) {
                Some(m) => {
                    valid_mac(&m)?;
                    Some(m)
                }
                None => None,
            };
            let ipv4 = match opt_trim(&a.ipv4) {
                Some(ip) => {
                    valid_ipv4(&ip)?;
                    Some(ip)
                }
                None => None,
            };
            if attachments.iter().any(|x| x.network == name) {
                continue; // dedupe
            }
            attachments.push(NetAttach {
                network: name.to_string(),
                mac,
                ipv4,
            });
        }
    } else if let Some(net) = req
        .network
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_token(net)?;
        let mac = match opt_trim(&req.mac) {
            Some(m) => {
                valid_mac(&m)?;
                Some(m)
            }
            None => None,
        };
        let ipv4 = match opt_trim(&req.ipv4) {
            Some(ip) => {
                valid_ipv4(&ip)?;
                Some(ip)
            }
            None => None,
        };
        attachments.push(NetAttach {
            network: net.to_string(),
            mac,
            ipv4,
        });
    }
    if attachments.len() > 16 {
        return Err(anyhow!("ERR_CODE:docker.too_many_networks"));
    }
    let network: Option<String> = attachments.first().map(|a| a.network.clone());

    // Port mappings -> exposed_ports + host port bindings.
    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    let mut bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    if let Some(ports) = &req.ports {
        if ports.len() > 50 {
            return Err(anyhow!("ERR_CODE:docker.too_many_ports"));
        }
        for p in ports {
            if p.host < 1 || p.host > 65535 || p.container < 1 || p.container > 65535 {
                return Err(anyhow!("ERR_CODE:docker.port_range"));
            }
            let proto = p.proto.as_deref().unwrap_or("tcp");
            if proto != "tcp" && proto != "udp" {
                return Err(anyhow!("ERR_CODE:docker.bad_proto"));
            }
            let key = format!("{}/{}", p.container, proto);
            exposed.insert(key.clone(), HashMap::new());
            // Default IPv4 wildcard (0.0.0.0) binding; when ipv6 is on, also add
            // an IPv6 wildcard (::) binding for the same host port.
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
    }

    // Environment variables.
    let mut env: Vec<String> = Vec::new();
    if let Some(envs) = &req.env {
        if envs.len() > 100 {
            return Err(anyhow!("ERR_CODE:docker.too_many_envs"));
        }
        for e in envs {
            let e = e.trim();
            if e.is_empty() {
                continue;
            }
            validate_env(e)?;
            env.push(e.to_string());
        }
    }

    // Volume mounts -> binds.
    let mut binds: Vec<String> = Vec::new();
    if let Some(vols) = &req.volumes {
        if vols.len() > 50 {
            return Err(anyhow!("ERR_CODE:docker.too_many_mounts"));
        }
        for v in vols {
            let host = v.host.trim();
            let container = v.container.trim();
            // Source is either an absolute host path (bind mount) or a named
            // docker volume (no leading slash). The container target must always
            // be an absolute path.
            if host.starts_with('/') {
                validate_path(host)?;
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
    }

    // Resource limits (cgroup v2). Validated formats only, capped to the host.
    let mut nano_cpus: Option<i64> = None;
    let mut memory: Option<i64> = None;
    if let Some(cpus) = req.cpus.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_cpus(cpus)?;
        let host = host_cpus();
        let v: f64 = cpus.parse().unwrap_or(0.0);
        if host > 0 && v > host as f64 {
            return Err(anyhow!("CPU 限制不能超过宿主机核数（{host}）"));
        }
        // docker NanoCPUs = cpus * 1e9.
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
            return Err(anyhow!("ERR_CODE:docker.mem_over_host"));
        }
        memory = Some(bytes as i64);
    }

    let tty = req.tty.unwrap_or(false);
    // -i: keep STDIN open. Defaults to the same value as -t so a single legacy
    // `tty: true` request still behaves as before (interactive + TTY).
    let interactive = req.interactive.unwrap_or(tty);

    // CPU weight (cpu-shares). Default 1024 (docker's own default). 0 or unset
    // means "leave at default".
    let cpu_shares: Option<i64> = match req.cpu_shares {
        Some(v) if v > 0 => {
            if !(2..=262144).contains(&v) {
                return Err(anyhow!("ERR_CODE:docker.cpu_shares_range"));
            }
            Some(v)
        }
        _ => None,
    };

    let privileged = req.privileged.unwrap_or(false);

    // DNS servers (validated IPv4 each).
    let mut dns: Vec<String> = Vec::new();
    if let Some(list) = &req.dns {
        if list.len() > 8 {
            return Err(anyhow!("ERR_CODE:docker.too_many_dns"));
        }
        for d in list {
            let d = d.trim();
            if d.is_empty() {
                continue;
            }
            valid_ipv4(d)?;
            dns.push(d.to_string());
        }
    }

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
    let first = attachments.first().cloned();
    let networking_config = match &first {
        Some(a) if a.mac.is_some() || a.ipv4.is_some() => {
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
        _ => None,
    };
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
        network_mode: network.clone(),
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

/// Validate a `--cpus` value: a positive decimal like "0.5", "1", "2.5".
pub(crate) fn validate_cpus(s: &str) -> Result<()> {
    let v: f64 = s
        .parse()
        .map_err(|_| anyhow!("ERR_CODE:docker.bad_cpu_format"))?;
    if v <= 0.0 || v > 1024.0 {
        return Err(anyhow!("ERR_CODE:docker.cpu_out_of_range"));
    }
    // Restrict the charset too (parse alone would accept "inf"/"NaN").
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(anyhow!("ERR_CODE:docker.bad_cpu_format"));
    }
    Ok(())
}

/// Validate a `--memory` value: a positive integer with an optional b/k/m/g
/// suffix, e.g. "512m", "1g", "268435456".
pub(crate) fn validate_memory(s: &str) -> Result<()> {
    let lower = s.to_ascii_lowercase();
    let (num, _suffix) = match lower.chars().last() {
        Some(c) if matches!(c, 'b' | 'k' | 'm' | 'g') => (&lower[..lower.len() - 1], Some(c)),
        _ => (lower.as_str(), None),
    };
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("ERR_CODE:docker.bad_mem_format"));
    }
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("ERR_CODE:docker.bad_mem_format"))?;
    if n == 0 {
        return Err(anyhow!("ERR_CODE:docker.mem_too_small"));
    }
    Ok(())
}

/// Convert a validated `--memory` value to bytes (for the host cap). Returns 0
/// for an unparseable value (treated as "no cap" by the caller).
pub(crate) fn mem_to_bytes(s: &str) -> u64 {
    let lower = s.to_ascii_lowercase();
    let (num, mult) = match lower.chars().last() {
        Some('b') => (&lower[..lower.len() - 1], 1u64),
        Some('k') => (&lower[..lower.len() - 1], 1024),
        Some('m') => (&lower[..lower.len() - 1], 1024 * 1024),
        Some('g') => (&lower[..lower.len() - 1], 1024 * 1024 * 1024),
        _ => (lower.as_str(), 1),
    };
    num.parse::<u64>()
        .ok()
        .map(|n| n.saturating_mul(mult))
        .unwrap_or(0)
}

/// Split a command string into argv. Supports simple single/double quoting; no
/// shell features (no globbing, pipes, substitution). Each token is a separate
/// argv entry passed to `docker run`, so there's no shell-injection surface.
pub(crate) fn split_command(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has_token = false;
    for c in s.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    has_token = true;
                }
                ' ' | '\t' => {
                    if has_token {
                        out.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                '\n' | '\r' => return Err(anyhow!("ERR_CODE:docker.cmd_no_newline")),
                _ => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err(anyhow!("ERR_CODE:docker.cmd_unclosed_quote"));
    }
    if has_token {
        out.push(cur);
    }
    if out.len() > 100 {
        return Err(anyhow!("ERR_CODE:docker.cmd_too_many_args"));
    }
    Ok(out)
}

/// True when a host port is already bound by some other process on the box.
/// Only `AddrInUse` counts as busy — a permission error (privileged port and
/// we're not root) must not be reported as a conflict (false positive).
pub(crate) fn port_busy(port: i64, proto: &str) -> bool {
    if !(1..=65535).contains(&port) {
        return false;
    }
    let addr = ("0.0.0.0", port as u16);
    let inuse = |e: std::io::Error| e.kind() == std::io::ErrorKind::AddrInUse;
    if proto == "udp" {
        std::net::UdpSocket::bind(addr).err().is_some_and(inuse)
    } else {
        std::net::TcpListener::bind(addr).err().is_some_and(inuse)
    }
}

/// Reject a create/edit when its published host ports clash with: (a) another
/// port in the same form, (b) a port already published by a different running
/// container, or (c) a port held by some other host process. The container being
/// replaced (edit/upgrade) is excluded so it can reuse its own ports.
pub(crate) async fn check_port_conflicts(req: &Req) -> Result<()> {
    let ports = match &req.ports {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()),
    };

    // (a) Duplicate host port (same protocol) within the form itself.
    let mut seen: std::collections::HashSet<(i64, String)> = std::collections::HashSet::new();
    for p in ports {
        let proto = p.proto.as_deref().unwrap_or("tcp").to_string();
        if !seen.insert((p.host, proto.clone())) {
            return Err(anyhow!(
                "宿主机端口 {}/{} 在表单中重复，请勿映射同一端口多次。",
                p.host,
                proto.to_uppercase()
            ));
        }
    }

    // Containers whose ports we may reuse (edit/upgrade replaces them).
    let mut excluded: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(r) = opt_trim(&req.replace) {
        excluded.insert(r);
    }
    if let Some(n) = opt_trim(&req.name) {
        excluded.insert(n);
    }

    // Map every host port published by a running container -> owner name.
    let dkr = dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: false,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut held: HashMap<(i64, String), String> = HashMap::new();
    for c in &containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        if let Some(pts) = &c.ports {
            for prt in pts {
                if let Some(pub_port) = prt.public_port {
                    let proto = prt
                        .typ
                        .map(|t| format!("{t:?}").to_lowercase())
                        .unwrap_or_else(|| "tcp".to_string());
                    held.entry((pub_port as i64, proto))
                        .or_insert_with(|| name.clone());
                }
            }
        }
    }

    // (b) container conflict, then (c) host-process conflict.
    for p in ports {
        let proto = p.proto.as_deref().unwrap_or("tcp").to_string();
        let key = (p.host, proto.clone());
        match held.get(&key) {
            Some(owner) if !excluded.contains(owner) => {
                return Err(anyhow!(
                    "宿主机端口 {}/{} 已被容器「{}」占用，无法映射。",
                    p.host,
                    proto.to_uppercase(),
                    owner
                ));
            }
            // Held by the container we're replacing — reusing it is fine.
            Some(_) => {}
            None => {
                if port_busy(p.host, &proto) {
                    return Err(anyhow!(
                        "宿主机端口 {}/{} 已被其他进程占用，无法映射。",
                        p.host,
                        proto.to_uppercase()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validate the request, register a detached op, create the container via the
/// daemon API, and (when requested) start it. Returns an op_id.
pub(crate) fn start_create(req: &Req) -> Result<Value> {
    let (spec, display_name) = build_create_spec(req)?;
    let target = if display_name.is_empty() {
        spec.image.clone()
    } else {
        display_name.clone()
    };

    let op_id = new_op_id();
    op_create(&op_id, "create", &target);

    let op_id_t = op_id.clone();
    let target_t = target.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.creating_container", &[]));
        match create_container(spec).await {
            Ok((id, started)) => {
                let short = id.chars().take(12).collect::<String>();
                op_push(
                    &op_id_t,
                    &pmsg(
                        "dk.container_created",
                        &[
                            if started {
                                "@dklbl.created_started"
                            } else {
                                "@dklbl.created"
                            },
                            short.as_str(),
                        ],
                    ),
                );
                op_finish(&op_id_t, "done", "", &target_t);
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": target }))
}

/// Create (and optionally start) a container via the daemon API. Returns the
/// new container id and whether it was started.
pub(crate) async fn create_container(spec: CreateSpec) -> Result<(String, bool)> {
    let dkr = dkr()?;
    // Edit/upgrade: remove the container being replaced first so the new one can
    // reuse its name. Managed service containers are never replaced this way.
    if let Some(old) = spec.replace.as_deref() {
        if let Some(why) = managed_container_guard(old).await {
            return Err(anyhow!(why));
        }
        let opts = bollard::container::RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        dkr.remove_container(old, Some(opts))
            .await
            .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    let options = spec
        .name
        .clone()
        .map(|name| bollard::container::CreateContainerOptions {
            name,
            platform: None,
        });
    let created = dkr
        .create_container(options, spec.config)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let id = created.id;
    // Connect any additional networks before starting, each with its optional
    // MAC / static IPv4 endpoint config.
    for a in &spec.extra_networks {
        let endpoint = bollard::models::EndpointSettings {
            ipam_config: a
                .ipv4
                .clone()
                .map(|ip| bollard::models::EndpointIpamConfig {
                    ipv4_address: Some(ip),
                    ..Default::default()
                }),
            mac_address: a.mac.clone(),
            ..Default::default()
        };
        dkr.connect_network(
            &a.network,
            bollard::network::ConnectNetworkOptions {
                container: id.clone(),
                endpoint_config: endpoint,
            },
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    if spec.start {
        dkr.start_container(
            &id,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok((id, spec.start))
}
