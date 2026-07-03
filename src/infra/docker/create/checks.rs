//! Container-create validators + host-port conflict detection (split from create.rs).
use super::*;

/// Validate a `--cpus` value: a positive decimal like "0.5", "1", "2.5".
pub(crate) fn validate_cpus(s: &str) -> Result<()> {
    let v: f64 = s
        .parse()
        .map_err(|_| docker_err(DockerError::BadCpuFormat))?;
    if v <= 0.0 || v > 1024.0 {
        return Err(docker_err(DockerError::CpuOutOfRange));
    }
    // Restrict the charset too (parse alone would accept "inf"/"NaN").
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(docker_err(DockerError::BadCpuFormat));
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
        return Err(docker_err(DockerError::BadMemFormat));
    }
    let n: u64 = num
        .parse()
        .map_err(|_| docker_err(DockerError::BadMemFormat))?;
    if n == 0 {
        return Err(docker_err(DockerError::MemTooSmall));
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
                '\n' | '\r' => return Err(docker_err(DockerError::CmdNoNewline)),
                _ => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err(docker_err(DockerError::CmdUnclosedQuote));
    }
    if has_token {
        out.push(cur);
    }
    if out.len() > 100 {
        return Err(docker_err(DockerError::CmdTooManyArgs));
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
    reject_duplicate_ports(ports)?;

    // Containers whose ports we may reuse (edit/upgrade replaces them).
    let mut excluded: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(r) = opt_trim(&req.replace) {
        excluded.insert(r);
    }
    if let Some(n) = opt_trim(&req.name) {
        excluded.insert(n);
    }

    // Map every host port published by a running container -> owner name.
    let held = held_host_ports().await?;

    // (b) container conflict, then (c) host-process conflict.
    for p in ports {
        let proto = p.proto.as_deref().unwrap_or("tcp").to_string();
        let key = (p.host, proto.clone());
        match held.get(&key) {
            Some(owner) if !excluded.contains(owner) => {
                return Err(anyhow!(
                    "ERR_CODE:docker.port_in_use_container\u{1f}{}\u{1f}{}\u{1f}{}",
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
                        "ERR_CODE:docker.port_in_use_process\u{1f}{}\u{1f}{}",
                        p.host,
                        proto.to_uppercase()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Reject a host port + protocol mapped more than once within the same request.
pub(crate) fn reject_duplicate_ports(ports: &[PortMap]) -> Result<()> {
    let mut seen: std::collections::HashSet<(i64, String)> = std::collections::HashSet::new();
    for p in ports {
        let proto = p.proto.as_deref().unwrap_or("tcp").to_string();
        if !seen.insert((p.host, proto.clone())) {
            return Err(anyhow!(
                "ERR_CODE:docker.port_duplicated\u{1f}{}\u{1f}{}",
                p.host,
                proto.to_uppercase()
            ));
        }
    }
    Ok(())
}

/// Map every host port currently published by a running container to its owner
/// container name, keyed by (host_port, protocol).
pub(crate) async fn held_host_ports() -> Result<HashMap<(i64, String), String>> {
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
        let Some(pts) = &c.ports else { continue };
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
    Ok(held)
}
