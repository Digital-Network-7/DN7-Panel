//! Container listing, inspect, logs (split from docker.rs).
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
    // containers this turns ~N*500ms into ~500ms total.
    let shell_futs = containers.iter().map(|c| {
        let dkr = dkr.clone();
        let id = c.id.clone().unwrap_or_default();
        let running = c.state.as_deref() == Some("running");
        async move {
            if running {
                container_has_shell(&dkr, &id).await
            } else {
                false
            }
        }
    });
    let shells = futures_util::future::join_all(shell_futs).await;

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
    // DN7 Panel-managed service containers (nginx / mysql) are marked so the UI
    // can show "内置" and hide direct controls (the panel also refuses ops on
    // them — see `managed_container_guard`).
    let has_mysql_label = c
        .labels
        .as_ref()
        .map(|l| l.contains_key("dn7.mysql"))
        .unwrap_or(false);
    let managed = name == crate::mysql::CONTAINER || has_mysql_label;
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

/// Probe whether a running container has a usable `/bin/sh` (so the terminal
/// button is only shown when an interactive shell can actually be opened).
pub(crate) async fn container_has_shell(dkr: &Docker, id: &str) -> bool {
    let exec = dkr
        .create_exec(
            id,
            bollard::exec::CreateExecOptions {
                cmd: Some(vec![
                    "/bin/sh",
                    "-c",
                    "for s in /bin/bash /bin/sh /bin/ash; do [ -x \"$s\" ] && exit 0; done; exit 1",
                ]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await;
    let exec = match exec {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Start it detached, then inspect the exit code.
    if dkr
        .start_exec(
            &exec.id,
            Some(bollard::exec::StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await
        .is_err()
    {
        return false;
    }
    // Give it a brief moment, then check the exit code.
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(inspect) = dkr.inspect_exec(&exec.id).await {
            if let Some(running) = inspect.running {
                if running {
                    continue;
                }
            }
            return inspect.exit_code == Some(0);
        }
    }
    false
}

/// Inspect one container for the detail page: identity, state, restart policy,
/// created time, and shell availability.
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

/// Tail a container's logs (via the daemon API).
/// Strip non-text bytes from decoded log output: keep newlines/tabs and any
/// valid printable character (including CJK/emoji), drop control characters and
/// the U+FFFD replacement marker left by invalid UTF-8. This turns a binary
/// line (e.g. a raw TLS handshake logged verbatim) into harmless short text
/// instead of a wall of escapes / boxes.
pub(crate) fn sanitize_log(s: &str) -> String {
    let filtered: String = s
        .chars()
        .filter(|&c| c == '\n' || c == '\r' || c == '\t' || (!c.is_control() && c != '\u{FFFD}'))
        .collect();
    strip_hex_escapes(&filtered)
}

/// Remove literal C-style hex escapes like `\x16\x03\x01…` that some servers
/// (notably nginx) write into their access logs when a client sends raw binary
/// to a text endpoint (e.g. a TLS ClientHello to a plain-HTTP port). They are
/// valid text but render as a wall of noise, so any run of them is collapsed
/// away. Three-digit octal escapes (`\NNN`) emitted by some loggers go too.
pub(crate) fn strip_hex_escapes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        // \xHH (hex byte escape)
        if i + 4 <= chars.len()
            && chars[i] == '\\'
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && chars[i + 2].is_ascii_hexdigit()
            && chars[i + 3].is_ascii_hexdigit()
        {
            i += 4;
            continue;
        }
        // \NNN (3-digit octal byte escape)
        if i + 4 <= chars.len()
            && chars[i] == '\\'
            && ('0'..='7').contains(&chars[i + 1])
            && ('0'..='7').contains(&chars[i + 2])
            && ('0'..='7').contains(&chars[i + 3])
        {
            i += 4;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

pub(crate) async fn container_logs(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let tail = req.tail.unwrap_or(200).clamp(1, 2000);
    let dkr = dkr()?;
    let opts = bollard::container::LogsOptions::<String> {
        stdout: true,
        stderr: true,
        tail: tail.to_string(),
        timestamps: false,
        ..Default::default()
    };
    let mut stream = dkr.logs(&r, Some(opts));
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(out) => bytes.extend_from_slice(&out.into_bytes()),
            Err(e) => {
                // "bytes remaining on stream" and similar end-of-stream framing
                // errors (common with TTY containers / stream teardown) are
                // benign — keep whatever we've already collected.
                let msg = e.to_string();
                if msg.contains("bytes remaining") || !bytes.is_empty() {
                    break;
                }
                return Err(anyhow!(friendly_docker_err(&e)));
            }
        }
    }
    // Decode leniently, then drop non-text bytes so a stray binary line (e.g. a
    // TLS handshake probe logged verbatim) doesn't fill the view with control /
    // replacement characters. Keeps newlines/tabs and all valid (incl. CJK) text.
    let mut text = sanitize_log(&String::from_utf8_lossy(&bytes));
    // If there's no output, a constantly-restarting container is the usual
    // cause. Surface its state + last exit code so the user understands why.
    if text.trim().is_empty() {
        if let Ok(c) = dkr.inspect_container(&r, None).await {
            let st = c.state.as_ref();
            let status = st
                .and_then(|s| s.status.map(|x| format!("{x:?}").to_lowercase()))
                .unwrap_or_default();
            let exit = st.and_then(|s| s.exit_code).unwrap_or(0);
            let err = st.and_then(|s| s.error.clone()).unwrap_or_default();
            let restarts = c.restart_count.unwrap_or(0);
            let mut hint = format!(
                "（容器暂无日志输出）\n状态：{status} · 退出码：{exit} · 重启次数：{restarts}"
            );
            if !err.trim().is_empty() {
                hint.push_str(&format!("\n错误：{}", err.trim()));
            }
            if restarts != 0 || status == "restarting" {
                hint.push_str(
                    "\n\n提示：容器可能因默认命令立即退出而不断重启。请在创建时开启「分配终端」或填写常驻启动命令（如 sleep infinity），或将重启策略设为 no。",
                );
            }
            text = hint;
        }
    }
    Ok(json!({ "logs": text }))
}

/// Simple single-container lifecycle ops (start/stop/restart/pause/unpause/
/// kill/remove) that share the shape: resolve ref, call one bollard method,
/// report the result. `kill`/`remove` also re-check the managed-container guard.
pub(crate) async fn container_action(req: &Req, action: &str) -> Result<Value> {
    use bollard::container::{KillContainerOptions, RemoveContainerOptions, StartContainerOptions};
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let verb: &str = match action {
        "start" => {
            dkr.start_container(&r, None::<StartContainerOptions<String>>)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "started"
        }
        "stop" => {
            dkr.stop_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "stopped"
        }
        "restart" => {
            dkr.restart_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "restarted"
        }
        "pause" => {
            dkr.pause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "paused"
        }
        "unpause" => {
            dkr.unpause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "resumed"
        }
        "kill" => {
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
            dkr.kill_container(&r, None::<KillContainerOptions<String>>)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "killed"
        }
        "remove" => {
            // Managed service containers must be removed from their own pages.
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
            let opts = RemoveContainerOptions {
                force: true,
                ..Default::default()
            };
            dkr.remove_container(&r, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            "removed"
        }
        other => return Err(anyhow!("unsupported container action: {other}")),
    };
    let mut m = serde_json::Map::new();
    m.insert(verb.to_string(), Value::String(r));
    Ok(Value::Object(m))
}
