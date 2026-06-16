//! Cert expiry parse, nginx reload, and upstream resolution helpers (split from access.rs).
use super::*;

/// Best-effort parse of a PEM cert's notAfter (expiry) as an ISO date string.
/// Implemented in the `certparse` submodule (minimal ASN.1 walk).
pub(crate) fn cert_not_after(pem: &str) -> Option<String> {
    parse_cert_not_after(pem)
}

/// Reload nginx (`nginx -s reload`).
pub(crate) async fn reload() -> Result<()> {
    let lo = layout()?;
    validate_and_reload(&lo).await
}

/// `nginx -t` then `nginx -s reload`. Errors carry nginx's own message so a bad
/// generated config is visible.
pub(crate) async fn validate_and_reload(_lo: &Layout) -> Result<()> {
    let (ok, _o, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())
        ));
    }
    let (ok, _o, e) = run("nginx", &["-s", "reload"]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
    }
    Ok(())
}

/// Resolve a container's first reachable IPv4 address from the Docker daemon
/// (used in **host mode**, where the host's nginx can't resolve a container
/// *name* — only an IP works). Returns the IP from a user-defined network if
/// present, else the default bridge IP, else None.
pub(crate) async fn container_ip(target: &str) -> Option<String> {
    let dkr = crate::infra::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let networks = inspect.network_settings.and_then(|n| n.networks)?;
    // Prefer a user-defined network's IP; fall back to the bridge.
    let mut bridge_ip: Option<String> = None;
    for (name, ep) in networks {
        let ip = ep.ip_address.filter(|s| !s.is_empty());
        match ip {
            Some(ip) if name == "bridge" => bridge_ip = Some(ip),
            Some(ip) => return Some(ip), // user-defined network IP preferred
            None => {}
        }
    }
    bridge_ip
}

/// In **host mode**, find the host port that publishes the container's
/// `container_port` on the **loopback interface** (so the host's nginx can proxy
/// to `127.0.0.1:<host_port>`, stable across container restarts — unlike the
/// container IP). Returns None when the port isn't published, or is published
/// only on a specific *external* interface that loopback can't reach (the caller
/// then falls back to the container IP).
pub(crate) async fn published_host_port(target: &str, container_port: i64) -> Option<u16> {
    let dkr = crate::infra::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let ports = inspect.network_settings.and_then(|n| n.ports)?;
    // Docker keys ports like "3000/tcp" -> [{HostIp, HostPort}, ...]. Only the
    // TCP binding is usable for an HTTP reverse proxy; ignore UDP.
    let key_tcp = format!("{container_port}/tcp");
    for (key, binds) in ports {
        if key != key_tcp {
            continue;
        }
        if let Some(binds) = binds {
            for b in binds {
                // A binding to a specific external IP (e.g. 1.2.3.4) is NOT
                // reachable from the host's nginx via 127.0.0.1, so only accept
                // wildcard / loopback HostIps. Empty == 0.0.0.0 (all interfaces).
                let host_ip = b.host_ip.as_deref().unwrap_or("");
                let loopback_reachable = matches!(
                    host_ip,
                    "" | "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "[::]"
                );
                if !loopback_reachable {
                    continue;
                }
                if let Some(hp) = b.host_port.and_then(|p| p.parse::<u16>().ok()) {
                    return Some(hp);
                }
            }
        }
    }
    None
}

/// Resolve the proxy upstream (`host:port`) for a site:
///  - **proxy_host**: the user-supplied host[:port] as-is.
///  - **proxy_container**: the host's nginx can't resolve a container name.
///    Prefer the published host port (`127.0.0.1:<hostport>`, stable across
///    restarts); otherwise fall back to the container's bridge IP.
pub(crate) async fn resolve_upstream(_lo: &Layout, site: &Site) -> Result<String> {
    match site.kind.as_str() {
        "proxy_host" => Ok(with_scheme_port(&site.target_url, &site.scheme)),
        "proxy_container" => resolve_container_upstream(&site.container, site.container_port).await,
        _ => Ok(String::new()),
    }
}

/// Resolve a container's `host:port` upstream for the host nginx: prefer the
/// published host port (`127.0.0.1:<hostport>`, restart-stable), otherwise fall
/// back to the container's bridge IP.
pub(crate) async fn resolve_container_upstream(
    container: &str,
    container_port: i64,
) -> Result<String> {
    if let Some(hp) = published_host_port(container, container_port).await {
        Ok(format!("127.0.0.1:{hp}"))
    } else {
        let ip = container_ip(container).await.ok_or_else(|| {
            anyhow!(
                "容器 {container} 未映射端口 {container_port} 到宿主机，且无法解析其 IP；请为容器发布该端口后重试"
            )
        })?;
        Ok(format!("{ip}:{container_port}"))
    }
}
