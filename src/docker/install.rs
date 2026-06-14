//! Docker engine install (OS detect + scripted install) (split from docker.rs).
use super::*;

pub(crate) fn start_install(req: &Req) -> Result<Value> {
    const INSTALL_OP: &str = "install";
    // If an install is already running, just hand back its op id.
    if let Ok(m) = ops().lock() {
        if let Some(o) = m.get(INSTALL_OP) {
            if o.status == "running" {
                return Ok(
                    json!({ "op_id": INSTALL_OP, "target": "docker", "already_running": true }),
                );
            }
        }
    }

    if !is_root() {
        return Err(anyhow!("ERR_CODE:docker.need_root"));
    }

    // "distro" (docker.io, default) | "ce"; "auto" (default) | "cn" | "global".
    let channel = match req.channel.as_deref() {
        Some("ce") => "ce",
        _ => "distro",
    }
    .to_string();
    let region = match req.region.as_deref() {
        Some("cn") => "cn",
        Some("global") => "global",
        _ => "auto",
    }
    .to_string();

    op_create(INSTALL_OP, "install", "docker");
    tokio::spawn(async move {
        match run_install_detached(INSTALL_OP, &channel, &region).await {
            Ok(()) => op_finish(INSTALL_OP, "done", "", ""),
            Err(e) => op_finish(INSTALL_OP, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": INSTALL_OP, "target": "docker" }))
}

pub(crate) async fn run_install_detached(
    op_id: &str,
    channel: &str,
    region_pref: &str,
) -> Result<()> {
    if docker_is_installed().await {
        op_push(op_id, &pmsg("dk.already_installed", &[]));
        return Ok(());
    }

    let os = detect_os();
    op_push(
        op_id,
        &pmsg("dk.detected_os", &[os.pretty.as_str(), os.family.as_str()]),
    );

    let region = resolve_region(region_pref).await;
    op_push(
        op_id,
        &pmsg(
            "dk.install_method",
            &[
                if channel == "ce" {
                    "@dklbl.ce"
                } else {
                    "@dklbl.distro"
                },
                if region == "cn" {
                    "@dklbl.cn"
                } else {
                    "@dklbl.global"
                },
            ],
        ),
    );

    // Primary attempt: native distro package (friendliest, uses the system's
    // existing mirrors — no external Docker repo), or the official convenience
    // script for the `ce` channel / unknown distros.
    let primary = build_install_script(&os.family, channel, region);
    op_push(op_id, &pmsg("dk.start_install", &[]));
    let _ = stream_shell_to_op(op_id, &primary).await;

    // Universal fallback: if the daemon still isn't present, run get.docker.com
    // (it handles the repo setup for every supported distro). Covers e.g. RHEL/
    // Rocky/Alma where the distro repos ship podman, not a `docker` package.
    if !docker_is_installed().await {
        op_push(op_id, &pmsg("dk.fallback_script", &[]));
        let _ = stream_shell_to_op(op_id, &get_docker_script(region)).await;
    }

    // Region tuning + enable/start. For CN, write registry-mirror accelerators
    // (faster image pulls) before restarting; otherwise just ensure it's up.
    if region == "cn" {
        op_push(op_id, &pmsg("dk.config_mirror", &[]));
        let _ = stream_shell_to_op(op_id, REGISTRY_MIRROR_SCRIPT).await;
    } else {
        op_push(op_id, &pmsg("dk.starting", &[]));
        let _ = stream_shell_to_op(op_id, ENABLE_START_SCRIPT).await;
    }

    op_push(op_id, &pmsg("dk.verify_install", &[]));
    if docker_is_installed().await {
        op_push(op_id, &pmsg("dk.install_done", &[]));
        Ok(())
    } else {
        Err(anyhow!("ERR_CODE:docker.install_failed"))
    }
}

/// True when the Docker daemon is reachable (installed + running).
pub(crate) async fn docker_is_installed() -> bool {
    docker_info()
        .await
        .ok()
        .and_then(|i| i.get("installed").and_then(Value::as_bool))
        == Some(true)
}

/// Detected host OS family + a human label.
pub(crate) struct OsInfo {
    family: String,
    pretty: String,
}

/// Classify the host distro from `/etc/os-release` into an install family.
pub(crate) fn detect_os() -> OsInfo {
    fn unquote(s: &str) -> String {
        s.trim().trim_matches('"').to_string()
    }
    let txt = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let (mut id, mut like, mut name, mut ver) =
        (String::new(), String::new(), String::new(), String::new());
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = unquote(v);
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = unquote(v);
        } else if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            name = unquote(v);
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            ver = unquote(v);
        }
    }
    let hay = format!(" {} {} ", id.to_lowercase(), like.to_lowercase());
    let has = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));
    let family = if has(&["debian", "ubuntu", "linuxmint", "raspbian", "devuan", "pop"]) {
        "debian"
    } else if has(&[
        "rhel",
        "centos",
        "fedora",
        "rocky",
        "almalinux",
        "amzn",
        "ol",
        "oracle",
    ]) {
        "rhel"
    } else if has(&["suse", "sles", "opensuse"]) {
        "suse"
    } else if has(&["arch", "manjaro", "endeavouros"]) {
        "arch"
    } else if has(&["alpine"]) {
        "alpine"
    } else {
        "unknown"
    };
    let pretty = if !name.is_empty() {
        name
    } else if !id.is_empty() {
        format!("{id} {ver}").trim().to_string()
    } else {
        "Linux".to_string()
    };
    OsInfo {
        family: family.to_string(),
        pretty,
    }
}

/// Resolve the region preference to "cn" | "global". For "auto", probe whether
/// Docker's global infra is quickly reachable; if not, assume a CN network.
pub(crate) async fn resolve_region(pref: &str) -> &'static str {
    match pref {
        "cn" => "cn",
        "global" => "global",
        _ => {
            if tcp_reachable("download.docker.com:443", 2500).await {
                "global"
            } else {
                "cn"
            }
        }
    }
}

/// Best-effort: can we open a TCP connection to `addr` within `ms` ms?
pub(crate) async fn tcp_reachable(addr: &str, ms: u64) -> bool {
    let addrs = match tokio::net::lookup_host(addr).await {
        Ok(a) => a,
        Err(_) => return false,
    };
    for a in addrs {
        let ok = tokio::time::timeout(
            std::time::Duration::from_millis(ms),
            tokio::net::TcpStream::connect(a),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

/// Build the primary install script for a distro family + channel + region.
pub(crate) fn build_install_script(family: &str, channel: &str, region: &str) -> String {
    // The `ce` channel and unknown distros use Docker's convenience script,
    // which sets up the official repo for every supported distro.
    if channel == "ce" || family == "unknown" {
        return get_docker_script(region);
    }
    match family {
        "debian" => "set -e\n\
             export DEBIAN_FRONTEND=noninteractive\n\
             apt-get update\n\
             apt-get install -y docker.io\n\
             apt-get install -y docker-compose-v2 >/dev/null 2>&1 || true"
            .to_string(),
        // Fedora / Amazon Linux ship a `docker`/`moby-engine` package; RHEL/
        // Rocky/Alma don't (they get caught by the get.docker.com fallback).
        "rhel" => "set -e\n\
             (dnf -y install docker || dnf -y install moby-engine || yum -y install docker)"
            .to_string(),
        "suse" => "set -e\nzypper --non-interactive install docker".to_string(),
        "arch" => "set -e\npacman -Sy --noconfirm docker".to_string(),
        "alpine" => "set -e\n\
             apk add --no-cache docker docker-cli-compose\n\
             rc-update add docker boot || true"
            .to_string(),
        _ => get_docker_script(region),
    }
}

/// Docker's official convenience script, mirrored to Aliyun for CN networks.
pub(crate) fn get_docker_script(region: &str) -> String {
    let mirror = if region == "cn" {
        " --mirror Aliyun"
    } else {
        ""
    };
    format!(
        "set -e\n\
         if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com -o /tmp/dn7-get-docker.sh;\n\
         elif command -v wget >/dev/null 2>&1; then wget -qO /tmp/dn7-get-docker.sh https://get.docker.com;\n\
         else echo 'no curl/wget' >&2; exit 1; fi\n\
         sh /tmp/dn7-get-docker.sh{mirror}\n\
         rm -f /tmp/dn7-get-docker.sh"
    )
}

/// Ensure the docker service is enabled + started across init systems.
pub(crate) const ENABLE_START_SCRIPT: &str = "systemctl enable --now docker 2>/dev/null \
     || service docker start 2>/dev/null \
     || rc-service docker start 2>/dev/null || true";

/// Write CN registry-mirror accelerators into daemon.json and (re)start Docker.
/// NOTE: public CN accelerators change/shut down periodically — review these.
pub(crate) const REGISTRY_MIRROR_SCRIPT: &str = r#"set -e
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run",
    "https://dockerproxy.net"
  ]
}
JSON
systemctl daemon-reload 2>/dev/null || true
systemctl enable docker 2>/dev/null || true
systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || rc-service docker restart 2>/dev/null || true"#;

/// Run a shell script, pushing combined output lines into the op registry.
pub(crate) async fn stream_shell_to_op(op_id: &str, script: &str) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use tokio::process::Command;

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行安装脚本：{e}"))?;

    // Drain stderr concurrently to avoid a stdout/stderr pipe deadlock.
    let stderr = child.stderr.take();
    let err_task = tokio::spawn(async move {
        let mut buf = String::new();
        if let Some(mut e) = stderr {
            let _ = e.read_to_string(&mut buf).await;
        }
        buf
    });
    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|e| anyhow!("安装脚本失败：{e}"))?;
    let err = err_task.await.unwrap_or_default();
    for line in err
        .lines()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        op_push(op_id, line.trim());
    }
    if !status.success() {
        return Err(anyhow!("ERR_CODE:docker.install_script_nonzero"));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn is_root() -> bool {
    // SAFETY: getuid is always safe.
    unsafe { libc_getuid() == 0 }
}

#[cfg(not(unix))]
pub(crate) fn is_root() -> bool {
    false
}

#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}
