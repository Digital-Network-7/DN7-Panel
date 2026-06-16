//! Command helpers + install/occupancy detection (split from nginx.rs).
use super::*;

// Command helpers.
// ---------------------------------------------------------------------------

/// Run a command, returning (success, stdout, stderr).
pub(crate) async fn run(cmd: &str, args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

pub(crate) fn trim_msg(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(500).collect())
}

/// Run a shell script on the host (used for the package-manager install steps
/// and port-listener detection).
pub(crate) async fn sh(script: &str) -> Result<(bool, String, String)> {
    run("sh", &["-c", script]).await
}

#[cfg(unix)]
pub(crate) fn is_root() -> bool {
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

// ---------------------------------------------------------------------------
// Detection: what's installed / occupying 80+443, and our current managed mode.
// ---------------------------------------------------------------------------

/// Detect the host nginx binary + whether it (or anything) holds 80/443, plus
/// whether we've completed setup. Never errors — a clean host reports
/// everything false so the UI can drive the setup flow.
pub(crate) async fn nginx_info() -> Result<Value> {
    // Host nginx binary + version.
    let (ok, _o, e) = run("nginx", &["-v"])
        .await
        .unwrap_or((false, String::new(), String::new()));
    // `nginx -v` prints to stderr like "nginx version: nginx/1.24.0".
    let host_nginx_present = ok;
    let host_nginx_version = if ok {
        e.split('/')
            .nth(1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Who's listening on 80 / 443?
    let p80 = port_listener(80).await;
    let p443 = port_listener(443).await;

    // host nginx "owns" 80/443 if the listener process looks like nginx.
    let host_owns_ports = p80.contains("nginx") || p443.contains("nginx");

    Ok(json!({
        "managed": is_setup(),                  // setup completed?
        "host_nginx_present": host_nginx_present,
        "host_nginx_version": host_nginx_version,
        "host_owns_ports": host_owns_ports,
        "port80": p80,                          // listener description ("" if free)
        "port443": p443,
        "is_root": is_root(),
    }))
}

/// Best-effort: a short description of what's listening on `port` (process name)
/// or "" if it appears free. Tries `ss`, then `lsof`, then a pure-Rust
/// `/proc/net` fallback so it still works when neither tool is installed.
pub(crate) async fn port_listener(port: u16) -> String {
    if let Ok((true, out, _)) = run("ss", &["-ltnp"]).await {
        for line in out.lines() {
            if line.contains(&format!(":{port}")) && line.to_lowercase().contains("listen") {
                // Extract a process name from users:(("nginx",pid=..)).
                if let Some(idx) = line.find("users:((\"") {
                    let rest = &line[idx + 9..];
                    if let Some(end) = rest.find('"') {
                        return rest[..end].to_string();
                    }
                }
                return "占用".to_string();
            }
        }
        return String::new();
    }
    // Fallback: lsof.
    if let Ok((true, out, _)) =
        run("lsof", &["-i", &format!(":{port}"), "-sTCP:LISTEN", "-Pn"]).await
    {
        if let Some(line) = out.lines().nth(1) {
            return line.split_whitespace().next().unwrap_or("占用").to_string();
        }
    }
    // Last resort: parse /proc directly (no external tools needed).
    proc_port_listener(port)
}

/// Pure-Rust port-listener probe: scan `/proc/net/tcp` + `tcp6` for a socket in
/// the LISTEN state on `port`, then resolve its owning process name by matching
/// the socket inode against `/proc/<pid>/fd`. Returns the process name, a
/// generic "占用" if the port is held but the owner can't be resolved, or "" if
/// the port appears free.
pub(crate) fn proc_port_listener(port: u16) -> String {
    let inode = match listening_inode("/proc/net/tcp", port)
        .or_else(|| listening_inode("/proc/net/tcp6", port))
    {
        Some(i) => i,
        None => return String::new(),
    };
    proc_name_for_inode(inode).unwrap_or_else(|| "占用".to_string())
}

/// Find the socket inode listening on `port` in a `/proc/net/tcp{,6}` file.
/// Columns: `sl local_address rem_address st ... inode`. `local_address` is
/// `HEXIP:HEXPORT`; LISTEN state is `0A`.
pub(crate) fn listening_inode(path: &str, port: u16) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if cols[3] != "0A" {
            continue; // not LISTEN
        }
        let local_port = cols[1]
            .rsplit(':')
            .next()
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        if local_port != Some(port) {
            continue;
        }
        if let Ok(inode) = cols[9].parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

/// Resolve the process name owning a socket `inode` by scanning `/proc/<pid>/fd`
/// for a `socket:[<inode>]` symlink, then reading `/proc/<pid>/comm`.
pub(crate) fn proc_name_for_inode(inode: u64) -> Option<String> {
    let want = format!("socket:[{inode}]");
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = match name.to_str().and_then(|s| s.parse::<u32>().ok()) {
            Some(p) => p,
            None => continue, // not a pid dir
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => continue, // no permission / process gone
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == want {
                    return std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
            }
        }
    }
    None
}

/// List running containers (name + published port hint) so the proxy form can
/// offer "forward to container:port" targets. Uses the daemon API (no `docker`
/// CLI); returns empty if Docker isn't present.
pub(crate) async fn list_running_containers() -> Result<Value> {
    let dkr = crate::infra::docker::dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: false,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(trim_msg(&e.to_string()).unwrap_or_else(|| "无法获取容器".into())))?;
    let mut items = Vec::new();
    for c in containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let ports = c
            .ports
            .as_ref()
            .map(|ps| {
                let mut v: Vec<String> = ps
                    .iter()
                    .map(|p| {
                        let proto = p
                            .typ
                            .map(|t| format!("{t:?}").to_lowercase())
                            .unwrap_or_else(|| "tcp".into());
                        match p.public_port {
                            Some(pp) => format!("{pp}->{}/{proto}", p.private_port),
                            None => format!("{}/{proto}", p.private_port),
                        }
                    })
                    .collect();
                v.sort();
                v.dedup();
                v.join(", ")
            })
            .unwrap_or_default();
        items.push(json!({
            "name": name,
            "ports": ports,
            "image": c.image.clone().unwrap_or_default(),
        }));
    }
    Ok(json!({ "containers": items }))
}

/// List immediate subdirectories of an absolute host path (for the static-site
/// "use existing directory" picker). Defaults to "/". Returns dirs only.
pub(crate) async fn list_dirs(path_arg: Option<&str>) -> Result<Value> {
    let raw = path_arg.map(str::trim).unwrap_or("/");
    let base = if raw.is_empty() { "/" } else { raw };
    let path = std::path::Path::new(base);
    if !path.is_absolute() {
        return Err(anyhow!("ERR_CODE:nginx.local_root_abs"));
    }
    let canon =
        std::fs::canonicalize(path).map_err(|_| anyhow!("ERR_CODE:nginx.local_root_missing"))?;
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&canon) {
        for ent in rd.flatten() {
            if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                if let Some(name) = ent.file_name().to_str() {
                    if !name.starts_with('.') {
                        dirs.push(name.to_string());
                    }
                }
            }
        }
    }
    dirs.sort();
    let cur = canon.to_string_lossy().to_string();
    let parent = canon.parent().map(|p| p.to_string_lossy().to_string());
    Ok(json!({ "path": cur, "parent": parent, "dirs": dirs }))
}
