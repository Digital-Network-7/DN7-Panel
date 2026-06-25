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
// Detection: our current managed mode + what's occupying 80/443.
// ---------------------------------------------------------------------------

/// Report the built-in web server's status: whether setup has completed, the
/// engine identity, and what (if anything) holds 80/443. Never errors — a clean
/// host reports `managed: false` so the UI can drive the setup flow.
///
/// The web server is now the in-process pure-Rust edge proxy, not an external
/// nginx binary. The JSON keys are unchanged so the UI's setup hint keeps
/// working; only how they're computed changes: the engine is always present
/// (it's compiled in) and its "version" is the panel build version.
pub(crate) async fn nginx_info() -> Result<Value> {
    // The web engine is built into the panel, so it's always present; its
    // version is the panel build version.
    let host_nginx_present = true;
    let host_nginx_version = env!("CARGO_PKG_VERSION").to_string();

    // Who's listening on 80 / 443? (Surfaced so an operator can see a foreign
    // process holding a port that would prevent the edge from binding.)
    let p80 = port_listener(80).await;
    let p443 = port_listener(443).await;

    // Did the edge fail to bind because a foreign process holds :80/:443? If so,
    // the UI offers a force-start (which kills the occupant). Describe who's on
    // each conflicting port so the operator knows what would be killed.
    let conflict_ports = crate::edge::port_conflict().unwrap_or_default();
    let mut conflict_procs = serde_json::Map::new();
    for &p in &conflict_ports {
        conflict_procs.insert(p.to_string(), json!(port_listener(p).await));
    }

    Ok(json!({
        "managed": is_setup(),                  // setup completed?
        "built_in": true,                       // the engine is the in-process edge
        "host_nginx_present": host_nginx_present,
        "host_nginx_version": host_nginx_version,
        "host_owns_ports": is_setup() && conflict_ports.is_empty(),
        "port80": p80,                          // listener description ("" if free)
        "port443": p443,
        "port_conflict": !conflict_ports.is_empty(),
        "conflict_ports": conflict_ports,
        "conflict_procs": Value::Object(conflict_procs),
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

/// Find the PIDs holding a LISTEN socket on `port`. Tries `ss` (parsing
/// `pid=`), then a pure-Rust `/proc` scan so it works without `ss` installed.
pub(crate) async fn pids_on_port(port: u16) -> Vec<u32> {
    if let Ok((true, out, _)) = run("ss", &["-ltnp"]).await {
        let pids = ss_pids(&out, port);
        if !pids.is_empty() {
            return pids;
        }
    }
    proc_pids_on_port(port)
}

/// Parse `ss -ltnp` output for the PIDs listening on `port`. The local-address
/// column ends with `:<port>` (`0.0.0.0:80`, `[::]:80`), which anchors the match
/// so `:80` can't be confused with `:8080`.
pub(crate) fn ss_pids(out: &str, port: u16) -> Vec<u32> {
    let suffix = format!(":{port}");
    let mut pids = Vec::new();
    for line in out.lines() {
        let on_port = line
            .split_whitespace()
            .any(|c| c.contains(':') && c.ends_with(&suffix));
        if !on_port {
            continue;
        }
        let mut rest = line;
        while let Some(i) = rest.find("pid=") {
            rest = &rest[i + 4..];
            let n: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(p) = n.parse::<u32>() {
                pids.push(p);
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// Pure-Rust fallback: resolve the PIDs holding `port` via `/proc/net/tcp{,6}`
/// (socket inode) → `/proc/<pid>/fd`.
pub(crate) fn proc_pids_on_port(port: u16) -> Vec<u32> {
    let mut pids = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Some(inode) = listening_inode(path, port) {
            pids.extend(proc_pids_for_inode(inode));
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// All PIDs whose `/proc/<pid>/fd` references socket `inode` (forked workers
/// share the listen fd, so there can be several).
fn proc_pids_for_inode(inode: u64) -> Vec<u32> {
    let want = format!("socket:[{inode}]");
    let mut pids = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return pids,
    };
    for entry in entries.flatten() {
        let pid = match entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fds = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == want {
                    pids.push(pid);
                    break;
                }
            }
        }
    }
    pids
}

/// Force-start: kill every foreign process holding `ports` so the edge can take
/// over :80/:443. SIGTERM first, then SIGKILL any straggler after a grace
/// window. Never signals our own process (or pid ≤ 1). Because the edge always
/// binds with `SO_REUSEPORT`, an `AddrInUse` occupant is by definition NOT our
/// own edge, so this can't kill a sibling. Returns the PIDs we signalled.
pub(crate) async fn kill_port_holders(ports: &[u16]) -> Vec<u32> {
    use std::collections::BTreeSet;
    let me = std::process::id();
    let gather = |set: &mut BTreeSet<u32>, found: Vec<u32>| {
        for pid in found {
            if pid != me && pid > 1 {
                set.insert(pid);
            }
        }
    };

    let mut targets = BTreeSet::new();
    for &port in ports {
        gather(&mut targets, pids_on_port(port).await);
    }
    if targets.is_empty() {
        return Vec::new();
    }
    const SIGTERM: i32 = 15;
    const SIGKILL: i32 = 9;
    for &pid in &targets {
        signal(pid, SIGTERM);
    }
    // Grace window, then force-kill anything still holding a conflicting port.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let mut still = BTreeSet::new();
    for &port in ports {
        gather(&mut still, pids_on_port(port).await);
    }
    for &pid in &still {
        signal(pid, SIGKILL);
    }
    targets.into_iter().collect()
}

/// Deliver signal `sig` to `pid` (best-effort; errors are ignored).
#[cfg(unix)]
fn signal(pid: u32, sig: i32) {
    // SAFETY: kill(2) only delivers a signal and returns a status we don't need.
    unsafe {
        libc::kill(pid as libc::pid_t, sig as libc::c_int);
    }
}
#[cfg(not(unix))]
fn signal(_pid: u32, _sig: i32) {}

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
        return Err(nginx_err(NginxError::LocalRootAbs));
    }
    let canon = std::fs::canonicalize(path).map_err(|_| nginx_err(NginxError::LocalRootMissing))?;
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
