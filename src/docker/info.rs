//! Docker daemon helpers: error formatting + info/host capacity (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// docker daemon helpers (bollard)
// ---------------------------------------------------------------------------

/// Turn a bollard error into a bounded, user-facing message.
pub(crate) fn friendly_docker_err(e: &bollard::errors::Error) -> String {
    // bollard surfaces the daemon's JSON message for API errors; trim it.
    trim_msg(&e.to_string()).unwrap_or_else(|| "Docker 操作失败".into())
}

/// Keep an error message bounded and non-empty.
pub(crate) fn trim_msg(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let s: String = s.chars().take(500).collect();
    Some(s)
}

/// Detect docker presence + versions via the daemon API. Never errors: an
/// unreachable daemon is reported as `installed:false` so the UI can offer to
/// install it.
pub(crate) async fn docker_info() -> Result<Value> {
    let dkr = match dkr() {
        Ok(d) => d,
        Err(_) => {
            return Ok(json!({
                "installed": false,
                "daemon_running": false,
                "docker_present": false,
            }));
        }
    };

    let version = match dkr.version().await {
        Ok(v) => v,
        Err(_) => {
            // Socket exists but daemon not answering (or no permission).
            return Ok(json!({
                "installed": false,
                "daemon_running": false,
                "docker_present": false,
            }));
        }
    };

    let server_version = version.version.clone().unwrap_or_default();
    // The API version field is the closest "client" analogue without a CLI.
    let client_version = version.api_version.clone().unwrap_or_default();

    // Compose plugin version isn't exposed over the engine API; report empty.
    let compose_version = String::new();

    Ok(json!({
        "installed": !server_version.is_empty(),
        "daemon_running": !server_version.is_empty(),
        "docker_present": true,
        "server_version": server_version,
        "client_version": client_version,
        "compose_version": compose_version,
        "cgroup_v2": cgroup_v2(),
        // Host capacity, so the create form can cap CPU/memory limits.
        "host_cpus": host_cpus(),
        "host_mem_bytes": host_mem_bytes(),
    }))
}

/// Whether the host is on cgroup v2 (unified hierarchy). Resource limits in the
/// UI are only offered when this is true, per the product spec.
pub(crate) fn cgroup_v2() -> bool {
    // cgroup v2 mounts a single unified hierarchy with this controllers file.
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Logical CPU count of the host (for capping the `--cpus` limit). Falls back to
/// 0 when it can't be determined (the UI then doesn't cap).
pub(crate) fn host_cpus() -> u64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(0)
}

/// Total physical memory of the host in bytes (for capping `--memory`). Parsed
/// from /proc/meminfo (`MemTotal: <kB> kB`); 0 when unavailable.
pub(crate) fn host_mem_bytes() -> u64 {
    let text = match std::fs::read_to_string("/proc/meminfo") {
        Ok(t) => t,
        Err(_) => return 0,
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Value is in kB.
            if let Some(kb) = rest.split_whitespace().next() {
                if let Ok(kb) = kb.parse::<u64>() {
                    return kb * 1024;
                }
            }
        }
    }
    0
}
