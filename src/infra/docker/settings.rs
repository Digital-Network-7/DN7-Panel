//! Docker daemon settings + registry/mirror config (split from docker.rs).
use super::*;

pub(crate) fn default_mirrors() -> Vec<String> {
    [
        "docker.m.daocloud.io",
        "docker.1panel.live",
        "hub.rat.dev",
        "mirror.ccs.tencentyun.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
pub(crate) fn d_true() -> bool {
    true
}
pub(crate) fn d_cgroup() -> String {
    "systemd".to_string()
}
pub(crate) fn d_logsize() -> String {
    "10m".to_string()
}
pub(crate) fn d_logfile() -> u32 {
    3
}
pub(crate) fn d_socket() -> String {
    DEFAULT_SOCKET.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DockerSettings {
    #[serde(default = "default_mirrors")]
    pub(crate) mirrors: Vec<String>,
    #[serde(default)]
    pub(crate) registries: Vec<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default = "d_true")]
    iptables: bool,
    #[serde(default = "d_true")]
    live_restore: bool,
    #[serde(default = "d_cgroup")]
    cgroup_driver: String,
    #[serde(default = "d_true")]
    log_rotate: bool,
    #[serde(default = "d_logsize")]
    log_max_size: String,
    #[serde(default = "d_logfile")]
    log_max_file: u32,
    #[serde(default = "d_socket")]
    socket_path: String,
}
impl Default for DockerSettings {
    fn default() -> Self {
        DockerSettings {
            mirrors: default_mirrors(),
            registries: Vec::new(),
            ipv6: false,
            iptables: true,
            live_restore: true,
            cgroup_driver: d_cgroup(),
            log_rotate: true,
            log_max_size: d_logsize(),
            log_max_file: d_logfile(),
            socket_path: d_socket(),
        }
    }
}

pub(crate) fn dk_settings_path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("docker-settings.json")
}
pub(crate) fn load_dk_settings() -> DockerSettings {
    std::fs::read_to_string(dk_settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<DockerSettings>(&s).ok())
        .unwrap_or_default()
}
pub(crate) fn save_dk_settings(s: &DockerSettings) -> Result<()> {
    let p = dk_settings_path();
    let data = serde_json::to_string_pretty(s)?;
    crate::platform::paths::write_public(&p, data.as_bytes())?;
    Ok(())
}

pub(crate) fn dk_settings_json() -> Value {
    let s = load_dk_settings();
    json!({
        "mirrors": s.mirrors,
        "registries": s.registries,
        "ipv6": s.ipv6,
        "iptables": s.iptables,
        "live_restore": s.live_restore,
        "cgroup_driver": s.cgroup_driver,
        "log_rotate": s.log_rotate,
        "log_max_size": s.log_max_size,
        "log_max_file": s.log_max_file,
        "socket_path": s.socket_path,
        "configured": dk_settings_path().exists(),
    })
}

/// A host token (mirror/registry): letters/digits/.-: and an optional /path,
/// no scheme or shell metacharacters.
pub(crate) fn valid_host_line(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 200
        && !s.contains("//")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '/' | '_'))
}

/// Validate a docker size like "10m" / "512k" (used for log max-size).
pub(crate) fn valid_log_size(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 10
        && s.chars().take(s.len() - 1).all(|c| c.is_ascii_digit())
        && matches!(s.chars().last(), Some('k' | 'K' | 'm' | 'M' | 'g' | 'G'))
}

pub(crate) async fn set_dk_settings(req: &Req) -> Result<Value> {
    let v = req
        .settings
        .clone()
        .ok_or_else(|| docker_err(DockerError::MissingSettings))?;
    let incoming: DockerSettings =
        serde_json::from_value(v).map_err(|_| docker_err(DockerError::BadSettings))?;

    // Mirror/registry lists are managed separately (Images → Advanced) and must
    // not be touched by the daemon-settings save — preserve them from the store.
    let mut incoming = incoming;
    let stored = load_dk_settings();
    incoming.mirrors = stored.mirrors;
    incoming.registries = stored.registries;

    // Validate.
    for m in incoming.mirrors.iter().chain(incoming.registries.iter()) {
        if !valid_host_line(m) {
            return Err(docker_err(DockerError::BadHostLine));
        }
    }
    if !matches!(incoming.cgroup_driver.as_str(), "systemd" | "cgroupfs") {
        return Err(docker_err(DockerError::BadCgroup));
    }
    if !valid_log_size(&incoming.log_max_size) {
        return Err(docker_err(DockerError::BadLogSize));
    }
    if incoming.log_max_file == 0 || incoming.log_max_file > 100 {
        return Err(docker_err(DockerError::BadLogFile));
    }
    let sock = incoming.socket_path.trim();
    if !sock.starts_with('/') || !sock.ends_with(".sock") || sock.len() > 200 {
        return Err(docker_err(DockerError::BadSocket));
    }

    // Persist the panel-side store first (mirrors/registries take effect for
    // the pull dialog immediately, independent of the daemon restart).
    save_dk_settings(&incoming)?;

    // Apply the daemon.json-backed knobs (may restart dockerd). Best-effort with
    // backup + rollback; surfaces a clear error if the daemon won't come back.
    apply_daemon_settings(&incoming).await?;
    Ok(json!({ "ok": true }))
}

/// Save only the panel-side mirror/registry lists (used by the pull dialog).
/// Does NOT touch daemon.json or restart Docker — these are panel-side only.
pub(crate) async fn set_registry_lists(req: &Req) -> Result<Value> {
    #[derive(Deserialize)]
    struct Lists {
        #[serde(default)]
        mirrors: Vec<String>,
        #[serde(default)]
        registries: Vec<String>,
    }
    let v = req
        .settings
        .clone()
        .ok_or_else(|| docker_err(DockerError::MissingSettings))?;
    let lists: Lists =
        serde_json::from_value(v).map_err(|_| docker_err(DockerError::BadSettings))?;
    for m in lists.mirrors.iter().chain(lists.registries.iter()) {
        if !valid_host_line(m) {
            return Err(docker_err(DockerError::BadHostLine));
        }
    }
    let mut cur = load_dk_settings();
    cur.mirrors = lists.mirrors;
    cur.registries = lists.registries;
    save_dk_settings(&cur)?;
    Ok(json!({ "ok": true }))
}

pub(crate) const DAEMON_JSON: &str = "/etc/docker/daemon.json";
pub(crate) const DROPIN_DIR: &str = "/etc/systemd/system/docker.service.d";
pub(crate) const DROPIN: &str = "/etc/systemd/system/docker.service.d/dn7-docker.conf";

/// Merge our knobs into daemon.json (preserving unrelated keys), back it up,
/// write, (re)configure the systemd socket override when needed, restart docker
/// and verify it comes back — rolling everything back on failure.
pub(crate) async fn apply_daemon_settings(s: &DockerSettings) -> Result<()> {
    // Read existing daemon.json (preserve unknown keys) and the current drop-in.
    let prev = std::fs::read_to_string(DAEMON_JSON).unwrap_or_default();
    let prev_dropin = std::fs::read_to_string(DROPIN).ok();
    // Custom socket: daemon.json `hosts` + a systemd drop-in that drops the
    // unit's `-H fd://` (otherwise dockerd refuses: "hosts conflict").
    let custom_sock = s.socket_path != DEFAULT_SOCKET && s.socket_path != "/run/docker.sock";

    let body = build_daemon_json(s, &prev, custom_sock)?;

    // Backup + write daemon.json.
    let backup = format!("{DAEMON_JSON}.dn7-bak");
    if !prev.is_empty() {
        let _ = std::fs::write(&backup, &prev);
    }
    if let Some(dir) = std::path::Path::new(DAEMON_JSON).parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(DAEMON_JSON, &body)?;

    // systemd drop-in for the socket override.
    let mut reloaded = false;
    if custom_sock {
        std::fs::create_dir_all(DROPIN_DIR)?;
        let dockerd = which_dockerd();
        let dropin = format!("[Service]\nExecStart=\nExecStart={dockerd}\n");
        std::fs::write(DROPIN, dropin)?;
        let _ = sh("systemctl daemon-reload").await;
        reloaded = true;
    } else if prev_dropin.is_some() {
        let _ = std::fs::remove_file(DROPIN);
        let _ = sh("systemctl daemon-reload").await;
        reloaded = true;
    }

    // Restart docker and verify it comes back.
    let _ = sh("systemctl restart docker").await;
    if daemon_back().await {
        return Ok(());
    }

    rollback_daemon(&prev, prev_dropin, reloaded).await;
    Err(docker_err(DockerError::DaemonRestartFailed))
}

/// Merge our managed keys into the existing daemon.json object (preserving any
/// unknown keys) and return the pretty-printed body to write.
fn build_daemon_json(s: &DockerSettings, prev: &str, custom_sock: bool) -> Result<String> {
    let mut obj: serde_json::Map<String, Value> = serde_json::from_str(prev)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .unwrap_or_default();

    obj.insert("ipv6".into(), json!(s.ipv6));
    if s.ipv6 {
        obj.entry("fixed-cidr-v6")
            .or_insert_with(|| json!("fd00:dn7::/48"));
    } else {
        obj.remove("fixed-cidr-v6");
    }
    obj.insert("iptables".into(), json!(s.iptables));
    obj.insert("live-restore".into(), json!(s.live_restore));
    obj.insert(
        "exec-opts".into(),
        json!([format!("native.cgroupdriver={}", s.cgroup_driver)]),
    );
    if s.log_rotate {
        obj.insert("log-driver".into(), json!("json-file"));
        obj.insert(
            "log-opts".into(),
            json!({ "max-size": s.log_max_size, "max-file": s.log_max_file.to_string() }),
        );
    } else {
        obj.remove("log-opts");
    }
    if custom_sock {
        obj.insert(
            "hosts".into(),
            json!([format!("unix://{}", s.socket_path), "fd://"]),
        );
    } else {
        obj.remove("hosts");
    }
    Ok(serde_json::to_string_pretty(&Value::Object(obj))?)
}

/// Restore the previous daemon.json + drop-in and restart docker, after a failed
/// settings apply.
async fn rollback_daemon(prev: &str, prev_dropin: Option<String>, reloaded: bool) {
    if prev.is_empty() {
        let _ = std::fs::remove_file(DAEMON_JSON);
    } else {
        let _ = std::fs::write(DAEMON_JSON, prev);
    }
    match prev_dropin {
        Some(d) => {
            let _ = std::fs::write(DROPIN, d);
        }
        None => {
            let _ = std::fs::remove_file(DROPIN);
        }
    }
    if reloaded {
        let _ = sh("systemctl daemon-reload").await;
    }
    let _ = sh("systemctl restart docker").await;
}

/// Locate the dockerd binary for the systemd ExecStart override.
pub(crate) fn which_dockerd() -> String {
    for p in [
        "/usr/bin/dockerd",
        "/usr/local/bin/dockerd",
        "/usr/sbin/dockerd",
    ] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    "/usr/bin/dockerd".to_string()
}

/// Poll the daemon for readiness after a restart (up to ~20s).
pub(crate) async fn daemon_back() -> bool {
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        if let Ok(d) = dkr() {
            if d.ping().await.is_ok() {
                return true;
            }
        }
    }
    false
}

/// Run a shell command, returning success only.
pub(crate) async fn sh(script: &str) -> Result<bool> {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .await?;
    Ok(out.status.success())
}
