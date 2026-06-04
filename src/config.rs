use std::env;
use std::path::PathBuf;

/// Runtime configuration shared by both roles (supervisor + agent).
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Backend base URL, e.g. https://api.teaops.example.com
    pub backend_url: String,
    /// How often to collect & report metrics, in seconds.
    pub interval_secs: u64,
    /// Path where the agent persists its token after pairing.
    pub token_file: PathBuf,
    /// Optional pre-provisioned agent token (skips pairing flow entirely).
    pub agent_token: Option<String>,
    /// Transient process-state directory (`<base>/run`): pid/heartbeat/lock.
    pub runtime_dir: PathBuf,
    /// Persisted-data directory (`<base>/data`): token, version, `.agent_key`.
    pub data_dir: PathBuf,
    /// Log directory (`<base>/log`): the daemon log.
    pub log_dir: PathBuf,
    /// Seconds without a heartbeat before a peer role is considered dead.
    pub heartbeat_timeout_secs: u64,
    /// Supervisor: how often to check the agent child (seconds).
    pub supervise_interval_secs: u64,
    /// Supervisor: minimum delay between agent restarts (seconds).
    pub restart_backoff_secs: u64,
    /// Local web management: whether to serve the on-box web console.
    pub web_enabled: bool,
    /// Local web management: TCP port to bind (default 1080). The bind address
    /// is 0.0.0.0 so it's reachable off-box (per product decision).
    pub web_port: u16,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        let backend_url = env::var("TEAOPS_BACKEND_URL")
            .unwrap_or_else(|_| "https://api.teaops.dn7.cn".to_string());
        let interval_secs = env::var("TEAOPS_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        // Base dir (normally /var/ops). Everything else hangs off it, grouped
        // into data/run/log subdirs. TEAOPS_RUNTIME_DIR overrides the base for
        // backward compatibility with existing deployments / tests.
        let base_dir = env::var("TEAOPS_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::paths::default_base_dir());
        let data_dir = base_dir.join(crate::paths::DATA_SUBDIR);
        let runtime_dir = base_dir.join(crate::paths::RUN_SUBDIR);
        let log_dir = base_dir.join(crate::paths::LOG_SUBDIR);
        // The token lives in the persisted-data subdir. An explicit
        // TEAOPS_TOKEN_FILE still wins for special deployments.
        let token_file = env::var("TEAOPS_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("teaops-agent.token"));
        let agent_token = env::var("TEAOPS_AGENT_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        let heartbeat_timeout_secs = env::var("TEAOPS_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        let supervise_interval_secs = env::var("TEAOPS_SUPERVISE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let restart_backoff_secs = env::var("TEAOPS_RESTART_BACKOFF_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        // Local web console. Default ON, port 1080. Env vars set the initial
        // defaults; the web module persists user changes in `<data>/web.json`
        // which take precedence at runtime.
        let web_enabled = env::var("TEAOPS_WEB_ENABLED")
            .ok()
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let web_port = env::var("TEAOPS_WEB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1080);

        AgentConfig {
            backend_url: backend_url.trim_end_matches('/').to_string(),
            interval_secs,
            token_file,
            agent_token,
            runtime_dir,
            data_dir,
            log_dir,
            heartbeat_timeout_secs,
            supervise_interval_secs,
            restart_backoff_secs,
            web_enabled,
            web_port,
        }
    }

    /// WebSocket URL for the agent metrics stream, derived from `backend_url`
    /// (http -> ws, https -> wss). The agent_token is sent in the
    /// `Authorization` header (see `ws::MetricsStream::connect`), not the URL,
    /// so it never lands in proxy access logs.
    pub fn agent_ws_url(&self) -> String {
        format!("{}/agent/ws", self.ws_base())
    }

    /// WebSocket URL the agent dials to relay a PTY terminal back to the backend
    /// for a given session (in response to an `open-terminal` command). The
    /// token travels in the `Authorization` header; only the (non-secret,
    /// single-use, server-bound) session id is in the URL.
    pub fn agent_terminal_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/terminal?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// WebSocket URL the agent dials to relay a file-transfer channel back to
    /// the backend for a given session (in response to an `open-file` command).
    pub fn agent_file_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/file?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// WebSocket URL the agent dials to relay a Docker management channel back
    /// to the backend for a given session (in response to an `open-docker`
    /// command).
    pub fn agent_docker_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/docker?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// WebSocket URL the agent dials to relay an Nginx management channel back
    /// to the backend for a given session (in response to an `open-nginx`
    /// command).
    pub fn agent_nginx_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/nginx?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// WebSocket URL the agent dials to relay a MySQL management channel back
    /// to the backend for a given session (in response to an `open-mysql`
    /// command).
    pub fn agent_mysql_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/mysql?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// WebSocket URL the agent dials to relay a process-list channel back to the
    /// backend for a given session (in response to an `open-procs` command).
    pub fn agent_procs_ws_url(&self, session: &str) -> String {
        format!(
            "{}/agent/procs?session={}",
            self.ws_base(),
            urlencode(session)
        )
    }

    /// Derive the ws/wss base from `backend_url`.
    fn ws_base(&self) -> String {
        if let Some(rest) = self.backend_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.backend_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.backend_url.clone()
        }
    }
}

/// Minimal percent-encoding for a token in a query string (alnum, `-_.~` pass
/// through; everything else is %XX-encoded).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
