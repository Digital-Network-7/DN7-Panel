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
    /// Shared runtime directory for pid/heartbeat/lock files.
    pub runtime_dir: PathBuf,
    /// Seconds without a heartbeat before a peer role is considered dead.
    pub heartbeat_timeout_secs: u64,
    /// Supervisor: how often to check the agent child (seconds).
    pub supervise_interval_secs: u64,
    /// Supervisor: minimum delay between agent restarts (seconds).
    pub restart_backoff_secs: u64,
    /// Download/CDN service base URL (fallback binary source).
    pub download_url: String,
    /// Upstream repo (`owner/name`) for GitHub-first downloads/self-update.
    pub repo: String,
}

impl AgentConfig {
    pub fn from_env() -> Self {
        let backend_url = env::var("TEAOPS_BACKEND_URL")
            .unwrap_or_else(|_| "https://wxapi.dn7.cn".to_string());
        let interval_secs = env::var("TEAOPS_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let token_file = env::var("TEAOPS_TOKEN_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("teaops-agent.token"));
        let agent_token = env::var("TEAOPS_AGENT_TOKEN").ok().filter(|s| !s.is_empty());
        let runtime_dir = env::var("TEAOPS_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
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
        let download_url = env::var("TEAOPS_DOWNLOAD_URL")
            .unwrap_or_else(|_| "https://download.agent.dn7.cn".to_string())
            .trim_end_matches('/')
            .to_string();
        let repo =
            env::var("TEAOPS_REPO").unwrap_or_else(|_| "simonsmithmd/Teaops-agent".to_string());

        AgentConfig {
            backend_url: backend_url.trim_end_matches('/').to_string(),
            interval_secs,
            token_file,
            agent_token,
            runtime_dir,
            heartbeat_timeout_secs,
            supervise_interval_secs,
            restart_backoff_secs,
            download_url,
            repo,
        }
    }

    /// WebSocket URL for the agent metrics stream, derived from `backend_url`
    /// (http -> ws, https -> wss). The agent_token is passed as a query param
    /// since the backend authenticates the connection at upgrade time.
    pub fn agent_ws_url(&self, agent_token: &str) -> String {
        let ws_base = if let Some(rest) = self.backend_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.backend_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.backend_url.clone()
        };
        format!("{ws_base}/agent/ws?token={}", urlencode(agent_token))
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
