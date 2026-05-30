use std::env;
use std::path::PathBuf;

/// Agent runtime configuration.
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
    /// Path to the teaops-agentd supervisor binary (for mutual guarding).
    pub agentd_bin: PathBuf,
    /// Seconds without a heartbeat before agentd is considered dead.
    pub heartbeat_timeout_secs: u64,
    /// Whether the agent should (re)launch agentd if it dies.
    pub guard_agentd: bool,
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
        let agentd_bin = env::var("TEAOPS_AGENTD_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./teaops-agentd"));
        let heartbeat_timeout_secs = env::var("TEAOPS_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        // Guarding agentd is opt-in: only meaningful when run under agentd.
        let guard_agentd = env::var("TEAOPS_GUARD_AGENTD")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        AgentConfig {
            backend_url: backend_url.trim_end_matches('/').to_string(),
            interval_secs,
            token_file,
            agent_token,
            runtime_dir,
            agentd_bin,
            heartbeat_timeout_secs,
            guard_agentd,
        }
    }

    /// WebSocket URL for the agent metrics stream, derived from `backend_url`
    /// (http -> ws, https -> wss).
    pub fn agent_ws_url(&self) -> String {
        let ws_base = if let Some(rest) = self.backend_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.backend_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.backend_url.clone()
        };
        format!("{ws_base}/agent/ws")
    }
}
