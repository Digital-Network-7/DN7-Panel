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

        AgentConfig {
            backend_url: backend_url.trim_end_matches('/').to_string(),
            interval_secs,
            token_file,
            agent_token,
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
