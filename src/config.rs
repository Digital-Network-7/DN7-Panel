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
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let interval_secs = env::var("TEAOPS_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
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
}
