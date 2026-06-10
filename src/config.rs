use std::env;
use std::path::PathBuf;

/// Runtime configuration shared by both roles (supervisor + panel).
///
/// DN7 Panel is a standalone on-box management console: there is no backend
/// connection. The only remote interaction is the (currently untriggered)
/// self-update download, which uses `update_url`.
#[derive(Clone, Debug)]
pub struct PanelConfig {
    /// Transient process-state directory (`<base>/run`): pid/heartbeat/lock.
    pub runtime_dir: PathBuf,
    /// Persisted-data directory (`<base>/data`): version, `.panel_key`, web.json.
    pub data_dir: PathBuf,
    /// Log directory (`<base>/log`): the daemon log.
    pub log_dir: PathBuf,
    /// Seconds without a heartbeat before a peer role is considered dead.
    pub heartbeat_timeout_secs: u64,
    /// Supervisor: how often to check the panel child (seconds).
    pub supervise_interval_secs: u64,
    /// Supervisor: minimum delay between panel restarts (seconds).
    pub restart_backoff_secs: u64,
    /// Local web management: whether to serve the on-box web console.
    pub web_enabled: bool,
    /// Local web management: TCP port to bind (default 1080). The bind address
    /// is 0.0.0.0 so it's reachable off-box (per product decision).
    pub web_port: u16,
    /// GitHub `owner/repo` that publishes the release binaries. Used by the
    /// self-update GitHub source (release assets are addressed deterministically
    /// — no api.github.com call, so no rate limit).
    pub github_repo: String,
    /// Base URL of the dn7.cn site that mirrors the release binaries + manifest.
    /// Used by the self-update DN7 source.
    pub dn7_base: String,
}

impl PanelConfig {
    pub fn from_env() -> Self {
        // Base dir (normally /var/ops). Everything else hangs off it, grouped
        // into data/run/log subdirs. DN7_RUNTIME_DIR overrides the base for
        // special deployments / tests.
        let base_dir = env::var("DN7_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| crate::paths::default_base_dir());
        let data_dir = base_dir.join(crate::paths::DATA_SUBDIR);
        let runtime_dir = base_dir.join(crate::paths::RUN_SUBDIR);
        let log_dir = base_dir.join(crate::paths::LOG_SUBDIR);
        let heartbeat_timeout_secs = env::var("DN7_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        let supervise_interval_secs = env::var("DN7_SUPERVISE_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let restart_backoff_secs = env::var("DN7_RESTART_BACKOFF_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);
        // Local web console. Default ON, port 1080. Env vars set the initial
        // defaults; the web module persists user changes in `<data>/web.json`
        // which take precedence at runtime.
        let web_enabled = env::var("DN7_WEB_ENABLED")
            .ok()
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let web_port = env::var("DN7_WEB_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1080);
        let github_repo = env::var("DN7_GITHUB_REPO")
            .unwrap_or_else(|_| "Digital-Network-7/DN7-Panel".to_string());
        let dn7_base = env::var("DN7_SITE_URL").unwrap_or_else(|_| "https://dn7.cn".to_string());

        PanelConfig {
            runtime_dir,
            data_dir,
            log_dir,
            heartbeat_timeout_secs,
            supervise_interval_secs,
            restart_backoff_secs,
            web_enabled,
            web_port,
            github_repo: github_repo.trim().trim_end_matches('/').to_string(),
            dn7_base: dn7_base.trim().trim_end_matches('/').to_string(),
        }
    }
}
