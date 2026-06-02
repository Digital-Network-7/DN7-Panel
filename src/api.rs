use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::config::AgentConfig;
use crate::metrics::Metrics;

/// Backend's standard success envelope: { ok: bool, data: T }
#[derive(Debug, Deserialize)]
struct Envelope<T> {
    ok: bool,
    data: Option<T>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterData {
    /// 128-char server token (shown as a QR for direct add).
    pub agent_token: String,
    /// 8-digit quick-add code (valid 30 min); exchangeable for the token.
    pub pairing_code: String,
    pub register_secret: String,
    pub expires_at: String,
    /// Human-friendly expiry in China Standard Time (UTC+8). Older backends may
    /// omit it, so it defaults to empty and the agent falls back to expires_at.
    #[serde(default)]
    pub expires_at_display: String,
}

#[derive(Debug, Deserialize)]
pub struct PollData {
    pub claimed: bool,
    pub agent_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ShouldUpgradeData {
    pub auto_update: bool,
    /// Version the backend wants this agent on (empty if none published).
    /// Part of the wire contract; the agent gates on `upgrade_now` + its own
    /// version check, so this is informational for now.
    #[serde(default)]
    #[allow(dead_code)]
    pub target_version: String,
    /// True only when the backend's staggered rollout has cleared THIS server
    /// to upgrade now. New agents act on this; absent for older backends.
    #[serde(default)]
    pub upgrade_now: bool,
}

#[derive(Debug, Serialize)]
struct RegisterReq {
    hostname: String,
    ip: String,
    os_version: String,
}

#[derive(Debug, Serialize)]
struct PollReq {
    register_secret: String,
}

#[derive(Debug, Serialize)]
struct ShouldUpgradeReq {
    agent_token: String,
}

#[derive(Debug, Serialize)]
struct TrafficReportReq<'a> {
    agent_token: String,
    samples: &'a [crate::traffic::ProcTrafficDelta],
}

#[derive(Debug, Serialize)]
struct ReportReq {
    agent_token: String,
    cpu_usage: f64,
    memory_usage: f64,
    disk_usage: f64,
    net_rx: f64,
    net_tx: f64,
    uptime: i64,
    hostname: String,
    os_version: String,
    ip: String,
    agent_version: String,
    is_container: bool,
    cpu_cores: i64,
    mem_total: u64,
    mem_used: u64,
    disk_total: u64,
    disk_used: u64,
    disk_mounts: Vec<crate::metrics::DiskMount>,
    update_phase: String,
    update_progress: u64,
    update_done_bytes: u64,
    update_total_bytes: u64,
}

/// HTTP client wrapper around the TeaOps backend API.
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
}

impl ApiClient {
    pub fn new(cfg: &AgentConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .expect("failed to build http client");
        ApiClient {
            http,
            base: cfg.backend_url.clone(),
        }
    }

    async fn unwrap_envelope<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await?;
        let env: Envelope<T> = serde_json::from_str(&text)
            .map_err(|e| anyhow!("invalid response ({status}): {e}; body={text}"))?;
        if !env.ok {
            return Err(anyhow!(
                "backend error ({status}): {}",
                env.error.unwrap_or_else(|| "unknown".into())
            ));
        }
        env.data.ok_or_else(|| anyhow!("missing data in response"))
    }

    /// POST /agent/register
    pub async fn register(&self, m: &Metrics) -> Result<RegisterData> {
        let req = RegisterReq {
            hostname: m.hostname.clone(),
            ip: m.ip.clone(),
            os_version: m.os_version.clone(),
        };
        let resp = self
            .http
            .post(format!("{}/agent/register", self.base))
            .json(&req)
            .send()
            .await?;
        Self::unwrap_envelope(resp).await
    }

    /// POST /agent/poll
    pub async fn poll(&self, register_secret: &str) -> Result<PollData> {
        let req = PollReq {
            register_secret: register_secret.to_string(),
        };
        let resp = self
            .http
            .post(format!("{}/agent/poll", self.base))
            .json(&req)
            .send()
            .await?;
        Self::unwrap_envelope(resp).await
    }

    /// POST /agent/report
    pub async fn report(&self, agent_token: &str, m: &Metrics) -> Result<()> {
        let req = ReportReq {
            agent_token: agent_token.to_string(),
            cpu_usage: m.cpu_usage,
            memory_usage: m.memory_usage,
            disk_usage: m.disk_usage,
            net_rx: m.net_rx,
            net_tx: m.net_tx,
            uptime: m.uptime,
            hostname: m.hostname.clone(),
            os_version: m.os_version.clone(),
            ip: m.ip.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            is_container: m.is_container,
            cpu_cores: m.cpu_cores,
            mem_total: m.mem_total,
            mem_used: m.mem_used,
            disk_total: m.disk_total,
            disk_used: m.disk_used,
            disk_mounts: m.disk_mounts.clone(),
            update_phase: m.update_phase.clone(),
            update_progress: m.update_progress,
            update_done_bytes: m.update_done_bytes,
            update_total_bytes: m.update_total_bytes,
        };
        let resp = self
            .http
            .post(format!("{}/agent/report", self.base))
            .json(&req)
            .send()
            .await?;
        let _: serde_json::Value = Self::unwrap_envelope(resp).await?;
        Ok(())
    }

    /// POST /agent/should-upgrade — ask whether auto-update is enabled for this
    /// server. Used as the periodic, connection-independent upgrade path.
    pub async fn should_upgrade(&self, agent_token: &str) -> Result<ShouldUpgradeData> {
        let req = ShouldUpgradeReq {
            agent_token: agent_token.to_string(),
        };
        let resp = self
            .http
            .post(format!("{}/agent/should-upgrade", self.base))
            .json(&req)
            .send()
            .await?;
        Self::unwrap_envelope(resp).await
    }

    /// POST /agent/traffic — push a batch of per-process traffic deltas. Fire-
    /// and-forget from the caller's perspective beyond surfacing transport
    /// errors; the backend folds them into windowed Top-N rankings.
    pub async fn report_traffic(
        &self,
        agent_token: &str,
        samples: &[crate::traffic::ProcTrafficDelta],
    ) -> Result<()> {
        let req = TrafficReportReq {
            agent_token: agent_token.to_string(),
            samples,
        };
        let resp = self
            .http
            .post(format!("{}/agent/traffic", self.base))
            .json(&req)
            .send()
            .await?;
        let _: serde_json::Value = Self::unwrap_envelope(resp).await?;
        Ok(())
    }
}
