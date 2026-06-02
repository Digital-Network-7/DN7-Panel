//! WebSocket transport for streaming metrics to the backend.
//!
//! Preferred over HTTP `POST /agent/report`. Each report is sent as a JSON
//! text frame matching the backend's `ReportRequest`; the backend replies with
//! `{"ok":true}` or `{"ok":false,"error":...}`. The backend may also push
//! command frames (e.g. `{"command":"upgrade","download_url":"..."}`), which
//! `send` surfaces to the caller. If the connection drops or cannot be
//! established, the caller falls back to HTTP.

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
    MaybeTlsStream, WebSocketStream,
};

use crate::metrics::Metrics;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A command pushed down from the backend over the WebSocket.
#[derive(Debug, Clone)]
pub enum ServerCommand {
    /// Self-update to the latest version. The agent resolves the binary source
    /// itself (GitHub-first, download-service fallback).
    Upgrade,
    /// Open a local PTY shell and relay it back to the backend for the given
    /// terminal session id (dial `/agent/terminal?session=...`).
    OpenTerminal(String),
    /// Open a PTY running `docker exec` into a container and relay it back for
    /// the given session id (dial `/agent/terminal?session=...`).
    OpenContainerExec { session: String, container: String },
    /// Open a file-transfer channel and relay it back for the given session id
    /// (dial `/agent/file?session=...`).
    OpenFile(String),
    /// Open a file-transfer channel scoped to a container's filesystem (via
    /// `docker exec`/`docker cp`) and relay it back (dial `/agent/file?...`).
    OpenContainerFile { session: String, container: String },
    /// Open a Docker management channel and relay it back for the given session
    /// id (dial `/agent/docker?session=...`).
    OpenDocker(String),
    /// Open an Nginx management channel and relay it back for the given session
    /// id (dial `/agent/nginx?session=...`).
    OpenNginx(String),
    /// (Re)join the private overlay network: bring up a TUN device at `ip/prefix`
    /// and relay its packets through the backend (dial `/agent/pnet`). When
    /// `gone` is true, tear the overlay down instead.
    Pnet { ip: String, prefix: u8, gone: bool },
}

/// A live agent->backend metrics stream.
pub struct MetricsStream {
    socket: Socket,
    token: String,
}

impl MetricsStream {
    /// Establish the WebSocket connection. The agent token is sent in the
    /// `Authorization: Bearer` header (kept out of the URL/proxy logs); the
    /// backend still accepts a legacy `?token=` query for older agents.
    pub async fn connect(ws_url: &str, agent_token: &str) -> Result<Self> {
        let mut req = ws_url
            .into_client_request()
            .map_err(|e| anyhow!("bad ws url: {e}"))?;
        req.headers_mut().insert(
            AUTHORIZATION,
            format!("Bearer {agent_token}")
                .parse()
                .map_err(|e| anyhow!("bad auth header: {e}"))?,
        );
        let (socket, _resp) = connect_async(req).await?;
        Ok(MetricsStream {
            socket,
            token: agent_token.to_string(),
        })
    }

    /// Send one metrics report and wait for the backend ack. Returns any
    /// command frames received while waiting for the ack (e.g. an upgrade).
    ///
    /// The ack wait is bounded by `ack_timeout`: if the backend doesn't ack
    /// within it (a stalled/half-open connection), we error out so the caller
    /// drops the socket and reconnects, rather than blocking the whole metrics
    /// loop for tens of seconds (which would otherwise let samples pile up and
    /// then burst out on recovery).
    pub async fn send(&mut self, m: &Metrics, ack_timeout: Duration) -> Result<Vec<ServerCommand>> {
        match tokio::time::timeout(ack_timeout, self.send_inner(m)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("timed out waiting for backend ack")),
        }
    }

    async fn send_inner(&mut self, m: &Metrics) -> Result<Vec<ServerCommand>> {
        let payload = serde_json::json!({
            "agent_token": self.token,
            "cpu_usage": m.cpu_usage,
            "memory_usage": m.memory_usage,
            "disk_usage": m.disk_usage,
            "net_rx": m.net_rx,
            "net_tx": m.net_tx,
            "uptime": m.uptime,
            "hostname": m.hostname,
            "os_version": m.os_version,
            "ip": m.ip,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "is_container": m.is_container,
            "cpu_cores": m.cpu_cores,
            "mem_total": m.mem_total,
            "mem_used": m.mem_used,
            "disk_total": m.disk_total,
            "disk_used": m.disk_used,
            "disk_mounts": m.disk_mounts,
            "update_phase": m.update_phase,
            "update_progress": m.update_progress,
            "update_done_bytes": m.update_done_bytes,
            "update_total_bytes": m.update_total_bytes,
        });
        self.socket.send(Message::Text(payload.to_string())).await?;

        let mut commands = Vec::new();

        // Read frames until we get the ack (collecting any commands en route).
        loop {
            match self.socket.next().await {
                Some(Ok(Message::Text(text))) => {
                    let v: serde_json::Value =
                        serde_json::from_str(&text).map_err(|e| anyhow!("invalid frame: {e}"))?;

                    // Command frame (no "ok" field, has "command").
                    if let Some(cmd) = v.get("command").and_then(|c| c.as_str()) {
                        if cmd == "upgrade" {
                            commands.push(ServerCommand::Upgrade);
                        } else if cmd == "open-terminal" {
                            if let Some(session) = v.get("session").and_then(|s| s.as_str()) {
                                commands.push(ServerCommand::OpenTerminal(session.to_string()));
                            }
                        } else if cmd == "open-container-exec" {
                            if let (Some(session), Some(container)) = (
                                v.get("session").and_then(|s| s.as_str()),
                                v.get("container").and_then(|s| s.as_str()),
                            ) {
                                commands.push(ServerCommand::OpenContainerExec {
                                    session: session.to_string(),
                                    container: container.to_string(),
                                });
                            }
                        } else if cmd == "open-file" {
                            if let Some(session) = v.get("session").and_then(|s| s.as_str()) {
                                commands.push(ServerCommand::OpenFile(session.to_string()));
                            }
                        } else if cmd == "open-container-file" {
                            if let (Some(session), Some(container)) = (
                                v.get("session").and_then(|s| s.as_str()),
                                v.get("container").and_then(|s| s.as_str()),
                            ) {
                                commands.push(ServerCommand::OpenContainerFile {
                                    session: session.to_string(),
                                    container: container.to_string(),
                                });
                            }
                        } else if cmd == "open-docker" {
                            if let Some(session) = v.get("session").and_then(|s| s.as_str()) {
                                commands.push(ServerCommand::OpenDocker(session.to_string()));
                            }
                        } else if cmd == "open-nginx" {
                            if let Some(session) = v.get("session").and_then(|s| s.as_str()) {
                                commands.push(ServerCommand::OpenNginx(session.to_string()));
                            }
                        } else if cmd == "pnet" {
                            let ip = v
                                .get("ip")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string();
                            let prefix =
                                v.get("prefix").and_then(|p| p.as_u64()).unwrap_or(24) as u8;
                            let gone = v.get("gone").and_then(|g| g.as_bool()).unwrap_or(false);
                            commands.push(ServerCommand::Pnet { ip, prefix, gone });
                        }
                        continue;
                    }

                    // Ack frame.
                    if v.get("ok").and_then(|b| b.as_bool()) == Some(true) {
                        return Ok(commands);
                    }
                    let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown");
                    return Err(anyhow!("backend rejected report: {err}"));
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                Some(Ok(Message::Close(_))) | None => {
                    return Err(anyhow!("websocket closed by server"))
                }
                Some(Err(e)) => return Err(anyhow!("websocket error: {e}")),
                _ => continue,
            }
        }
    }
}
