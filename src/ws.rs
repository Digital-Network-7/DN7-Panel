//! WebSocket transport for streaming metrics to the backend.
//!
//! Preferred over HTTP `POST /agent/report`. Each report is sent as a JSON
//! text frame matching the backend's `ReportRequest`; the backend replies with
//! `{"ok":true}` or `{"ok":false,"error":...}`. If the connection drops or
//! cannot be established, the caller falls back to HTTP.

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::metrics::Metrics;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A live agent->backend metrics stream.
pub struct MetricsStream {
    socket: Socket,
    token: String,
}

impl MetricsStream {
    /// Establish the WebSocket connection.
    pub async fn connect(ws_url: &str, agent_token: &str) -> Result<Self> {
        let (socket, _resp) = connect_async(ws_url).await?;
        Ok(MetricsStream {
            socket,
            token: agent_token.to_string(),
        })
    }

    /// Send one metrics report and wait for the backend ack.
    pub async fn send(&mut self, m: &Metrics) -> Result<()> {
        let payload = serde_json::json!({
            "agent_token": self.token,
            "cpu_usage": m.cpu_usage,
            "memory_usage": m.memory_usage,
            "disk_usage": m.disk_usage,
            "uptime": m.uptime,
            "hostname": m.hostname,
            "os_version": m.os_version,
            "ip": m.ip,
        });
        self.socket
            .send(Message::Text(payload.to_string()))
            .await?;

        // Read frames until we get the ack (skipping pings/pongs).
        loop {
            match self.socket.next().await {
                Some(Ok(Message::Text(text))) => {
                    let v: serde_json::Value = serde_json::from_str(&text)
                        .map_err(|e| anyhow!("invalid ack: {e}"))?;
                    if v.get("ok").and_then(|b| b.as_bool()) == Some(true) {
                        return Ok(());
                    }
                    let err = v
                        .get("error")
                        .and_then(|e| e.as_str())
                        .unwrap_or("unknown");
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
