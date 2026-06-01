//! Agent-side file-transfer relay.
//!
//! When the backend pushes an `open-file` command, the agent dials back
//! `/agent/file?session=` (token in the `Authorization` header) and serves a
//! small file protocol against the local filesystem:
//!
//!   backend WS  <->  agent  <->  local filesystem
//!
//! Control frames (JSON text) from the client:
//!   {"type":"list","path":"/abs/dir"}
//!   {"type":"download","path":"/abs/file"}
//!   {"type":"upload","path":"/abs/file","size":N}  then binary chunks, then
//!       {"type":"upload-end"}
//!   {"type":"cancel"}                              abort the active transfer
//!   {"type":"mkdir","path":"/abs/dir"}
//!   {"type":"delete","path":"/abs/path"}
//! Responses (JSON text unless noted):
//!   {"type":"list","path":..,"entries":[{name,is_dir,size}]}
//!   {"type":"download-begin","name":..,"size":N}  then binary chunks, then
//!       {"type":"download-end"}
//!   {"type":"upload-progress","received":N}        ack bytes written (for speed)
//!   {"type":"ok","message":..} / {"type":"error","message":..}
//!   {"type":"cancelled"}                           the active transfer was aborted

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

/// Chunk size for streaming file content (256 KiB).
const CHUNK: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ClientMsg {
    List { path: String },
    Download { path: String },
    // `size` is declared by the client (and metered by the backend); the agent
    // doesn't need it, but keep it so the frame deserializes cleanly.
    Upload {
        path: String,
        #[serde(default)]
        #[allow(dead_code)]
        size: i64,
    },
    UploadEnd,
    Cancel,
    Mkdir { path: String },
    Delete { path: String },
}

/// State for an in-progress upload (between `upload` and `upload-end`).
struct UploadState {
    file: tokio::fs::File,
    path: PathBuf,
    /// Bytes written so far; echoed back as `upload-progress` so the client can
    /// compute the *real* client→agent throughput (not its local buffer fill).
    received: u64,
}

/// Connect to the backend file relay and serve the protocol until either side
/// closes.
pub async fn run_file_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_file_ws_url(session);
    let mut req = url
        .into_client_request()
        .map_err(|e| anyhow!("bad ws url: {e}"))?;
    req.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {agent_token}")
            .parse()
            .map_err(|e| anyhow!("bad auth header: {e}"))?,
    );
    let (ws, _resp) = connect_async(req).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    let mut upload: Option<UploadState> = None;

    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                let parsed: Result<ClientMsg, _> = serde_json::from_str(t.trim());
                let cmd = match parsed {
                    Ok(c) => c,
                    Err(_) => {
                        send_err(&mut ws_tx, "无法识别的指令").await;
                        continue;
                    }
                };
                match cmd {
                    ClientMsg::List { path } => {
                        if let Err(e) = handle_list(&mut ws_tx, &path).await {
                            send_err(&mut ws_tx, &format!("列目录失败：{e}")).await;
                        }
                    }
                    ClientMsg::Download { path } => {
                        match handle_download(&mut ws_tx, &mut ws_rx, &path).await {
                            Ok(true) => {} // completed
                            Ok(false) => {
                                // Cancelled mid-stream by the client.
                                send_cancelled(&mut ws_tx).await;
                            }
                            Err(e) => {
                                send_err(&mut ws_tx, &format!("下载失败：{e}")).await;
                            }
                        }
                    }
                    ClientMsg::Upload { path, .. } => {
                        match tokio::fs::File::create(&path).await {
                            Ok(file) => {
                                upload = Some(UploadState {
                                    file,
                                    path: PathBuf::from(&path),
                                    received: 0,
                                });
                            }
                            Err(e) => {
                                upload = None;
                                send_err(&mut ws_tx, &format!("无法创建文件：{e}")).await;
                            }
                        }
                    }
                    ClientMsg::UploadEnd => {
                        if let Some(mut u) = upload.take() {
                            let _ = u.file.flush().await;
                            send_ok(&mut ws_tx, &format!("已上传到 {}", u.path.display())).await;
                        } else {
                            send_err(&mut ws_tx, "没有进行中的上传").await;
                        }
                    }
                    ClientMsg::Cancel => {
                        // Abort an in-progress upload: drop the partial file.
                        if let Some(u) = upload.take() {
                            drop(u.file);
                            let _ = tokio::fs::remove_file(&u.path).await;
                        }
                        send_cancelled(&mut ws_tx).await;
                    }
                    ClientMsg::Mkdir { path } => match tokio::fs::create_dir_all(&path).await {
                        Ok(_) => send_ok(&mut ws_tx, "已创建目录").await,
                        Err(e) => send_err(&mut ws_tx, &format!("创建目录失败：{e}")).await,
                    },
                    ClientMsg::Delete { path } => {
                        let p = Path::new(&path);
                        let res = if p.is_dir() {
                            tokio::fs::remove_dir_all(&path).await
                        } else {
                            tokio::fs::remove_file(&path).await
                        };
                        match res {
                            Ok(_) => send_ok(&mut ws_tx, "已删除").await,
                            Err(e) => send_err(&mut ws_tx, &format!("删除失败：{e}")).await,
                        }
                    }
                }
            }
            Ok(Message::Binary(b)) => {
                // Upload chunk for the active upload.
                if let Some(u) = upload.as_mut() {
                    if let Err(e) = u.file.write_all(&b).await {
                        send_err(&mut ws_tx, &format!("写入失败：{e}")).await;
                        let _ = tokio::fs::remove_file(&u.path).await;
                        upload = None;
                    } else {
                        u.received += b.len() as u64;
                        // Ack the bytes durably received so the client can show
                        // the true client→agent throughput (the backend paces
                        // these frames, so the client's own send rate lies).
                        let ack = u.received;
                        send_upload_progress(&mut ws_tx, ack).await;
                    }
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = ws_tx.send(Message::Pong(p)).await;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    let _ = ws_tx.close().await;
    Ok(())
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

async fn handle_list(ws: &mut WsSink, path: &str) -> Result<()> {
    // Default to "/" when empty.
    let dir = if path.trim().is_empty() { "/" } else { path };
    let mut entries = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name().to_string_lossy().to_string();
        let md = ent.metadata().await.ok();
        let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = md.as_ref().map(|m| m.len()).unwrap_or(0);
        entries.push(serde_json::json!({ "name": name, "is_dir": is_dir, "size": size }));
    }
    // Directories first, then files; both alphabetical.
    entries.sort_by(|a, b| {
        let ad = a["is_dir"].as_bool().unwrap_or(false);
        let bd = b["is_dir"].as_bool().unwrap_or(false);
        bd.cmp(&ad).then_with(|| {
            a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
        })
    });
    let payload = serde_json::json!({ "type": "list", "path": dir, "entries": entries });
    ws.send(Message::Text(payload.to_string())).await?;
    Ok(())
}

type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Stream a file to the client, chunk by chunk. Between chunks it watches the
/// incoming stream for a `{"type":"cancel"}` frame so a download can be aborted
/// promptly. Returns Ok(true) when the whole file was sent, Ok(false) when the
/// client cancelled.
async fn handle_download(ws: &mut WsSink, rx: &mut WsStream, path: &str) -> Result<bool> {
    let md = tokio::fs::metadata(path).await?;
    if md.is_dir() {
        return Err(anyhow!("不能下载目录"));
    }
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let begin = serde_json::json!({ "type": "download-begin", "name": name, "size": md.len() });
    ws.send(Message::Text(begin.to_string())).await?;

    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        // Send the chunk fully (never drop a partial send), then do a quick
        // non-blocking check for a cancel frame the client may have sent.
        ws.send(Message::Binary(buf[..n].to_vec())).await?;
        if check_cancel(rx).await {
            return Ok(false);
        }
    }
    ws.send(Message::Text("{\"type\":\"download-end\"}".to_string())).await?;
    Ok(true)
}

/// Non-blocking peek at the incoming stream: returns true if a cancel frame (or
/// a close) is already pending. Never waits for a new frame.
async fn check_cancel(rx: &mut WsStream) -> bool {
    use futures_util::future::FutureExt;
    match rx.next().now_or_never() {
        Some(Some(Ok(Message::Text(t)))) => is_cancel(&t),
        Some(Some(Ok(Message::Close(_)))) | Some(None) => true,
        _ => false,
    }
}

/// True if a text frame is a `{"type":"cancel"}` control message.
fn is_cancel(t: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(t.trim())
        .ok()
        .and_then(|v| v.get("type").and_then(|s| s.as_str()).map(|s| s == "cancel"))
        .unwrap_or(false)
}

async fn send_ok(ws: &mut WsSink, message: &str) {
    let _ = ws
        .send(Message::Text(
            serde_json::json!({ "type": "ok", "message": message }).to_string(),
        ))
        .await;
}

async fn send_upload_progress(ws: &mut WsSink, received: u64) {
    let _ = ws
        .send(Message::Text(
            serde_json::json!({ "type": "upload-progress", "received": received }).to_string(),
        ))
        .await;
}

async fn send_cancelled(ws: &mut WsSink) {
    let _ = ws
        .send(Message::Text(
            serde_json::json!({ "type": "cancelled" }).to_string(),
        ))
        .await;
}

async fn send_err(ws: &mut WsSink, message: &str) {
    let _ = ws
        .send(Message::Text(
            serde_json::json!({ "type": "error", "message": message }).to_string(),
        ))
        .await;
}
