//! Agent-side file-transfer relay.
//!
//! When the backend pushes an `open-file` command, the agent dials back
//! `/agent/file?token=&session=` and serves a small file protocol against the
//! local filesystem:
//!
//!   backend WS  <->  agent  <->  local filesystem
//!
//! Control frames (JSON text) from the client:
//!   {"type":"list","path":"/abs/dir"}
//!   {"type":"download","path":"/abs/file"}
//!   {"type":"upload","path":"/abs/file","size":N}  then binary chunks, then
//!       {"type":"upload-end"}
//!   {"type":"mkdir","path":"/abs/dir"}
//!   {"type":"delete","path":"/abs/path"}
//! Responses (JSON text unless noted):
//!   {"type":"list","path":..,"entries":[{name,is_dir,size}]}
//!   {"type":"download-begin","name":..,"size":N}  then binary chunks, then
//!       {"type":"download-end"}
//!   {"type":"ok","message":..} / {"type":"error","message":..}

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

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
    Mkdir { path: String },
    Delete { path: String },
}

/// State for an in-progress upload (between `upload` and `upload-end`).
struct UploadState {
    file: tokio::fs::File,
    path: PathBuf,
}

/// Connect to the backend file relay and serve the protocol until either side
/// closes.
pub async fn run_file_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_file_ws_url(agent_token, session);
    let (ws, _resp) = connect_async(&url).await?;
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
                        if let Err(e) = handle_download(&mut ws_tx, &path).await {
                            send_err(&mut ws_tx, &format!("下载失败：{e}")).await;
                        }
                    }
                    ClientMsg::Upload { path, .. } => {
                        match tokio::fs::File::create(&path).await {
                            Ok(file) => {
                                upload = Some(UploadState { file, path: PathBuf::from(&path) });
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
                        upload = None;
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

async fn handle_download(ws: &mut WsSink, path: &str) -> Result<()> {
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
        ws.send(Message::Binary(buf[..n].to_vec())).await?;
    }
    ws.send(Message::Text("{\"type\":\"download-end\"}".to_string())).await?;
    Ok(())
}

async fn send_ok(ws: &mut WsSink, message: &str) {
    let _ = ws
        .send(Message::Text(
            serde_json::json!({ "type": "ok", "message": message }).to_string(),
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
