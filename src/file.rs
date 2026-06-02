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

// ---------------------------------------------------------------------------
// Container-scoped file transfer (via `docker exec` / `docker cp`).
//
// Mirrors the host file protocol but every operation runs *inside* a container:
//   - list/mkdir/delete/stat run `docker exec <c> sh -c '<script>' sh "<path>"`
//     with the path passed as a positional arg ($1), never interpolated into
//     the script, so there's no shell-injection surface.
// ---------------------------------------------------------------------------
// Container-scoped file transfer (daemon API: exec for list/mkdir/delete,
// archive/tar for upload + download). No `docker` CLI required.
// Paths must be absolute (so they can't be mistaken for command flags).
// ---------------------------------------------------------------------------

/// State for an in-progress container upload (temp file on the host, copied into
/// the container on upload-end).
struct ContainerUploadState {
    file: tokio::fs::File,
    temp_path: PathBuf,
    dest_path: String,
    received: u64,
}

/// Reject container refs that could smuggle extra docker flags.
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

/// Require an absolute path (so it can't be read as a CLI flag).
fn check_abs(path: &str) -> Result<()> {
    if path.starts_with('/') {
        Ok(())
    } else {
        Err(anyhow!("路径必须为绝对路径"))
    }
}

/// A short, collision-resistant suffix for a host temp file name (pid + a
/// monotonic counter). Avoids pulling in a uuid dependency just for this.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("{}-{}", std::process::id(), n)
}

/// Serve the file protocol against a container's filesystem.
pub async fn run_container_file_channel(
    cfg: &AgentConfig,
    agent_token: &str,
    session: &str,
    container: &str,
) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
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

    let mut upload: Option<ContainerUploadState> = None;

    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                let cmd = match serde_json::from_str::<ClientMsg>(t.trim()) {
                    Ok(c) => c,
                    Err(_) => {
                        send_err(&mut ws_tx, "无法识别的指令").await;
                        continue;
                    }
                };
                match cmd {
                    ClientMsg::List { path } => {
                        if let Err(e) = ctn_list(&mut ws_tx, container, &path).await {
                            send_err(&mut ws_tx, &format!("列目录失败：{e}")).await;
                        }
                    }
                    ClientMsg::Download { path } => {
                        match ctn_download(&mut ws_tx, &mut ws_rx, container, &path).await {
                            Ok(true) => {}
                            Ok(false) => send_cancelled(&mut ws_tx).await,
                            Err(e) => send_err(&mut ws_tx, &format!("下载失败：{e}")).await,
                        }
                    }
                    ClientMsg::Upload { path, .. } => {
                        if let Err(e) = check_abs(&path) {
                            send_err(&mut ws_tx, &e.to_string()).await;
                            continue;
                        }
                        // Buffer into a unique host temp file.
                        let temp_path = std::env::temp_dir()
                            .join(format!("teaops-ctn-up-{}", unique_suffix()));
                        match tokio::fs::File::create(&temp_path).await {
                            Ok(file) => {
                                upload = Some(ContainerUploadState {
                                    file,
                                    temp_path,
                                    dest_path: path,
                                    received: 0,
                                });
                            }
                            Err(e) => {
                                upload = None;
                                send_err(&mut ws_tx, &format!("无法创建临时文件：{e}")).await;
                            }
                        }
                    }
                    ClientMsg::UploadEnd => {
                        if let Some(mut u) = upload.take() {
                            let _ = u.file.flush().await;
                            drop(u.file);
                            // Upload the temp file into the container via the
                            // archive API (tar stream) — no `docker` CLI needed.
                            let res = ctn_upload_file(container, &u.temp_path, &u.dest_path).await;
                            let _ = tokio::fs::remove_file(&u.temp_path).await;
                            match res {
                                Ok(_) => {
                                    send_ok(&mut ws_tx, &format!("已上传到 {}", u.dest_path)).await;
                                }
                                Err(e) => {
                                    send_err(&mut ws_tx, &format!("上传到容器失败：{e}")).await;
                                }
                            }
                        } else {
                            send_err(&mut ws_tx, "没有进行中的上传").await;
                        }
                    }
                    ClientMsg::Cancel => {
                        if let Some(u) = upload.take() {
                            drop(u.file);
                            let _ = tokio::fs::remove_file(&u.temp_path).await;
                        }
                        send_cancelled(&mut ws_tx).await;
                    }
                    ClientMsg::Mkdir { path } => {
                        match ctn_exec_ok(container, "mkdir -p \"$1\"", &path).await {
                            Ok(_) => send_ok(&mut ws_tx, "已创建目录").await,
                            Err(e) => send_err(&mut ws_tx, &format!("创建目录失败：{e}")).await,
                        }
                    }
                    ClientMsg::Delete { path } => {
                        match ctn_exec_ok(container, "rm -rf \"$1\"", &path).await {
                            Ok(_) => send_ok(&mut ws_tx, "已删除").await,
                            Err(e) => send_err(&mut ws_tx, &format!("删除失败：{e}")).await,
                        }
                    }
                }
            }
            Ok(Message::Binary(b)) => {
                if let Some(u) = upload.as_mut() {
                    if let Err(e) = u.file.write_all(&b).await {
                        send_err(&mut ws_tx, &format!("写入失败：{e}")).await;
                        let _ = tokio::fs::remove_file(&u.temp_path).await;
                        upload = None;
                    } else {
                        u.received += b.len() as u64;
                        send_upload_progress(&mut ws_tx, u.received).await;
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

    if let Some(u) = upload.take() {
        drop(u.file);
        let _ = tokio::fs::remove_file(&u.temp_path).await;
    }
    let _ = ws_tx.close().await;
    Ok(())
}

/// Run `sh -c '<script>' sh "<arg>"` inside the container via the daemon exec
/// API. `arg` becomes `$1` (a separate argv entry — no shell injection). Returns
/// (exit_code, stdout, stderr-ish combined). No `docker` CLI required.
async fn ctn_exec_collect(
    container: &str,
    script: &str,
    arg: &str,
) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
    use futures::StreamExt;

    let dkr = crate::docker::dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    script.to_string(),
                    "sh".to_string(),
                    arg.to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;
    let started = dkr
        .start_exec(&exec.id, Some(StartExecOptions { detach: false, ..Default::default() }))
        .await
        .map_err(|e| anyhow!("容器内执行失败：{e}"))?;

    let mut buf = String::new();
    if let StartExecResults::Attached { mut output, .. } = started {
        while let Some(item) = output.next().await {
            if let Ok(msg) = item {
                buf.push_str(&String::from_utf8_lossy(&msg.into_bytes()));
            }
        }
    }
    // Inspect for the real exit code.
    let code = dkr
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code)
        .unwrap_or(0);
    Ok((code, buf))
}

/// Run a container script expecting a zero exit (mkdir/delete).
async fn ctn_exec_ok(container: &str, script: &str, arg: &str) -> Result<()> {
    check_abs(arg)?;
    let (code, out) = ctn_exec_collect(container, script, arg).await?;
    if code == 0 {
        Ok(())
    } else {
        let msg = out.trim();
        Err(anyhow!(if msg.is_empty() {
            "操作失败".to_string()
        } else {
            msg.chars().take(300).collect::<String>()
        }))
    }
}

/// Upload a host temp file into the container at `dest_path` using the archive
/// (tar) API. Works even on shell-less images.
async fn ctn_upload_file(
    container: &str,
    temp_path: &Path,
    dest_path: &str,
) -> Result<()> {
    check_abs(dest_path)?;
    let dest = Path::new(dest_path);
    let parent = dest
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    let fname = dest
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .ok_or_else(|| anyhow!("目标路径无效"))?;

    // Build an in-memory tar containing the single file under its base name.
    let data = tokio::fs::read(temp_path).await?;
    let mut tar_buf: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::file());
        builder
            .append_data(&mut header, &fname, data.as_slice())
            .map_err(|e| anyhow!("打包失败：{e}"))?;
        builder.finish().map_err(|e| anyhow!("打包失败：{e}"))?;
    }

    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::UploadToContainerOptions {
        path: parent,
        ..Default::default()
    };
    dkr.upload_to_container(container, Some(opts), tar_buf.into())
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// List a directory inside the container via the daemon exec API. Emits the same
/// `{type:"list"}` shape as the host path: each entry is `{name, is_dir, size}`.
async fn ctn_list(ws: &mut WsSink, container: &str, path: &str) -> Result<()> {
    let dir = if path.trim().is_empty() { "/" } else { path };
    check_abs(dir)?;
    // Portable listing: for each entry print "<d|f>\t<size>\t<name>".
    let script = r#"cd "$1" 2>/dev/null || exit 7
for name in * .[!.]* ..?*; do
  [ -e "$name" ] || [ -L "$name" ] || continue
  if [ -d "$name" ]; then
    printf 'd\t0\t%s\n' "$name"
  else
    sz=$(stat -c %s "$name" 2>/dev/null || stat -f %z "$name" 2>/dev/null || echo 0)
    printf 'f\t%s\t%s\n' "$sz" "$name"
  fi
done"#;
    let (code, stdout) = ctn_exec_collect(container, script, dir).await?;
    if code != 0 {
        return Err(anyhow!("目录不存在或无权限"));
    }
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let mut it = line.splitn(3, '\t');
        let t = it.next().unwrap_or("");
        let sz = it.next().unwrap_or("0");
        let name = match it.next() {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let is_dir = t == "d";
        let size: u64 = sz.trim().parse().unwrap_or(0);
        entries.push(serde_json::json!({ "name": name, "is_dir": is_dir, "size": size }));
    }
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

/// Stream a file out of the container via the archive (tar) API, unpacking the
/// single entry and forwarding its bytes in chunks. Honors a mid-stream cancel.
/// Returns Ok(false) if the client cancelled.
async fn ctn_download(
    ws: &mut WsSink,
    rx: &mut WsStream,
    container: &str,
    path: &str,
) -> Result<bool> {
    use futures::StreamExt;

    check_abs(path)?;
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::DownloadFromContainerOptions { path: path.to_string() };

    // Collect the tar stream into memory. (Container files transferred through
    // the app are bounded by the per-level rate limit + practical sizes.)
    let mut stream = dkr.download_from_container(container, Some(opts));
    let mut tar_bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            // The most common failure is a missing path.
            anyhow!(friendly_archive_err(&e))
        })?;
        tar_bytes.extend_from_slice(&chunk);
    }

    // Unpack the (single) regular file entry from the tar.
    let (name, data) = extract_single_file(&tar_bytes)
        .ok_or_else(|| anyhow!("不能下载目录或空文件"))?;

    let begin = serde_json::json!({ "type": "download-begin", "name": name, "size": data.len() });
    ws.send(Message::Text(begin.to_string())).await?;

    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + CHUNK).min(data.len());
        ws.send(Message::Binary(data[offset..end].to_vec())).await?;
        offset = end;
        if check_cancel(rx).await {
            return Ok(false);
        }
    }
    ws.send(Message::Text("{\"type\":\"download-end\"}".to_string())).await?;
    Ok(true)
}

/// Map a bollard archive error to a friendly message.
fn friendly_archive_err(e: &bollard::errors::Error) -> String {
    let s = e.to_string();
    if s.contains("no such file") || s.contains("not found") || s.contains("404") {
        "文件不存在".to_string()
    } else {
        s.chars().take(300).collect()
    }
}

/// Extract the first regular-file entry from a tar archive, returning
/// (basename, bytes). Returns None if there's no regular file (e.g. a dir).
fn extract_single_file(tar_bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut ar = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let entries = ar.entries().ok()?;
    for entry in entries.flatten() {
        let is_file = entry.header().entry_type().is_file();
        if !is_file {
            continue;
        }
        let name = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "download".to_string());
        let mut data = Vec::new();
        let mut entry = entry;
        if std::io::Read::read_to_end(&mut entry, &mut data).is_ok() {
            return Some((name, data));
        }
    }
    None
}
