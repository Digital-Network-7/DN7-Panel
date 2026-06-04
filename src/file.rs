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

/// Reject deleting a path that is (or sits at) a critical system directory, to
/// guard against a catastrophic recursive delete (e.g. an accidental `/` or
/// `/etc`). This is a safety net, not an access-control boundary: the server
/// owner already has full file access by design — we only block the handful of
/// paths whose removal would brick the host.
fn is_protected_path(path: &str) -> bool {
    // Normalize: trim, drop a single trailing slash (but keep root "/").
    let p = path.trim();
    let p = if p.len() > 1 {
        p.trim_end_matches('/')
    } else {
        p
    };
    if p.is_empty() || p == "/" {
        return true;
    }
    const PROTECTED: &[&str] = &[
        "/bin", "/sbin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
        "/root", "/run", "/sys", "/usr", "/var",
    ];
    PROTECTED.contains(&p)
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ClientMsg {
    List {
        path: String,
    },
    Download {
        path: String,
    },
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
    Mkdir {
        path: String,
    },
    Delete {
        path: String,
    },
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
                    ClientMsg::Upload { path, .. } => match tokio::fs::File::create(&path).await {
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
                    },
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
                        if is_protected_path(&path) {
                            send_err(&mut ws_tx, "该系统目录受保护，禁止删除").await;
                            continue;
                        }
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
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
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
    ws.send(Message::Text("{\"type\":\"download-end\"}".to_string()))
        .await?;
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
        .and_then(|v| {
            v.get("type")
                .and_then(|s| s.as_str())
                .map(|s| s == "cancel")
        })
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
// Container-scoped file transfer (Docker daemon API; no `docker` CLI).
//
// Mirrors the host file protocol but every operation targets a container:
//   - list/mkdir/delete run via the daemon exec API (`/bin/sh -c '<script>' sh
//     "<path>"`), the path passed as a positional arg ($1), never interpolated
//     into the script — no shell-injection surface.
//   - download streams the container archive (tar) API, parsing the single
//     entry incrementally and forwarding its bytes in chunks (no full buffering).
//   - upload buffers chunks into a host temp file, then streams a tar of it into
//     the container via the archive API (works on shell-less images too).
// Paths must be absolute (so they can't be mistaken for flags), and deletes of
// critical system directories are refused (see `is_protected_path`).
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
                        let temp_path =
                            std::env::temp_dir().join(format!("teaops-ctn-up-{}", unique_suffix()));
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
                        if is_protected_path(&path) {
                            send_err(&mut ws_tx, "该系统目录受保护，禁止删除").await;
                            continue;
                        }
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
async fn ctn_exec_collect(container: &str, script: &str, arg: &str) -> Result<(i64, String)> {
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
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
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
/// (tar) API, **streaming** the tar body (header + file content read in chunks +
/// padding + footer) so we never hold the whole file in memory. Works even on
/// shell-less images.
async fn ctn_upload_file(container: &str, temp_path: &Path, dest_path: &str) -> Result<()> {
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

    // File size (for the tar header) from metadata — no full read.
    let size = tokio::fs::metadata(temp_path).await?.len();

    // Build the 512-byte tar header up front (size is known).
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::file());
    header
        .set_path(&fname)
        .map_err(|e| anyhow!("打包失败：{e}"))?;
    header.set_cksum();

    let body = upload_tar_stream(header, temp_path.to_path_buf(), size);

    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::UploadToContainerOptions {
        path: parent,
        ..Default::default()
    };
    dkr.upload_to_container_streaming(container, Some(opts), body)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

/// Build a streaming tar body for a single file: 512-byte header, then the file
/// content read in CHUNK pieces, then NUL padding to a 512 boundary, then the
/// two zero blocks that terminate a tar. Never buffers the whole file.
fn upload_tar_stream(
    header: tar::Header,
    temp_path: std::path::PathBuf,
    size: u64,
) -> impl futures::Stream<Item = bytes::Bytes> + Send + 'static {
    use bytes::Bytes;

    // Tar stages emitted in order.
    enum Stage {
        Header,
        Body { file: tokio::fs::File, left: u64 },
        Pad,
        Footer,
        Done,
    }

    let header_bytes = Bytes::copy_from_slice(header.as_bytes());
    let pad = ((512 - (size % 512)) % 512) as usize;

    futures::stream::unfold(Stage::Header, move |stage| {
        let header_bytes = header_bytes.clone();
        let temp_path = temp_path.clone();
        async move {
            use tokio::io::AsyncReadExt;
            match stage {
                Stage::Header => {
                    // Open the file lazily for the body stage.
                    let next = if size > 0 {
                        match tokio::fs::File::open(&temp_path).await {
                            Ok(file) => Stage::Body { file, left: size },
                            // On open failure, end the stream early (upload fails
                            // server-side with a truncated/invalid tar).
                            Err(_) => Stage::Done,
                        }
                    } else if pad > 0 {
                        Stage::Pad
                    } else {
                        Stage::Footer
                    };
                    Some((header_bytes, next))
                }
                Stage::Body { mut file, left } => {
                    let want = (left as usize).min(CHUNK);
                    let mut buf = vec![0u8; want];
                    match file.read(&mut buf).await {
                        Ok(0) => {
                            // Unexpected EOF; move on to padding/footer.
                            let next = if pad > 0 { Stage::Pad } else { Stage::Footer };
                            // Emit nothing this step — recurse via an empty chunk.
                            Some((Bytes::new(), next))
                        }
                        Ok(n) => {
                            buf.truncate(n);
                            let remaining = left - n as u64;
                            let next = if remaining > 0 {
                                Stage::Body {
                                    file,
                                    left: remaining,
                                }
                            } else if pad > 0 {
                                Stage::Pad
                            } else {
                                Stage::Footer
                            };
                            Some((Bytes::from(buf), next))
                        }
                        Err(_) => Some((Bytes::new(), Stage::Footer)),
                    }
                }
                Stage::Pad => Some((Bytes::from(vec![0u8; pad]), Stage::Footer)),
                // Tar archives end with two 512-byte zero blocks.
                Stage::Footer => Some((Bytes::from(vec![0u8; 1024]), Stage::Done)),
                Stage::Done => None,
            }
        }
    })
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
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        })
    });
    let payload = serde_json::json!({ "type": "list", "path": dir, "entries": entries });
    ws.send(Message::Text(payload.to_string())).await?;
    Ok(())
}

/// Stream a file out of the container via the archive (tar) API, parsing the
/// tar **incrementally** as bytes arrive and forwarding the single file entry's
/// payload in chunks — never buffering the whole file in memory. Honors a
/// mid-stream cancel. Returns Ok(false) if the client cancelled.
async fn ctn_download(
    ws: &mut WsSink,
    rx: &mut WsStream,
    container: &str,
    path: &str,
) -> Result<bool> {
    use futures::StreamExt;

    check_abs(path)?;
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::DownloadFromContainerOptions {
        path: path.to_string(),
    };
    let mut stream = dkr.download_from_container(container, Some(opts));

    // Incremental single-entry tar parser. Docker returns a tar with one header
    // (512 bytes: name @0..100, octal size @124..136) followed by `size` bytes
    // of content. We parse the header from the first 512 bytes, emit
    // download-begin, then forward content bytes as they arrive.
    let mut header: Vec<u8> = Vec::with_capacity(512);
    let mut begun = false;
    let mut remaining: u64 = 0; // content bytes still to forward
    let mut pending: Vec<u8> = Vec::new(); // buffered content not yet flushed

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!(friendly_archive_err(&e)))?;
        let mut data: &[u8] = &chunk;

        // Phase 1: assemble the 512-byte tar header.
        if !begun {
            let need = 512 - header.len();
            let take = need.min(data.len());
            header.extend_from_slice(&data[..take]);
            data = &data[take..];
            if header.len() < 512 {
                continue; // need more bytes for the header
            }
            let (name, size) =
                parse_tar_header(&header).ok_or_else(|| anyhow!("不能下载目录或空文件"))?;
            if size == 0 {
                return Err(anyhow!("不能下载目录或空文件"));
            }
            remaining = size;
            begun = true;
            let begin = serde_json::json!({ "type": "download-begin", "name": name, "size": size });
            ws.send(Message::Text(begin.to_string())).await?;
        }

        // Phase 2: `data` now holds (some) content + trailing tar padding.
        if remaining > 0 && !data.is_empty() {
            let content_len = (remaining as usize).min(data.len());
            pending.extend_from_slice(&data[..content_len]);
            remaining -= content_len as u64;

            // Flush full CHUNK-sized frames, checking for cancel between them.
            while pending.len() >= CHUNK {
                let frame: Vec<u8> = pending.drain(..CHUNK).collect();
                ws.send(Message::Binary(frame)).await?;
                if check_cancel(rx).await {
                    return Ok(false);
                }
            }
        }
        // Bytes past the content are tar padding/footer — ignored.
        if begun && remaining == 0 {
            break;
        }
    }

    // Flush any remaining tail (< CHUNK).
    if !pending.is_empty() {
        ws.send(Message::Binary(pending)).await?;
        if check_cancel(rx).await {
            return Ok(false);
        }
    }

    if !begun {
        return Err(anyhow!("文件不存在"));
    }
    ws.send(Message::Text("{\"type\":\"download-end\"}".to_string()))
        .await?;
    Ok(true)
}

/// Parse a POSIX/GNU tar header: file base name (bytes 0..100, NUL-terminated)
/// and content size (octal ASCII, bytes 124..136). Returns None if the entry
/// isn't a regular file or the header is malformed.
fn parse_tar_header(h: &[u8]) -> Option<(String, u64)> {
    if h.len() < 512 {
        return None;
    }
    // Type flag at offset 156: '0' or '\0' == regular file.
    let typeflag = h[156];
    if !(typeflag == b'0' || typeflag == 0) {
        return None;
    }
    // Name (may be empty if using a GNU long-name extension, which docker
    // doesn't emit for a single file copy).
    let name_end = h[0..100].iter().position(|&b| b == 0).unwrap_or(100);
    let raw_name = String::from_utf8_lossy(&h[0..name_end]).to_string();
    let base = raw_name
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("download")
        .to_string();
    // Size: octal ASCII in bytes 124..136.
    let size_field = &h[124..136];
    let size_str = String::from_utf8_lossy(size_field);
    let size = u64::from_str_radix(size_str.trim().trim_end_matches('\0').trim(), 8).ok()?;
    Some((base, size))
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

// ---------------------------------------------------------------------------
// Web console (axum) file operations — plain request/response over HTTP, no
// WebSocket relay. Host paths use tokio::fs directly; container paths reuse the
// daemon exec / archive helpers above. Used by `web::server`.
// ---------------------------------------------------------------------------

/// List a host directory → `{ path, entries:[{name,is_dir,size}] }`.
pub async fn web_host_list(path: &str) -> Result<serde_json::Value> {
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
    entries.sort_by(|a, b| {
        let ad = a["is_dir"].as_bool().unwrap_or(false);
        let bd = b["is_dir"].as_bool().unwrap_or(false);
        bd.cmp(&ad).then_with(|| {
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        })
    });
    Ok(serde_json::json!({ "path": dir, "entries": entries }))
}

/// Create a host directory (recursive).
pub async fn web_host_mkdir(path: &str) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

/// Delete a host path (file or directory), refusing protected system dirs.
pub async fn web_host_delete(path: &str) -> Result<()> {
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    let p = Path::new(path);
    if p.is_dir() {
        tokio::fs::remove_dir_all(path).await?;
    } else {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

/// Read a whole host file → (file name, bytes). Refuses directories.
pub async fn web_host_read(path: &str) -> Result<(String, Vec<u8>)> {
    let md = tokio::fs::metadata(path).await?;
    if md.is_dir() {
        return Err(anyhow!("不能下载目录"));
    }
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let bytes = tokio::fs::read(path).await?;
    Ok((name, bytes))
}

/// Write bytes to a host file (overwrite/create).
pub async fn web_host_write(path: &str, bytes: &[u8]) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("路径不能为空"));
    }
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

/// List a container directory → `{ path, entries:[{name,is_dir,size}] }`.
pub async fn web_ctn_list(container: &str, path: &str) -> Result<serde_json::Value> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    let dir = if path.trim().is_empty() { "/" } else { path };
    check_abs(dir)?;
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
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        })
    });
    Ok(serde_json::json!({ "path": dir, "entries": entries }))
}

/// Create a directory inside a container.
pub async fn web_ctn_mkdir(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    ctn_exec_ok(container, "mkdir -p \"$1\"", path).await
}

/// Delete a path inside a container (refusing protected system dirs).
pub async fn web_ctn_delete(container: &str, path: &str) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    if is_protected_path(path) {
        return Err(anyhow!("该系统目录受保护，禁止删除"));
    }
    ctn_exec_ok(container, "rm -rf \"$1\"", path).await
}

/// Read a whole file out of a container → (file name, bytes), via the archive
/// (tar) API. Buffers the file in memory (web console transfers are modest).
pub async fn web_ctn_read(container: &str, path: &str) -> Result<(String, Vec<u8>)> {
    use futures::StreamExt;

    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    check_abs(path)?;
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::DownloadFromContainerOptions {
        path: path.to_string(),
    };
    let mut stream = dkr.download_from_container(container, Some(opts));

    let mut header: Vec<u8> = Vec::with_capacity(512);
    let mut begun = false;
    let mut remaining: u64 = 0;
    let mut name = String::from("download");
    let mut content: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| anyhow!(friendly_archive_err(&e)))?;
        let mut data: &[u8] = &chunk;
        if !begun {
            let need = 512 - header.len();
            let take = need.min(data.len());
            header.extend_from_slice(&data[..take]);
            data = &data[take..];
            if header.len() < 512 {
                continue;
            }
            let (n, size) =
                parse_tar_header(&header).ok_or_else(|| anyhow!("不能下载目录或空文件"))?;
            if size == 0 {
                return Err(anyhow!("不能下载目录或空文件"));
            }
            name = n;
            remaining = size;
            begun = true;
        }
        if remaining > 0 && !data.is_empty() {
            let content_len = (remaining as usize).min(data.len());
            content.extend_from_slice(&data[..content_len]);
            remaining -= content_len as u64;
        }
        if begun && remaining == 0 {
            break;
        }
    }
    if !begun {
        return Err(anyhow!("文件不存在"));
    }
    Ok((name, content))
}

/// Write bytes into a container at `dest_path` (via a host temp file + the
/// archive API). Works on shell-less images.
pub async fn web_ctn_write(container: &str, dest_path: &str, bytes: &[u8]) -> Result<()> {
    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }
    check_abs(dest_path)?;
    let temp_path = std::env::temp_dir().join(format!("teaops-ctn-web-{}", unique_suffix()));
    tokio::fs::write(&temp_path, bytes).await?;
    let res = ctn_upload_file(container, &temp_path, dest_path).await;
    let _ = tokio::fs::remove_file(&temp_path).await;
    res
}

#[cfg(test)]
mod tests {
    use super::{is_protected_path, parse_tar_header, valid_container_ref};

    #[test]
    fn protected_paths() {
        assert!(is_protected_path("/"));
        assert!(is_protected_path(""));
        assert!(is_protected_path("/etc"));
        assert!(is_protected_path("/etc/"));
        assert!(is_protected_path("/usr"));
        assert!(is_protected_path("/var"));
        assert!(is_protected_path("  /bin  "));
        assert!(!is_protected_path("/etc/nginx"));
        assert!(!is_protected_path("/root/data")); // /root is protected, subdir isn't
        assert!(!is_protected_path("/home/user/file.txt"));
        assert!(!is_protected_path("/data"));
    }

    #[test]
    fn container_ref_validation() {
        assert!(valid_container_ref("my-app"));
        assert!(valid_container_ref("a1b2c3"));
        assert!(!valid_container_ref(""));
        assert!(!valid_container_ref("-rm"));
        assert!(!valid_container_ref("a b"));
    }

    #[test]
    fn tar_header_roundtrip() {
        // Build a real tar header with the `tar` crate, then parse it back.
        let mut h = tar::Header::new_gnu();
        h.set_size(1234);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::file());
        h.set_path("hello.txt").unwrap();
        h.set_cksum();
        let bytes = h.as_bytes();
        let (name, size) = parse_tar_header(bytes).expect("parse");
        assert_eq!(name, "hello.txt");
        assert_eq!(size, 1234);
    }

    #[test]
    fn tar_header_rejects_dir() {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Directory);
        h.set_path("adir/").unwrap();
        h.set_cksum();
        assert!(parse_tar_header(h.as_bytes()).is_none());
    }
}
