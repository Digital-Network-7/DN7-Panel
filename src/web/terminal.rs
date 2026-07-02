//! On-box terminal for the web console.
//!
//! Bridges an axum WebSocket (from the browser console) to a local PTY — the
//! host login shell (`run_web_pty`) or a `docker exec` shell inside a container
//! (`run_web_container_exec`). The browser is the client directly; there is no
//! backend relay.

use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use futures::{SinkExt, StreamExt};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::Deserialize;
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientFrame {
    Resize {
        cols: u16,
        rows: u16,
    },
    Data {
        data: String,
    },
    /// Latency probe from the client; echoed straight back as a pong carrying
    /// the same timestamp so the client can compute the full round-trip delay.
    Ping {
        t: i64,
    },
}

/// Reject container refs that could smuggle extra docker flags / shell tokens.
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

enum Frame {
    Resize { cols: u16, rows: u16 },
    Data(Vec<u8>),
    Ping(i64),
}

fn parse_frame(text: &str) -> Frame {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(frame) = serde_json::from_str::<ClientFrame>(trimmed) {
            return match frame {
                ClientFrame::Resize { cols, rows } => Frame::Resize {
                    cols: cols.clamp(1, 1000),
                    rows: rows.clamp(1, 1000),
                },
                ClientFrame::Data { data } => Frame::Data(data.into_bytes()),
                ClientFrame::Ping { t } => Frame::Ping(t),
            };
        }
    }
    Frame::Data(text.as_bytes().to_vec())
}

/// Bridge an **axum** WebSocket (from the local web console) to a host PTY
/// shell. Mirrors `run_pty` but speaks axum's `Message` type and has no
/// outbound backend connection — the browser is the client directly.
pub async fn run_web_pty(
    socket: axum::extract::ws::WebSocket,
    login_user: Option<String>,
) -> Result<()> {
    use axum::extract::ws::Message as AxumMsg;

    // Run as the mapped system user when set (non-admin panel users). Instead of
    // shelling out to `su -`, we re-exec ourselves as `__webshell <user>`, which
    // drops to that user in a fresh single-threaded process and execs their login
    // shell (the OS then enforces their privileges) — no external program. The
    // super-admin (None) gets the panel's own shell (root).
    let mut cmd = match &login_user {
        Some(user) => {
            let exe = std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "/proc/self/exe".to_string());
            let mut c = CommandBuilder::new(exe);
            c.arg("__webshell");
            c.arg(user);
            c
        }
        None => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            let mut c = CommandBuilder::new(&shell);
            c.arg("-i");
            c
        }
    };
    cmd.env("TERM", "xterm-256color");

    let (mut ws_tx, mut ws_rx) = socket.split();

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| anyhow!("openpty: {e}"))?;

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| anyhow!("spawn command: {e}"))?;
    drop(pair.slave);

    let mut writer = pair
        .master
        .take_writer()
        .map_err(|e| anyhow!("pty writer: {e}"))?;
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| anyhow!("pty reader: {e}"))?;
    let master = pair.master;

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    loop {
        tokio::select! {
            chunk = out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        if ws_tx.send(AxumMsg::Binary(bytes)).await.is_err() { break; }
                    }
                    None => break,
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(AxumMsg::Text(t))) => match parse_frame(&t) {
                        Frame::Resize { cols, rows } => {
                            let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
                        }
                        Frame::Data(bytes) => {
                            if writer.write_all(&bytes).is_err() { break; }
                            let _ = writer.flush();
                        }
                        Frame::Ping(t) => {
                            let pong = format!("{{\"type\":\"pong\",\"t\":{t}}}");
                            if ws_tx.send(AxumMsg::Text(pong)).await.is_err() { break; }
                        }
                    },
                    Some(Ok(AxumMsg::Binary(b))) => {
                        if writer.write_all(&b).is_err() { break; }
                        let _ = writer.flush();
                    }
                    Some(Ok(AxumMsg::Ping(_))) | Some(Ok(AxumMsg::Pong(_))) => {}
                    Some(Ok(AxumMsg::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }

    let _ = child.kill();
    let _ = ws_tx.close().await;
    Ok(())
}

/// Bridge an **axum** WebSocket (from the local web console) to a `docker exec`
/// shell **inside a container** via the daemon API (bollard). Mirrors
/// `run_container_exec` but speaks axum's `Message` type and has no outbound
/// backend connection — the browser is the client directly.
pub async fn run_web_container_exec(
    socket: axum::extract::ws::WebSocket,
    container: &str,
) -> Result<()> {
    use axum::extract::ws::Message as AxumMsg;
    use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecOptions, StartExecResults}; // arch-allow(arch-migration: ws-pty-bridge): 容器终端是 axum WS↔docker exec 的单一流式桥接,拆出 infra 适配器会切断 PTY 流且无法在本地运行期验证;待引入 typed 终端适配器时再迁

    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }

    // In-house runtime: bridge the WS to a dn7 PTY exec (Linux-only) instead of a
    // Docker exec; everything else falls through to the bollard path below.
    #[cfg(target_os = "linux")]
    if matches!(std::env::var("DN7_RUNTIME").as_deref(), Ok("dn7")) {
        return run_dn7_container_exec(socket, container).await;
    }

    let (mut ws_tx, mut ws_rx) = socket.split();

    let dkr = crate::infra::docker::dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdin: Some(true),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                tty: Some(true),
                env: Some(vec!["TERM=xterm-256color".to_string()]),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    // Adapt to whatever interactive shell the image ships, in
                    // order of preference: bash -> sh -> ash (busybox/alpine).
                    "for s in /bin/bash /bin/sh /bin/ash; do [ -x \"$s\" ] && exec \"$s\"; done; exec /bin/sh"
                        .to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("无法创建容器会话：{e}"))?;

    let started = dkr
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| anyhow!("无法启动容器会话：{e}"))?;

    let (mut output, mut input) = match started {
        StartExecResults::Attached { output, input } => (output, input),
        StartExecResults::Detached => return Err(anyhow!("容器会话未能附着")),
    };

    let exec_id = exec.id.clone();
    loop {
        tokio::select! {
            chunk = output.next() => {
                match chunk {
                    Some(Ok(out)) => {
                        let bytes = out.into_bytes();
                        if ws_tx.send(AxumMsg::Binary(bytes.to_vec())).await.is_err() { break; }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(AxumMsg::Text(t))) => match parse_frame(&t) {
                        Frame::Resize { cols, rows } => {
                            let _ = dkr.resize_exec(&exec_id, ResizeExecOptions {
                                height: rows, width: cols,
                            }).await;
                        }
                        Frame::Data(bytes) => {
                            use tokio::io::AsyncWriteExt;
                            if input.write_all(&bytes).await.is_err() { break; }
                            let _ = input.flush().await;
                        }
                        Frame::Ping(t) => {
                            let pong = format!("{{\"type\":\"pong\",\"t\":{t}}}");
                            if ws_tx.send(AxumMsg::Text(pong)).await.is_err() { break; }
                        }
                    },
                    Some(Ok(AxumMsg::Binary(b))) => {
                        use tokio::io::AsyncWriteExt;
                        if input.write_all(&b).await.is_err() { break; }
                        let _ = input.flush().await;
                    }
                    Some(Ok(AxumMsg::Ping(_))) | Some(Ok(AxumMsg::Pong(_))) => {}
                    Some(Ok(AxumMsg::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }

    let _ = ws_tx.close().await;
    Ok(())
}

/// Bridge a WebSocket to a dn7 PTY exec (the in-house runtime's web terminal).
/// Opens a PTY-backed shell inside the container's namespaces and shuttles bytes
/// both ways; `{"type":"resize"}` frames drive `TIOCSWINSZ`.
#[cfg(target_os = "linux")]
async fn run_dn7_container_exec(
    socket: axum::extract::ws::WebSocket,
    container: &str,
) -> Result<()> {
    use axum::extract::ws::Message as AxumMsg;
    use std::os::fd::AsRawFd;
    use tokio::io::unix::AsyncFd;

    let id = dn7_container::container::resolve(container)
        .map_err(|_| anyhow!("no such container: {container}"))?;
    // Prefer bash, then sh, then ash (busybox) — whatever the image ships.
    let shell = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "for s in /bin/bash /bin/sh /bin/ash; do [ -x \"$s\" ] && exec \"$s\"; done; exec /bin/sh"
            .to_string(),
    ];
    let mut session = dn7_container::container::exec_pty(&id, &shell)
        .map_err(|e| anyhow!("无法创建容器会话：{e}"))?;
    let mfd = session.master.as_raw_fd();
    // Non-blocking master so reads/writes integrate with the async readiness loop.
    // SAFETY: fcntl on our own fd.
    unsafe {
        let fl = libc::fcntl(mfd, libc::F_GETFL);
        libc::fcntl(mfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    let afd = AsyncFd::new(mfd).map_err(|e| anyhow!("{e}"))?;

    let (mut ws_tx, mut ws_rx) = socket.split();
    let mut buf = [0u8; 8192];
    loop {
        tokio::select! {
            r = afd.readable() => {
                let mut g = match r { Ok(g) => g, Err(_) => break };
                let read = g.try_io(|fd| {
                    // SAFETY: read into our stack buffer from the (valid) master fd.
                    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                    if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                });
                match read {
                    Ok(Ok(0)) | Ok(Err(_)) => break,          // EOF / read error
                    Ok(Ok(n)) => {
                        if ws_tx.send(AxumMsg::Binary(buf[..n].to_vec())).await.is_err() { break; }
                    }
                    Err(_would_block) => {}                    // readiness was spurious
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(AxumMsg::Text(t))) => match parse_frame(&t) {
                        Frame::Resize { cols, rows } => session.resize(cols, rows),
                        Frame::Data(bytes) => write_fd(mfd, &bytes),
                        Frame::Ping(t) => {
                            let pong = format!("{{\"type\":\"pong\",\"t\":{t}}}");
                            if ws_tx.send(AxumMsg::Text(pong)).await.is_err() { break; }
                        }
                    },
                    Some(Ok(AxumMsg::Binary(b))) => write_fd(mfd, &b),
                    Some(Ok(AxumMsg::Ping(_))) | Some(Ok(AxumMsg::Pong(_))) => {}
                    Some(Ok(AxumMsg::Close(_))) | None => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }
    session.kill();
    let _ = ws_tx.close().await;
    Ok(())
}

/// Best-effort write of (small, keystroke-sized) terminal input to the pty master.
#[cfg(target_os = "linux")]
fn write_fd(fd: std::os::fd::RawFd, buf: &[u8]) {
    // SAFETY: write our buffer to the (valid) master fd; partial writes of tiny
    // keystroke input don't occur in practice on a fresh pty.
    unsafe {
        let _ = libc::write(fd, buf.as_ptr().cast(), buf.len());
    }
}

#[cfg(test)]
mod tests {
    use super::valid_container_ref;

    #[test]
    fn container_ref_validation() {
        assert!(valid_container_ref("my-container"));
        assert!(valid_container_ref("a1b2c3d4e5f6"));
        assert!(valid_container_ref("registry.io/app:tag"));
        assert!(!valid_container_ref(""));
        assert!(!valid_container_ref("-rm"));
        assert!(!valid_container_ref("a b"));
        assert!(!valid_container_ref("a;ls"));
    }
}
