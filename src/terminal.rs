//! Agent-side terminal relay.
//!
//! When the backend pushes an `open-terminal` command, the agent dials back
//! `/agent/terminal?session=` (token in the `Authorization` header), opens a
//! local PTY running the user's login shell, and bridges it to the backend
//! WebSocket:
//!
//!   backend WS  <->  agent  <->  local PTY shell
//!
//! Because the agent connects *outbound*, this works for intranet / NAT'd
//! servers the backend can't reach directly. The wire protocol matches the
//! backend's direct-SSH terminal: client→agent Text frames carry
//! `{"type":"data"|"resize"}`, agent→client frames are raw PTY output (Binary).

use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientFrame {
    Resize { cols: u16, rows: u16 },
    Data { data: String },
    /// Latency probe from the client; echoed straight back as a pong carrying
    /// the same timestamp so the client can compute the full round-trip delay.
    Ping { t: i64 },
}

/// Open a PTY shell and relay it to the backend for `session`. Runs until either
/// side closes; errors are logged by the caller.
pub async fn run_terminal(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let mut cmd = CommandBuilder::new(&shell);
    cmd.arg("-i");
    cmd.env("TERM", "xterm-256color");
    run_pty(cfg, agent_token, session, cmd).await
}

/// Open a `docker exec` session **inside a container** via the daemon API
/// (bollard) and relay it to the backend for `session`. No `docker` CLI is
/// required — we attach to the exec instance's TTY stream directly. Tries bash,
/// falling back to sh, so it works on minimal images too. The container still
/// needs *some* shell; the UI hides the terminal button when it doesn't (see
/// `container_has_shell`).
pub async fn run_container_exec(
    cfg: &AgentConfig,
    agent_token: &str,
    session: &str,
    container: &str,
) -> Result<()> {
    use bollard::exec::{CreateExecOptions, ResizeExecOptions, StartExecOptions, StartExecResults};

    if !valid_container_ref(container) {
        return Err(anyhow!("invalid container reference"));
    }

    // Connect the backend relay WS.
    let url = cfg.agent_terminal_ws_url(session);
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

    let dkr = crate::docker::dkr()?;
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
                    "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"
                        .to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("无法创建容器会话：{e}"))?;

    let started = dkr
        .start_exec(&exec.id, Some(StartExecOptions { detach: false, ..Default::default() }))
        .await
        .map_err(|e| anyhow!("无法启动容器会话：{e}"))?;

    let (mut output, mut input) = match started {
        StartExecResults::Attached { output, input } => (output, input),
        StartExecResults::Detached => return Err(anyhow!("容器会话未能附着")),
    };

    let exec_id = exec.id.clone();
    loop {
        tokio::select! {
            // Container -> backend (raw bytes as binary frames).
            chunk = output.next() => {
                match chunk {
                    Some(Ok(out)) => {
                        let bytes = out.into_bytes();
                        if ws_tx.send(Message::Binary(bytes.to_vec())).await.is_err() { break; }
                    }
                    Some(Err(_)) | None => break, // exec ended
                }
            }
            // Backend -> container (control frames or raw stdin).
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        match parse_frame(&t) {
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
                                if ws_tx.send(Message::Text(pong)).await.is_err() { break; }
                            }
                        }
                    }
                    Some(Ok(Message::Binary(b))) => {
                        use tokio::io::AsyncWriteExt;
                        if input.write_all(&b).await.is_err() { break; }
                        let _ = input.flush().await;
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = ws_tx.close().await;
    Ok(())
}

/// Reject container refs that could smuggle extra docker flags / shell tokens.
fn valid_container_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('-')
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':'))
}

/// Shared PTY relay: spawn `cmd` in a PTY and bridge it to the backend WS for
/// `session`. Used by both the host shell and `docker exec` terminals.
async fn run_pty(
    cfg: &AgentConfig,
    agent_token: &str,
    session: &str,
    cmd: CommandBuilder,
) -> Result<()> {
    let url = cfg.agent_terminal_ws_url(session);
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

    // Spin up a PTY with the requested command.
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| anyhow!("openpty: {e}"))?;

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| anyhow!("spawn command: {e}"))?;
    // The slave is held by the child; drop our handle so EOF propagates on exit.
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

    // PTY output -> async channel via a blocking reader thread.
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
            // PTY -> backend (raw bytes as binary frames).
            chunk = out_rx.recv() => {
                match chunk {
                    Some(bytes) => {
                        if ws_tx.send(Message::Binary(bytes)).await.is_err() { break; }
                    }
                    None => break, // shell exited
                }
            }
            // Backend -> PTY (control frames or raw stdin).
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        match parse_frame(&t) {
                            Frame::Resize { cols, rows } => {
                                let _ = master.resize(PtySize {
                                    rows, cols, pixel_width: 0, pixel_height: 0,
                                });
                            }
                            Frame::Data(bytes) => {
                                if writer.write_all(&bytes).is_err() { break; }
                                let _ = writer.flush();
                            }
                            Frame::Ping(t) => {
                                // Echo a pong (same timestamp) so the client can
                                // measure the miniapp↔backend↔agent round-trip.
                                let pong = format!("{{\"type\":\"pong\",\"t\":{t}}}");
                                if ws_tx.send(Message::Text(pong)).await.is_err() { break; }
                            }
                        }
                    }
                    Some(Ok(Message::Binary(b))) => {
                        if writer.write_all(&b).is_err() { break; }
                        let _ = writer.flush();
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {}
                }
            }
        }
    }

    // Best-effort cleanup.
    let _ = child.kill();
    let _ = ws_tx.close().await;
    Ok(())
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
