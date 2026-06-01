//! Agent-side Docker management.
//!
//! When the backend pushes an `open-docker` command, the agent dials back
//! `/agent/docker?session=` (token in the Authorization header) and serves a
//! request/response JSON protocol backed by the local `docker` CLI:
//!
//!   backend WS  <->  agent  <->  local `docker` CLI
//!
//! Every request carries an `id` echoed back in its response. Operations are a
//! fixed whitelist (no arbitrary command pass-through); user-supplied values
//! (image names, container ids, ...) are passed as separate argv entries to
//! `docker`, never interpolated into a shell, so there's no injection surface.
//!
//! Requests (client -> agent):
//!   {"id","op":"info"}
//!   {"id","op":"install"}
//!   {"id","op":"list_images"}
//!   {"id","op":"pull_image","image":"nginx:latest","mirror":"m.daocloud.io"?}
//!   {"id","op":"remove_image","ref":"<id|repo:tag>"}
//!   {"id","op":"list_containers"}
//!   {"id","op":"start_container"|"stop_container"|"restart_container"|"remove_container","ref":"<cid>"}
//!   {"id","op":"logs","ref":"<cid>","tail":200?}
//!   {"id","op":"list_networks"}
//!   {"id","op":"remove_network","ref":"<nid>"}
//! Responses (agent -> client):
//!   {"id","ok":true,"data":<json>}
//!   {"id","ok":false,"error":"..."}
//!   {"event":"progress","id":<id>,"line":"..."}   (during pull/install)

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::process::Command;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

#[derive(Debug, Deserialize)]
struct Req {
    #[serde(default)]
    id: i64,
    op: String,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    mirror: Option<String>,
    #[serde(default, rename = "ref")]
    reference: Option<String>,
    #[serde(default)]
    tail: Option<i64>,
}

/// Connect to the backend docker relay and serve the protocol until either side
/// closes.
pub async fn run_docker_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_docker_ws_url(session);
    let mut request = url
        .into_client_request()
        .map_err(|e| anyhow!("bad ws url: {e}"))?;
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {agent_token}")
            .parse()
            .map_err(|e| anyhow!("bad auth header: {e}"))?,
    );
    let (ws, _resp) = connect_async(request).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(t)) => {
                let req: Req = match serde_json::from_str(&t) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = ws_tx
                            .send(Message::Text(
                                json!({ "ok": false, "error": format!("bad request: {e}") }).to_string(),
                            ))
                            .await;
                        continue;
                    }
                };
                let id = req.id;
                // Ops that stream progress need the sink during execution.
                if req.op == "pull_image" || req.op == "install" {
                    let res = if req.op == "install" {
                        install_docker(&mut ws_tx, id).await
                    } else {
                        pull_image(&mut ws_tx, id, &req).await
                    };
                    let frame = match res {
                        Ok(data) => json!({ "id": id, "ok": true, "data": data }),
                        Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
                    };
                    if ws_tx.send(Message::Text(frame.to_string())).await.is_err() {
                        break;
                    }
                    continue;
                }
                // Simple request/response ops.
                let frame = match handle(&req).await {
                    Ok(data) => json!({ "id": id, "ok": true, "data": data }),
                    Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
                };
                if ws_tx.send(Message::Text(frame.to_string())).await.is_err() {
                    break;
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

/// Dispatch a non-streaming op.
async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => docker_info().await,
        "list_images" => list_images().await,
        "remove_image" => {
            let r = need_ref(req)?;
            run_ok(&["rmi", "-f", &r]).await?;
            Ok(json!({ "removed": r }))
        }
        "list_containers" => list_containers().await,
        "start_container" => {
            let r = need_ref(req)?;
            run_ok(&["start", &r]).await?;
            Ok(json!({ "started": r }))
        }
        "stop_container" => {
            let r = need_ref(req)?;
            run_ok(&["stop", &r]).await?;
            Ok(json!({ "stopped": r }))
        }
        "restart_container" => {
            let r = need_ref(req)?;
            run_ok(&["restart", &r]).await?;
            Ok(json!({ "restarted": r }))
        }
        "remove_container" => {
            let r = need_ref(req)?;
            run_ok(&["rm", "-f", &r]).await?;
            Ok(json!({ "removed": r }))
        }
        "logs" => container_logs(req).await,
        "list_networks" => list_networks().await,
        "remove_network" => {
            let r = need_ref(req)?;
            run_ok(&["network", "rm", &r]).await?;
            Ok(json!({ "removed": r }))
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

fn need_ref(req: &Req) -> Result<String> {
    let r = req
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing ref"))?;
    validate_token(r)?;
    Ok(r.to_string())
}

/// Reject values that don't look like a plausible docker id / name / ref so a
/// crafted value can't smuggle extra `docker` flags. Allows the characters that
/// appear in image refs (registry/name:tag@sha256:...), container names and ids.
fn validate_token(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 256 {
        return Err(anyhow!("invalid reference"));
    }
    if s.starts_with('-') {
        return Err(anyhow!("invalid reference"));
    }
    let ok = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@')
    });
    if !ok {
        return Err(anyhow!("invalid reference"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// docker command helpers
// ---------------------------------------------------------------------------

/// Run `docker <args...>` and return (success, stdout, stderr).
async fn run(args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("无法执行 docker：{e}（请确认已安装并在 PATH 中）"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

/// Run a docker command, erroring (with stderr) on non-zero exit.
async fn run_ok(args: &[&str]) -> Result<String> {
    let (ok, stdout, stderr) = run(args).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&stderr).unwrap_or_else(|| "命令执行失败".into())));
    }
    Ok(stdout)
}

/// Keep an error message bounded and non-empty.
fn trim_msg(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let s: String = s.chars().take(500).collect();
    Some(s)
}

/// Detect docker (and compose) presence + versions. Never errors: a missing
/// docker is reported as `installed:false` so the UI can offer to install it.
async fn docker_info() -> Result<Value> {
    // Server + client version via a stable format. Falls back gracefully.
    let (ok, stdout, _) = run(&[
        "version",
        "--format",
        "{{.Server.Version}}|{{.Client.Version}}",
    ])
    .await
    .unwrap_or((false, String::new(), String::new()));

    if !ok {
        // `docker` may exist but the daemon isn't running, or it's absent.
        let present = Command::new("docker").arg("--version").output().await.is_ok();
        return Ok(json!({
            "installed": false,
            "daemon_running": false,
            "docker_present": present,
        }));
    }

    let line = stdout.trim();
    let mut parts = line.split('|');
    let server_version = parts.next().unwrap_or("").trim().to_string();
    let client_version = parts.next().unwrap_or("").trim().to_string();

    // Compose plugin version (optional).
    let compose_version = run(&["compose", "version", "--short"])
        .await
        .ok()
        .filter(|(ok, _, _)| *ok)
        .map(|(_, o, _)| o.trim().to_string())
        .unwrap_or_default();

    Ok(json!({
        "installed": !server_version.is_empty(),
        "daemon_running": !server_version.is_empty(),
        "docker_present": true,
        "server_version": server_version,
        "client_version": client_version,
        "compose_version": compose_version,
    }))
}

/// List images: id, repo:tag, size, created.
async fn list_images() -> Result<Value> {
    let fmt = "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}";
    let stdout = run_ok(&["images", "--format", fmt]).await?;
    let mut items = Vec::new();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            continue;
        }
        let repo = f[1];
        let tag = f[2];
        let name = if repo == "<none>" {
            f[0].to_string()
        } else if tag == "<none>" {
            repo.to_string()
        } else {
            format!("{repo}:{tag}")
        };
        items.push(json!({
            "id": f[0],
            "name": name,
            "repo": repo,
            "tag": tag,
            "size": f[3],
            "created": f[4],
        }));
    }
    Ok(json!({ "images": items }))
}

/// List containers (all states): id, name, image, state, status, ports.
async fn list_containers() -> Result<Value> {
    let fmt = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.Ports}}";
    let stdout = run_ok(&["ps", "-a", "--format", fmt]).await?;
    let mut items = Vec::new();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 {
            continue;
        }
        items.push(json!({
            "id": f[0],
            "name": f[1],
            "image": f[2],
            "state": f[3],
            "status": f[4],
            "ports": f.get(5).copied().unwrap_or(""),
        }));
    }
    Ok(json!({ "containers": items }))
}

/// Tail a container's logs.
async fn container_logs(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let tail = req.tail.unwrap_or(200).clamp(1, 2000).to_string();
    // Merge stdout+stderr; logs go to stderr for many images.
    let (ok, stdout, stderr) = run(&["logs", "--tail", &tail, &r]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&stderr).unwrap_or_else(|| "无法获取日志".into())));
    }
    let mut text = stdout;
    if !stderr.trim().is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    Ok(json!({ "logs": text }))
}

/// List networks: id, name, driver, scope.
async fn list_networks() -> Result<Value> {
    let fmt = "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}";
    let stdout = run_ok(&["network", "ls", "--format", fmt]).await?;
    let mut items = Vec::new();
    for line in stdout.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 {
            continue;
        }
        items.push(json!({
            "id": f[0],
            "name": f[1],
            "driver": f[2],
            "scope": f[3],
        }));
    }
    Ok(json!({ "networks": items }))
}

// ---------------------------------------------------------------------------
// streaming ops: pull (with optional mirror + rename) and install
// ---------------------------------------------------------------------------

type Sink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>;

/// Send a progress line to the client (best-effort).
async fn progress(tx: &mut Sink, id: i64, line: &str) {
    let _ = tx
        .send(Message::Text(
            json!({ "event": "progress", "id": id, "line": line }).to_string(),
        ))
        .await;
}

/// Allowed mirror hosts for accelerated pulls. The image is pulled as
/// `<mirror>/docker.io/<image>` then re-tagged to the clean `<image>` so the
/// user only ever sees standard names. An empty/None mirror pulls directly.
fn mirror_allowed(host: &str) -> bool {
    const ALLOWED: &[&str] = &[
        "m.daocloud.io",
        "docker.m.daocloud.io",
        "dockerproxy.com",
        "docker.1panel.live",
        "hub.rat.dev",
        "mirror.ccs.tencentyun.com",
        "registry.cn-hangzhou.aliyuncs.com",
    ];
    ALLOWED.contains(&host)
}

/// Normalize a user image ref to its docker.io form for mirror prefixing.
/// `nginx` -> `docker.io/library/nginx:latest`, `user/app:1` ->
/// `docker.io/user/app:1`. Refs already carrying a registry host are returned
/// unchanged (we can't safely mirror those through docker.io).
fn docker_io_path(image: &str) -> Option<String> {
    // A leading registry host is only present when there's a '/' and the first
    // segment looks like a host: it contains a '.' or a ':' (host:port), or is
    // "localhost". Without a '/', the whole thing is a bare repo (any ':' is a
    // tag, e.g. "nginx:1.25"), so it's NOT qualified.
    let has_slash = image.contains('/');
    let first = image.split('/').next().unwrap_or("");
    let qualified = has_slash
        && (first.contains('.') || first.contains(':') || first == "localhost");
    if qualified {
        return None;
    }
    let with_tag = with_default_tag(image);
    if has_slash {
        Some(format!("docker.io/{with_tag}"))
    } else {
        Some(format!("docker.io/library/{with_tag}"))
    }
}

/// Ensure the final ref has a tag (defaults to :latest), for the rename step.
fn with_default_tag(image: &str) -> String {
    // Don't add a tag if a digest is pinned.
    if image.contains('@') {
        return image.to_string();
    }
    // A ':' after the last '/' is a tag; otherwise append :latest.
    let last_seg = image.rsplit('/').next().unwrap_or(image);
    if last_seg.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    }
}

/// Pull an image, optionally via an accelerated mirror, streaming progress.
async fn pull_image(tx: &mut Sink, id: i64, req: &Req) -> Result<Value> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?;
    validate_token(image)?;

    let mirror = req.mirror.as_deref().map(str::trim).filter(|s| !s.is_empty());

    // Decide the actual pull source and whether a rename is needed afterwards.
    let (pull_ref, final_ref) = match mirror {
        Some(host) => {
            if !mirror_allowed(host) {
                return Err(anyhow!("不支持的加速镜像源"));
            }
            match docker_io_path(image) {
                Some(path) => (format!("{host}/{path}"), Some(with_default_tag(image))),
                // Already a fully-qualified ref: pull as-is, no rename.
                None => (image.to_string(), None),
            }
        }
        None => (image.to_string(), None),
    };

    progress(tx, id, &format!("正在拉取 {pull_ref} …")).await;
    stream_pull(tx, id, &pull_ref).await?;

    // Re-tag to the clean name and drop the mirror-prefixed tag.
    if let Some(final_ref) = final_ref.as_deref() {
        if final_ref != pull_ref {
            progress(tx, id, &format!("重命名为 {final_ref}")).await;
            run_ok(&["tag", &pull_ref, final_ref]).await?;
            let _ = run(&["rmi", &pull_ref]).await; // best-effort cleanup
        }
    }

    let shown = final_ref.unwrap_or(pull_ref);
    progress(tx, id, "完成").await;
    Ok(json!({ "image": shown }))
}

/// Run `docker pull <ref>` streaming stdout lines as progress events.
async fn stream_pull(tx: &mut Sink, id: i64, pull_ref: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use std::process::Stdio;

    let mut child = Command::new("docker")
        .args(["pull", pull_ref])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 docker pull：{e}"))?;

    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let l = line.trim();
            if !l.is_empty() {
                progress(tx, id, l).await;
            }
        }
    }
    let status = child.wait().await.map_err(|e| anyhow!("docker pull 失败：{e}"))?;
    if !status.success() {
        // Surface stderr tail for diagnosis.
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = e.read_to_string(&mut err).await;
        }
        return Err(anyhow!(trim_msg(&err).unwrap_or_else(|| "拉取失败".into())));
    }
    Ok(())
}

/// Auto-install Docker using the official convenience script with the Aliyun
/// mirror (fast in mainland China), then configure registry mirrors in
/// daemon.json and restart the daemon. Streams progress. Requires root.
async fn install_docker(tx: &mut Sink, id: i64) -> Result<Value> {
    // Already installed? Then this is a no-op success.
    if let Ok(info) = docker_info().await {
        if info.get("installed").and_then(Value::as_bool) == Some(true) {
            return Ok(json!({ "already_installed": true }));
        }
    }

    if !is_root() {
        return Err(anyhow!("安装 Docker 需要 root 权限，请用 root 运行 Agent 后重试"));
    }

    progress(tx, id, "下载 Docker 安装脚本（get.docker.com，阿里云镜像）…").await;
    // Pipe the official script and run with --mirror Aliyun. We fetch then pipe
    // to sh so the mirror flag applies to the package download too.
    let script = "set -e; \
        if command -v curl >/dev/null 2>&1; then \
          curl -fsSL https://get.docker.com -o /tmp/teaops-get-docker.sh; \
        elif command -v wget >/dev/null 2>&1; then \
          wget -qO /tmp/teaops-get-docker.sh https://get.docker.com; \
        else echo 'no curl/wget' >&2; exit 1; fi; \
        sh /tmp/teaops-get-docker.sh --mirror Aliyun; \
        rm -f /tmp/teaops-get-docker.sh";
    stream_shell(tx, id, script).await?;

    // Configure registry mirrors (Aliyun/DaoCloud/Tencent public) in daemon.json
    // for fast pulls, then restart docker. Best-effort.
    progress(tx, id, "配置国内镜像加速并重启 Docker …").await;
    let conf = r#"set -e; mkdir -p /etc/docker; cat > /etc/docker/daemon.json <<'JSON'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://mirror.ccs.tencentyun.com"
  ]
}
JSON
systemctl daemon-reload 2>/dev/null || true
systemctl enable docker 2>/dev/null || true
systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || true"#;
    let _ = stream_shell(tx, id, conf).await;

    progress(tx, id, "校验安装结果 …").await;
    let info = docker_info().await?;
    if info.get("installed").and_then(Value::as_bool) == Some(true) {
        Ok(info)
    } else {
        Err(anyhow!("安装完成但 Docker 守护进程未就绪，请检查系统日志"))
    }
}

/// Run a shell script streaming its combined output as progress lines. Used by
/// install only (the script itself is a fixed constant — no user input).
async fn stream_shell(tx: &mut Sink, id: i64, script: &str) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use std::process::Stdio;

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行安装脚本：{e}"))?;

    // Stream stdout.
    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let l = line.trim();
            if !l.is_empty() {
                progress(tx, id, l).await;
            }
        }
    }
    let status = child.wait().await.map_err(|e| anyhow!("安装脚本失败：{e}"))?;
    // Drain stderr tail for diagnostics regardless of status.
    if let Some(mut e) = child.stderr.take() {
        use tokio::io::AsyncReadExt;
        let mut err = String::new();
        let _ = e.read_to_string(&mut err).await;
        for line in err.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev() {
            let l = line.trim();
            if !l.is_empty() {
                progress(tx, id, l).await;
            }
        }
    }
    if !status.success() {
        return Err(anyhow!("安装脚本返回非零退出码"));
    }
    Ok(())
}

#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: getuid is always safe.
    unsafe { libc_getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_refs() {
        assert!(validate_token("nginx:latest").is_ok());
        assert!(validate_token("user/app:1.2.3").is_ok());
        assert!(validate_token("m.daocloud.io/docker.io/nginx").is_ok());
        assert!(validate_token("sha256:abc123").is_ok());
        // injection-ish inputs are rejected
        assert!(validate_token("-v").is_err());
        assert!(validate_token("a; rm -rf /").is_err());
        assert!(validate_token("a b").is_err());
        assert!(validate_token("").is_err());
    }

    #[test]
    fn docker_io_path_qualifies() {
        assert_eq!(docker_io_path("nginx"), Some("docker.io/library/nginx:latest".into()));
        assert_eq!(docker_io_path("nginx:1.25"), Some("docker.io/library/nginx:1.25".into()));
        assert_eq!(docker_io_path("user/app"), Some("docker.io/user/app:latest".into()));
        // already-qualified registry refs are left alone (not mirrored)
        assert_eq!(docker_io_path("gcr.io/foo/bar"), None);
        assert_eq!(docker_io_path("localhost:5000/x"), None);
    }

    #[test]
    fn default_tag() {
        assert_eq!(with_default_tag("nginx"), "nginx:latest");
        assert_eq!(with_default_tag("nginx:1.25"), "nginx:1.25");
        assert_eq!(with_default_tag("user/app"), "user/app:latest");
        assert_eq!(with_default_tag("img@sha256:abc"), "img@sha256:abc");
    }

    #[test]
    fn mirror_whitelist() {
        assert!(mirror_allowed("m.daocloud.io"));
        assert!(!mirror_allowed("evil.example.com"));
    }
}
