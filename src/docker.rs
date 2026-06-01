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
//! Long-running operations (image pulls, Docker install) run **detached** in a
//! process-global registry, so they keep running even if the client leaves the
//! page and the WebSocket drops. The client starts one (`pull_image`/`install`,
//! which return an `op_id` immediately) and then polls `list_ops` / `op_log` to
//! watch progress and pick up the result when it reconnects.
//!
//! Requests (client -> agent):
//!   {"id","op":"info"}
//!   {"id","op":"install"}                       -> {op_id} (detached)
//!   {"id","op":"list_images"}
//!   {"id","op":"pull_image","image","mirror"?}  -> {op_id} (detached)
//!   {"id","op":"create_container", ...}          -> {op_id} (detached)
//!   {"id","op":"remove_image","ref"}
//!   {"id","op":"list_containers"}
//!   {"id","op":"start_container"|"stop_container"|"restart_container"|"remove_container","ref"}
//!   {"id","op":"logs","ref","tail"?}
//!   {"id","op":"list_networks"}
//!   {"id","op":"create_network","name"}
//!   {"id","op":"remove_network","ref"}
//!   {"id","op":"inspect_container_networks","ref"}      -> {attached,available}
//!   {"id","op":"connect_network","ref","network"}
//!   {"id","op":"disconnect_network","ref","network"}
//!   {"id","op":"list_ops"}                       -> running/finished operations
//!   {"id","op":"op_log","op_id"}                 -> a single op's progress lines
//!   {"id","op":"dismiss_op","op_id"}             -> forget a finished op
//! Responses (agent -> client): {"id","ok":true,"data":<json>} / {"id","ok":false,"error":".."}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
    #[serde(default)]
    op_id: Option<String>,
    // create_container fields
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ports: Option<Vec<PortMap>>,
    #[serde(default)]
    env: Option<Vec<String>>,
    #[serde(default)]
    volumes: Option<Vec<VolumeMap>>,
    #[serde(default)]
    restart: Option<String>,
    #[serde(default)]
    start: Option<bool>,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct PortMap {
    host: i64,
    container: i64,
    #[serde(default)]
    proto: Option<String>, // "tcp" | "udp", default tcp
}

#[derive(Debug, Deserialize, Clone)]
struct VolumeMap {
    host: String,
    container: String,
    #[serde(default)]
    readonly: bool,
}

// ---------------------------------------------------------------------------
// Detached operation registry (pulls + install). Process-global so an op keeps
// running across client reconnects.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct OpState {
    kind: String,         // "pull" | "install" | "create"
    target: String,       // image name (pull) or "docker" (install) or container name (create)
    status: String,       // "running" | "done" | "error"
    error: String,        // populated when status == "error"
    result_image: String, // final clean image name on a successful pull
    lines: Vec<String>,   // progress tail (bounded)
}

fn ops() -> &'static Mutex<HashMap<String, OpState>> {
    static OPS: OnceLock<Mutex<HashMap<String, OpState>>> = OnceLock::new();
    OPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn new_op_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("op{}", N.fetch_add(1, Ordering::Relaxed))
}

fn op_create(op_id: &str, kind: &str, target: &str) {
    if let Ok(mut m) = ops().lock() {
        m.insert(
            op_id.to_string(),
            OpState {
                kind: kind.to_string(),
                target: target.to_string(),
                status: "running".to_string(),
                error: String::new(),
                result_image: String::new(),
                lines: Vec::new(),
            },
        );
    }
}

fn op_push(op_id: &str, line: &str) {
    if line.is_empty() {
        return;
    }
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.lines.push(line.to_string());
            // Keep only the recent tail so a long pull can't grow unbounded.
            let len = o.lines.len();
            if len > 400 {
                o.lines.drain(0..len - 400);
            }
        }
    }
}

fn op_finish(op_id: &str, status: &str, error: &str, result_image: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.status = status.to_string();
            o.error = error.to_string();
            o.result_image = result_image.to_string();
        }
    }
}

/// Snapshot of all operations (without the full log) for `list_ops`.
fn ops_snapshot() -> Value {
    let m = match ops().lock() {
        Ok(m) => m,
        Err(_) => return json!({ "ops": [] }),
    };
    let list: Vec<Value> = m
        .iter()
        .map(|(id, o)| {
            json!({
                "op_id": id,
                "kind": o.kind,
                "target": o.target,
                "status": o.status,
                "error": o.error,
                "result_image": o.result_image,
                // The latest line gives the list a one-line progress hint.
                "last_line": o.lines.last().cloned().unwrap_or_default(),
            })
        })
        .collect();
    json!({ "ops": list })
}

fn op_log(op_id: &str) -> Value {
    let m = match ops().lock() {
        Ok(m) => m,
        Err(_) => return json!({ "lines": [], "status": "error", "error": "lock" }),
    };
    match m.get(op_id) {
        Some(o) => json!({
            "lines": o.lines,
            "status": o.status,
            "error": o.error,
            "result_image": o.result_image,
            "kind": o.kind,
            "target": o.target,
        }),
        None => json!({ "lines": [], "status": "gone", "error": "" }),
    }
}

fn op_dismiss(op_id: &str) {
    if let Ok(mut m) = ops().lock() {
        m.remove(op_id);
    }
}

/// Connect to the backend docker relay and serve the protocol until either side
/// closes. The connection is stateless: long ops live in the global registry.
pub async fn run_docker_channel(_cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = _cfg.agent_docker_ws_url(session);
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

/// Dispatch one request. Long ops (`pull_image`, `install`) start a detached
/// task and return an `op_id` immediately.
async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => docker_info().await,
        "list_images" => list_images().await,
        "pull_image" => start_pull(req),
        "create_container" => start_create(req),
        "install" => start_install(),
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => {
            let op_id = req.op_id.as_deref().unwrap_or("");
            Ok(op_log(op_id))
        }
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
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
        "create_network" => {
            let name = req
                .name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("缺少网络名"))?;
            validate_name(name)?;
            run_ok(&["network", "create", name]).await?;
            Ok(json!({ "created": name }))
        }
        "remove_network" => {
            let r = need_ref(req)?;
            run_ok(&["network", "rm", &r]).await?;
            Ok(json!({ "removed": r }))
        }
        "inspect_container_networks" => inspect_container_networks(req).await,
        "connect_network" => {
            let r = need_ref(req)?;
            let net = need_network(req)?;
            run_ok(&["network", "connect", &net, &r]).await?;
            Ok(json!({ "connected": net }))
        }
        "disconnect_network" => {
            let r = need_ref(req)?;
            let net = need_network(req)?;
            run_ok(&["network", "disconnect", &net, &r]).await?;
            Ok(json!({ "disconnected": net }))
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

/// Resolve + validate the `network` field (used by connect/disconnect).
fn need_network(req: &Req) -> Result<String> {
    let n = req
        .network
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("缺少网络名"))?;
    validate_token(n)?;
    Ok(n.to_string())
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
    let (ok, stdout, _) = run(&[
        "version",
        "--format",
        "{{.Server.Version}}|{{.Client.Version}}",
    ])
    .await
    .unwrap_or((false, String::new(), String::new()));

    if !ok {
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

/// For one container, report the networks it's attached to and the networks it
/// could still be connected to (so the UI can offer connect/disconnect).
/// Predefined networks (`host`, `none`) aren't offered as attach targets and
/// the predefined ones can't be disconnected when they're the only one — the
/// UI surfaces the agent's docker error in that case rather than guessing.
async fn inspect_container_networks(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    // Networks the container is currently on.
    let fmt = "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}\n{{end}}";
    let stdout = run_ok(&["inspect", "-f", fmt, &r]).await?;
    let attached: Vec<String> = stdout
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // All networks (to compute the "available to connect" set).
    let all = list_networks().await?;
    let mut available = Vec::new();
    if let Some(arr) = all.get("networks").and_then(Value::as_array) {
        for n in arr {
            let name = n.get("name").and_then(Value::as_str).unwrap_or("");
            // Skip ones it's already on and the special "none"/"host" drivers
            // (you don't hot-attach those at runtime).
            if name.is_empty() || attached.iter().any(|a| a == name) {
                continue;
            }
            if name == "none" || name == "host" {
                continue;
            }
            available.push(json!({ "name": name }));
        }
    }

    Ok(json!({ "attached": attached, "available": available }))
}

// ---------------------------------------------------------------------------
// Detached pull
// ---------------------------------------------------------------------------

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
fn docker_io_path(image: &str) -> Option<String> {
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
    if image.contains('@') {
        return image.to_string();
    }
    let last_seg = image.rsplit('/').next().unwrap_or(image);
    if last_seg.contains(':') {
        image.to_string()
    } else {
        format!("{image}:latest")
    }
}

/// Validate + resolve the pull, register a detached op, spawn it, return op_id.
fn start_pull(req: &Req) -> Result<Value> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    let mirror = req.mirror.as_deref().map(str::trim).filter(|s| !s.is_empty());

    // Decide the actual pull source and whether a rename is needed afterwards.
    let (pull_ref, final_ref) = match mirror {
        Some(host) => {
            if !mirror_allowed(host) {
                return Err(anyhow!("不支持的加速镜像源"));
            }
            match docker_io_path(&image) {
                Some(path) => (format!("{host}/{path}"), Some(with_default_tag(&image))),
                None => (image.clone(), None),
            }
        }
        None => (image.clone(), None),
    };

    let shown = final_ref.clone().unwrap_or_else(|| with_default_tag(&image));
    let op_id = new_op_id();
    op_create(&op_id, "pull", &shown);

    let op_id_t = op_id.clone();
    let shown_t = shown.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, &format!("正在拉取 {pull_ref} …"));
        match run_pull_detached(&op_id_t, &pull_ref).await {
            Ok(()) => {
                if let Some(final_ref) = final_ref.as_deref() {
                    if final_ref != pull_ref {
                        op_push(&op_id_t, &format!("重命名为 {final_ref}"));
                        if let Err(e) = run_ok(&["tag", &pull_ref, final_ref]).await {
                            op_finish(&op_id_t, "error", &e.to_string(), "");
                            return;
                        }
                        let _ = run(&["rmi", &pull_ref]).await; // best-effort
                    }
                }
                op_push(&op_id_t, "完成");
                op_finish(&op_id_t, "done", "", &shown_t);
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": shown }))
}

/// Run `docker pull <ref>`, pushing each output line into the op registry.
async fn run_pull_detached(op_id: &str, pull_ref: &str) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut child = Command::new("docker")
        .args(["pull", pull_ref])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 docker pull：{e}"))?;

    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child.wait().await.map_err(|e| anyhow!("docker pull 失败：{e}"))?;
    if !status.success() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err).await;
        }
        return Err(anyhow!(trim_msg(&err).unwrap_or_else(|| "拉取失败".into())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Detached create container
// ---------------------------------------------------------------------------

/// Whitelisted restart policies.
fn restart_allowed(p: &str) -> bool {
    matches!(p, "no" | "unless-stopped" | "always")
}

/// Validate a container name: docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]+.
fn validate_name(s: &str) -> Result<()> {
    if s.len() > 128 {
        return Err(anyhow!("容器名过长"));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok || s.starts_with('-') {
        return Err(anyhow!("容器名只能包含字母、数字、_ . -"));
    }
    Ok(())
}

/// Validate a host filesystem path (no shell metacharacters; must be absolute).
fn validate_path(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 1024 || !s.starts_with('/') {
        return Err(anyhow!("路径必须为绝对路径"));
    }
    // Disallow characters that could break out of a single argv entry or look
    // like injection; container/host paths in practice don't need them.
    let bad = s.chars().any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '"' | '\'' | '\\' | '<' | '>' | '*'));
    if bad {
        return Err(anyhow!("路径包含非法字符"));
    }
    Ok(())
}

/// Validate an env var entry "KEY=VALUE". KEY must be a valid identifier; VALUE
/// is taken verbatim (it's a separate argv entry, so no shell interpretation),
/// but we still reject newlines.
fn validate_env(s: &str) -> Result<()> {
    if s.len() > 4096 {
        return Err(anyhow!("环境变量过长"));
    }
    let (k, _v) = s.split_once('=').ok_or_else(|| anyhow!("环境变量需为 KEY=VALUE 格式"))?;
    if k.is_empty() {
        return Err(anyhow!("环境变量名不能为空"));
    }
    let key_ok = k.chars().enumerate().all(|(i, c)| {
        c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
    });
    if !key_ok {
        return Err(anyhow!("环境变量名只能包含字母、数字、下划线，且不以数字开头"));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(anyhow!("环境变量包含非法字符"));
    }
    Ok(())
}

/// Build the `docker run` argv from a validated request. Returns the args plus
/// the resolved (or empty) container name for display.
fn build_run_args(req: &Req) -> Result<(Vec<String>, String)> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    let mut args: Vec<String> = vec!["run".into(), "-d".into()];

    // Name (optional).
    let mut display_name = String::new();
    if let Some(n) = req.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_name(n)?;
        args.push("--name".into());
        args.push(n.to_string());
        display_name = n.to_string();
    }

    // Restart policy (whitelisted; default unless-stopped).
    let restart = req
        .restart
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unless-stopped");
    if !restart_allowed(restart) {
        return Err(anyhow!("不支持的重启策略"));
    }
    args.push("--restart".into());
    args.push(restart.to_string());

    // Network (optional; must be an existing network). Empty => default bridge.
    if let Some(net) = req.network.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_token(net)?;
        args.push("--network".into());
        args.push(net.to_string());
    }

    // Port mappings.
    if let Some(ports) = &req.ports {
        if ports.len() > 50 {
            return Err(anyhow!("端口映射过多"));
        }
        for p in ports {
            if p.host < 1 || p.host > 65535 || p.container < 1 || p.container > 65535 {
                return Err(anyhow!("端口需为 1-65535"));
            }
            let proto = p.proto.as_deref().unwrap_or("tcp");
            if proto != "tcp" && proto != "udp" {
                return Err(anyhow!("协议只能是 tcp 或 udp"));
            }
            args.push("-p".into());
            args.push(format!("{}:{}/{}", p.host, p.container, proto));
        }
    }

    // Environment variables.
    if let Some(envs) = &req.env {
        if envs.len() > 100 {
            return Err(anyhow!("环境变量过多"));
        }
        for e in envs {
            let e = e.trim();
            if e.is_empty() {
                continue;
            }
            validate_env(e)?;
            args.push("-e".into());
            args.push(e.to_string());
        }
    }

    // Volume mounts.
    if let Some(vols) = &req.volumes {
        if vols.len() > 50 {
            return Err(anyhow!("挂载过多"));
        }
        for v in vols {
            let host = v.host.trim();
            let container = v.container.trim();
            validate_path(host)?;
            validate_path(container)?;
            let spec = if v.readonly {
                format!("{host}:{container}:ro")
            } else {
                format!("{host}:{container}")
            };
            args.push("-v".into());
            args.push(spec);
        }
    }

    args.push(image);
    Ok((args, display_name))
}

/// Validate the request, register a detached op, run `docker run -d`, and (if
/// not starting) immediately stop the container. Returns an op_id.
fn start_create(req: &Req) -> Result<Value> {
    let (args, display_name) = build_run_args(req)?;
    let start = req.start.unwrap_or(true);
    let target = if display_name.is_empty() {
        req.image.clone().unwrap_or_default()
    } else {
        display_name.clone()
    };

    let op_id = new_op_id();
    op_create(&op_id, "create", &target);

    let op_id_t = op_id.clone();
    let target_t = target.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, "正在创建容器 …");
        // `docker run -d` creates and starts. If the user opted not to start,
        // create with `create` instead so it lands in a stopped state.
        let run_args: Vec<&str> = if start {
            args.iter().map(String::as_str).collect()
        } else {
            // swap the leading "run" for "create" (drop the -d, harmless on create)
            let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
            a[0] = "create";
            a
        };
        match run(&run_args).await {
            Ok((true, stdout, _)) => {
                let cid = stdout.trim();
                let short = cid.chars().take(12).collect::<String>();
                op_push(&op_id_t, &format!("容器已{}：{}", if start { "创建并启动" } else { "创建" }, short));
                op_finish(&op_id_t, "done", "", &target_t);
            }
            Ok((false, _, stderr)) => {
                op_finish(&op_id_t, "error", &trim_msg(&stderr).unwrap_or_else(|| "创建失败".into()), "");
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": target }))
}

// ---------------------------------------------------------------------------
// Detached install
// ---------------------------------------------------------------------------

/// Start (or resume watching) a detached Docker install. Uses a fixed op id so
/// re-entering the page finds the in-progress install and its full log.
fn start_install() -> Result<Value> {
    const INSTALL_OP: &str = "install";
    // If an install is already running, just hand back its op id.
    if let Ok(m) = ops().lock() {
        if let Some(o) = m.get(INSTALL_OP) {
            if o.status == "running" {
                return Ok(json!({ "op_id": INSTALL_OP, "target": "docker", "already_running": true }));
            }
        }
    }

    if !is_root() {
        return Err(anyhow!("安装 Docker 需要 root 权限，请用 root 运行 Agent 后重试"));
    }

    op_create(INSTALL_OP, "install", "docker");
    tokio::spawn(async move {
        match run_install_detached(INSTALL_OP).await {
            Ok(()) => op_finish(INSTALL_OP, "done", "", ""),
            Err(e) => op_finish(INSTALL_OP, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": INSTALL_OP, "target": "docker" }))
}

async fn run_install_detached(op_id: &str) -> Result<()> {
    if let Ok(info) = docker_info().await {
        if info.get("installed").and_then(Value::as_bool) == Some(true) {
            op_push(op_id, "Docker 已安装");
            return Ok(());
        }
    }

    op_push(op_id, "下载 Docker 安装脚本（get.docker.com，阿里云镜像）…");
    let script = "set -e; \
        if command -v curl >/dev/null 2>&1; then \
          curl -fsSL https://get.docker.com -o /tmp/teaops-get-docker.sh; \
        elif command -v wget >/dev/null 2>&1; then \
          wget -qO /tmp/teaops-get-docker.sh https://get.docker.com; \
        else echo 'no curl/wget' >&2; exit 1; fi; \
        sh /tmp/teaops-get-docker.sh --mirror Aliyun; \
        rm -f /tmp/teaops-get-docker.sh";
    stream_shell_to_op(op_id, script).await?;

    op_push(op_id, "配置国内镜像加速并重启 Docker …");
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
    let _ = stream_shell_to_op(op_id, conf).await;

    op_push(op_id, "校验安装结果 …");
    let info = docker_info().await?;
    if info.get("installed").and_then(Value::as_bool) == Some(true) {
        op_push(op_id, "安装完成");
        Ok(())
    } else {
        Err(anyhow!("安装完成但 Docker 守护进程未就绪，请检查系统日志"))
    }
}

/// Run a shell script, pushing combined output lines into the op registry.
async fn stream_shell_to_op(op_id: &str, script: &str) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行安装脚本：{e}"))?;

    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child.wait().await.map_err(|e| anyhow!("安装脚本失败：{e}"))?;
    if let Some(mut e) = child.stderr.take() {
        let mut err = String::new();
        let _ = e.read_to_string(&mut err).await;
        for line in err.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev() {
            op_push(op_id, line.trim());
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

    #[test]
    fn op_registry_lifecycle() {
        let id = "test-op-1";
        op_create(id, "pull", "nginx:latest");
        op_push(id, "layer 1");
        op_finish(id, "done", "", "nginx:latest");
        let log = op_log(id);
        assert_eq!(log["status"], "done");
        assert_eq!(log["result_image"], "nginx:latest");
        op_dismiss(id);
        assert_eq!(op_log(id)["status"], "gone");
    }

    fn mk_req(image: &str) -> Req {
        Req {
            id: 0,
            op: "create_container".into(),
            image: Some(image.into()),
            mirror: None,
            reference: None,
            tail: None,
            op_id: None,
            name: None,
            ports: None,
            env: None,
            volumes: None,
            restart: None,
            start: None,
            network: None,
        }
    }

    #[test]
    fn restart_whitelist() {
        assert!(restart_allowed("no"));
        assert!(restart_allowed("unless-stopped"));
        assert!(restart_allowed("always"));
        assert!(!restart_allowed("on-failure"));
        assert!(!restart_allowed("; rm -rf /"));
    }

    #[test]
    fn name_validation() {
        assert!(validate_name("my-app_1.0").is_ok());
        assert!(validate_name("-leading").is_err());
        assert!(validate_name("bad name").is_err());
        assert!(validate_name("a; ls").is_err());
    }

    #[test]
    fn path_validation() {
        assert!(validate_path("/data/app").is_ok());
        assert!(validate_path("relative/path").is_err());
        assert!(validate_path("/data;rm").is_err());
        assert!(validate_path("/data$(x)").is_err());
        assert!(validate_path("").is_err());
    }

    #[test]
    fn env_validation() {
        assert!(validate_env("KEY=value").is_ok());
        assert!(validate_env("MY_VAR=a b c").is_ok());
        assert!(validate_env("_X=1").is_ok());
        assert!(validate_env("noequals").is_err());
        assert!(validate_env("=novalue").is_err());
        assert!(validate_env("1BAD=x").is_err());
        assert!(validate_env("bad key=x").is_err());
    }

    #[test]
    fn build_run_args_basic() {
        let mut req = mk_req("nginx:latest");
        req.name = Some("web".into());
        req.ports = Some(vec![PortMap { host: 8080, container: 80, proto: None }]);
        req.env = Some(vec!["FOO=bar".into()]);
        req.volumes = Some(vec![VolumeMap {
            host: "/srv/html".into(),
            container: "/usr/share/nginx/html".into(),
            readonly: true,
        }]);
        let (args, name) = build_run_args(&req).unwrap();
        assert_eq!(name, "web");
        // default restart policy applied
        assert!(args.windows(2).any(|w| w[0] == "--restart" && w[1] == "unless-stopped"));
        assert!(args.windows(2).any(|w| w[0] == "-p" && w[1] == "8080:80/tcp"));
        assert!(args.windows(2).any(|w| w[0] == "-e" && w[1] == "FOO=bar"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "-v" && w[1] == "/srv/html:/usr/share/nginx/html:ro"));
        // image is the last argument
        assert_eq!(args.last().unwrap(), "nginx:latest");
    }

    #[test]
    fn build_run_args_rejects_bad_port() {
        let mut req = mk_req("nginx");
        req.ports = Some(vec![PortMap { host: 0, container: 80, proto: None }]);
        assert!(build_run_args(&req).is_err());
    }

    #[test]
    fn build_run_args_rejects_bad_restart() {
        let mut req = mk_req("nginx");
        req.restart = Some("on-failure".into());
        assert!(build_run_args(&req).is_err());
    }

    #[test]
    fn build_run_args_includes_network() {
        let mut req = mk_req("nginx");
        req.network = Some("my-net".into());
        let (args, _) = build_run_args(&req).unwrap();
        assert!(args.windows(2).any(|w| w[0] == "--network" && w[1] == "my-net"));
    }

    #[test]
    fn build_run_args_rejects_bad_network() {
        let mut req = mk_req("nginx");
        req.network = Some("bad net".into());
        assert!(build_run_args(&req).is_err());
    }
}
