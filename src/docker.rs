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
//!   {"id","op":"inspect_container","ref"}              -> one container's detail
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
use bollard::Docker;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

/// Connect to the local Docker daemon via its unix socket (or the platform
/// default). Replaces shelling out to the `docker` CLI — works as long as the
/// daemon socket is reachable, with no `docker` binary required on PATH.
pub fn dkr() -> Result<Docker> {
    Docker::connect_with_defaults()
        .map_err(|e| anyhow!("无法连接 Docker 守护进程：{e}（请确认 Docker 已安装并运行）"))
}

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
    // optional command override (argv, whitespace-split client-side or here)
    #[serde(default)]
    command: Option<String>,
    // allocate a pseudo-TTY (-t); keeps shells like `ubuntu`/`bash` alive
    #[serde(default)]
    tty: Option<bool>,
    // resource limits (cgroup v2 only): cpus like "0.5"/"2"; memory like "512m"/"1g"
    #[serde(default)]
    cpus: Option<String>,
    #[serde(default)]
    memory: Option<String>,
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
pub async fn run_docker_channel(
    _cfg: &AgentConfig,
    agent_token: &str,
    session: &str,
) -> Result<()> {
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
                                json!({ "ok": false, "error": format!("bad request: {e}") })
                                    .to_string(),
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
            let dkr = dkr()?;
            let opts = bollard::image::RemoveImageOptions {
                force: true,
                ..Default::default()
            };
            dkr.remove_image(&r, Some(opts), None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "removed": r }))
        }
        "list_containers" => list_containers().await,
        "inspect_container" => inspect_container(req).await,
        "start_container" => {
            let r = need_ref(req)?;
            dkr()?
                .start_container(
                    &r,
                    None::<bollard::container::StartContainerOptions<String>>,
                )
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "started": r }))
        }
        "stop_container" => {
            let r = need_ref(req)?;
            dkr()?
                .stop_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "stopped": r }))
        }
        "restart_container" => {
            let r = need_ref(req)?;
            dkr()?
                .restart_container(&r, None)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "restarted": r }))
        }
        "remove_container" => {
            let r = need_ref(req)?;
            let opts = bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            };
            dkr()?
                .remove_container(&r, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
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
            let opts = bollard::network::CreateNetworkOptions {
                name: name.to_string(),
                driver: "bridge".to_string(),
                ..Default::default()
            };
            dkr()?
                .create_network(opts)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "created": name }))
        }
        "remove_network" => {
            let r = need_ref(req)?;
            if let Err(e) = dkr()?.remove_network(&r).await {
                // The usual failure is an in-use / predefined network; give a
                // clear hint instead of the raw docker error.
                let raw = e.to_string().to_lowercase();
                let msg = if raw.contains("active endpoints") || raw.contains("in use") {
                    "该网络仍有容器在使用，请先断开相关容器后再删除".to_string()
                } else if raw.contains("predefined") || raw.contains("pre-defined") {
                    "内置网络（bridge/host/none）不可删除".to_string()
                } else {
                    friendly_docker_err(&e)
                };
                return Err(anyhow!(msg));
            }
            Ok(json!({ "removed": r }))
        }
        "inspect_container_networks" => inspect_container_networks(req).await,
        "connect_network" => {
            let r = need_ref(req)?;
            let net = need_network(req)?;
            let cfg = bollard::network::ConnectNetworkOptions {
                container: r.clone(),
                endpoint_config: Default::default(),
            };
            dkr()?
                .connect_network(&net, cfg)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "connected": net }))
        }
        "disconnect_network" => {
            let r = need_ref(req)?;
            let net = need_network(req)?;
            let cfg = bollard::network::DisconnectNetworkOptions {
                container: r.clone(),
                force: false,
            };
            dkr()?
                .disconnect_network(&net, cfg)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
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
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '@'));
    if !ok {
        return Err(anyhow!("invalid reference"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// docker daemon helpers (bollard)
// ---------------------------------------------------------------------------

/// Turn a bollard error into a bounded, user-facing message.
fn friendly_docker_err(e: &bollard::errors::Error) -> String {
    // bollard surfaces the daemon's JSON message for API errors; trim it.
    trim_msg(&e.to_string()).unwrap_or_else(|| "Docker 操作失败".into())
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

/// Detect docker presence + versions via the daemon API. Never errors: an
/// unreachable daemon is reported as `installed:false` so the UI can offer to
/// install it.
async fn docker_info() -> Result<Value> {
    let dkr = match dkr() {
        Ok(d) => d,
        Err(_) => {
            return Ok(json!({
                "installed": false,
                "daemon_running": false,
                "docker_present": false,
            }));
        }
    };

    let version = match dkr.version().await {
        Ok(v) => v,
        Err(_) => {
            // Socket exists but daemon not answering (or no permission).
            return Ok(json!({
                "installed": false,
                "daemon_running": false,
                "docker_present": false,
            }));
        }
    };

    let server_version = version.version.clone().unwrap_or_default();
    // The API version field is the closest "client" analogue without a CLI.
    let client_version = version.api_version.clone().unwrap_or_default();

    // Compose plugin version isn't exposed over the engine API; report empty.
    let compose_version = String::new();

    Ok(json!({
        "installed": !server_version.is_empty(),
        "daemon_running": !server_version.is_empty(),
        "docker_present": true,
        "server_version": server_version,
        "client_version": client_version,
        "compose_version": compose_version,
        "cgroup_v2": cgroup_v2(),
        // Host capacity, so the create form can cap CPU/memory limits.
        "host_cpus": host_cpus(),
        "host_mem_bytes": host_mem_bytes(),
    }))
}

/// Whether the host is on cgroup v2 (unified hierarchy). Resource limits in the
/// UI are only offered when this is true, per the product spec.
fn cgroup_v2() -> bool {
    // cgroup v2 mounts a single unified hierarchy with this controllers file.
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Logical CPU count of the host (for capping the `--cpus` limit). Falls back to
/// 0 when it can't be determined (the UI then doesn't cap).
fn host_cpus() -> u64 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(0)
}

/// Total physical memory of the host in bytes (for capping `--memory`). Parsed
/// from /proc/meminfo (`MemTotal: <kB> kB`); 0 when unavailable.
fn host_mem_bytes() -> u64 {
    let text = match std::fs::read_to_string("/proc/meminfo") {
        Ok(t) => t,
        Err(_) => return 0,
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // Value is in kB.
            if let Some(kb) = rest.split_whitespace().next() {
                if let Ok(kb) = kb.parse::<u64>() {
                    return kb * 1024;
                }
            }
        }
    }
    0
}

/// List images: id, repo:tag, size, created.
/// List images: id, repo:tag, size, created.
async fn list_images() -> Result<Value> {
    let dkr = dkr()?;
    let opts = bollard::image::ListImagesOptions::<String> {
        all: false,
        ..Default::default()
    };
    let images = dkr
        .list_images(Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut items = Vec::new();
    for img in images {
        let short_id = img
            .id
            .strip_prefix("sha256:")
            .unwrap_or(&img.id)
            .chars()
            .take(12)
            .collect::<String>();
        // Prefer the first non-<none> repo tag; fall back to the short id.
        let tags: Vec<String> = img
            .repo_tags
            .into_iter()
            .filter(|t| t != "<none>:<none>")
            .collect();
        let (name, repo, tag) = if let Some(t) = tags.first() {
            let mut sp = t.rsplitn(2, ':');
            let tg = sp.next().unwrap_or("latest").to_string();
            let rp = sp.next().unwrap_or(t).to_string();
            (t.clone(), rp, tg)
        } else {
            (short_id.clone(), "<none>".to_string(), "<none>".to_string())
        };
        items.push(json!({
            "id": short_id,
            "name": name,
            "repo": repo,
            "tag": tag,
            "size": human_size(img.size.max(0) as u64),
            "created": human_since(img.created),
        }));
    }
    Ok(json!({ "images": items }))
}

/// Format a byte count like docker's human sizes (e.g. "12.3MB").
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

/// Format a unix-timestamp "created" into a relative "x天前/小时前" hint.
fn human_since(created_secs: i64) -> String {
    if created_secs <= 0 {
        return String::new();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let diff = (now - created_secs).max(0);
    if diff < 3600 {
        format!("{}分钟前", (diff / 60).max(1))
    } else if diff < 86400 {
        format!("{}小时前", diff / 3600)
    } else {
        format!("{}天前", diff / 86400)
    }
}

/// List containers (all states): id, name, image, state, status, ports, and
/// whether a shell is available (so the UI can hide the terminal button for
/// shell-less images like distroless).
async fn list_containers() -> Result<Value> {
    let dkr = dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut items = Vec::new();
    for c in containers {
        let id = c.id.clone().unwrap_or_default();
        let short_id = id.chars().take(12).collect::<String>();
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let state = c.state.clone().unwrap_or_default();
        let running = state == "running";
        let has_shell = if running {
            container_has_shell(&dkr, &id).await
        } else {
            false
        };
        items.push(json!({
            "id": short_id,
            "name": name,
            "image": c.image.clone().unwrap_or_default(),
            "state": state,
            "status": c.status.clone().unwrap_or_default(),
            "ports": fmt_ports(&c.ports),
            "has_shell": has_shell,
        }));
    }
    Ok(json!({ "containers": items }))
}

/// Format published ports like docker ps (e.g. "0.0.0.0:8080->80/tcp").
fn fmt_ports(ports: &Option<Vec<bollard::models::Port>>) -> String {
    let mut out: Vec<String> = Vec::new();
    if let Some(ports) = ports {
        for p in ports {
            let proto = p
                .typ
                .map(|t| format!("{t:?}").to_lowercase())
                .unwrap_or_else(|| "tcp".into());
            match (p.public_port, &p.ip) {
                (Some(pub_port), Some(ip)) => {
                    out.push(format!("{ip}:{pub_port}->{}/{proto}", p.private_port))
                }
                (Some(pub_port), None) => {
                    out.push(format!("{pub_port}->{}/{proto}", p.private_port))
                }
                _ => out.push(format!("{}/{proto}", p.private_port)),
            }
        }
    }
    out.sort();
    out.dedup();
    out.join(", ")
}

/// Probe whether a running container has a usable `/bin/sh` (so the terminal
/// button is only shown when an interactive shell can actually be opened).
async fn container_has_shell(dkr: &Docker, id: &str) -> bool {
    let exec = dkr
        .create_exec(
            id,
            bollard::exec::CreateExecOptions {
                cmd: Some(vec!["/bin/sh", "-c", "true"]),
                attach_stdout: Some(false),
                attach_stderr: Some(false),
                ..Default::default()
            },
        )
        .await;
    let exec = match exec {
        Ok(e) => e,
        Err(_) => return false,
    };
    // Start it detached, then inspect the exit code.
    if dkr
        .start_exec(
            &exec.id,
            Some(bollard::exec::StartExecOptions {
                detach: true,
                ..Default::default()
            }),
        )
        .await
        .is_err()
    {
        return false;
    }
    // Give it a brief moment, then check the exit code.
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(inspect) = dkr.inspect_exec(&exec.id).await {
            if let Some(running) = inspect.running {
                if running {
                    continue;
                }
            }
            return inspect.exit_code == Some(0);
        }
    }
    false
}

/// Inspect one container for the detail page: identity, state, restart policy,
/// created time, and shell availability.
async fn inspect_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let c = dkr
        .inspect_container(&r, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;

    let name = c
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let state = c
        .state
        .as_ref()
        .and_then(|s| s.status.map(|st| format!("{st:?}").to_lowercase()))
        .unwrap_or_default();
    let running = c.state.as_ref().and_then(|s| s.running).unwrap_or(false);
    let exit_code = c.state.as_ref().and_then(|s| s.exit_code).unwrap_or(0);
    let restart_count = c.restart_count.unwrap_or(0);
    let image = c
        .config
        .as_ref()
        .and_then(|cf| cf.image.clone())
        .unwrap_or_default();
    let restart_policy = c
        .host_config
        .as_ref()
        .and_then(|h| h.restart_policy.as_ref())
        .and_then(|rp| rp.name.map(|n| format!("{n:?}").to_lowercase()))
        .unwrap_or_default();
    let created = c.created.clone().unwrap_or_default();
    let started_at = c
        .state
        .as_ref()
        .and_then(|s| s.started_at.clone())
        .unwrap_or_default();

    // Published ports from the network settings.
    let ports = c
        .network_settings
        .as_ref()
        .and_then(|n| n.ports.as_ref())
        .map(fmt_port_map)
        .unwrap_or_default();

    let has_shell = if running {
        container_has_shell(&dkr, &r).await
    } else {
        false
    };

    Ok(json!({
        "id": r,
        "name": name,
        "image": image,
        "state": state,
        "running": running,
        "restart_policy": restart_policy,
        "created": created,
        "started_at": started_at,
        "exit_code": exit_code,
        "restart_count": restart_count,
        "ports": ports,
        "has_shell": has_shell,
    }))
}

/// Format a container inspect PortMap into a docker-ps-like summary.
fn fmt_port_map(pm: &HashMap<String, Option<Vec<bollard::models::PortBinding>>>) -> String {
    let mut out: Vec<String> = Vec::new();
    for (container_port, bindings) in pm {
        if let Some(bindings) = bindings {
            for b in bindings {
                let host_ip = b.host_ip.clone().unwrap_or_default();
                let host_port = b.host_port.clone().unwrap_or_default();
                if host_port.is_empty() {
                    out.push(container_port.clone());
                } else if host_ip.is_empty() {
                    out.push(format!("{host_port}->{container_port}"));
                } else {
                    out.push(format!("{host_ip}:{host_port}->{container_port}"));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out.join(", ")
}

/// Tail a container's logs (via the daemon API).
async fn container_logs(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let tail = req.tail.unwrap_or(200).clamp(1, 2000);
    let dkr = dkr()?;
    let opts = bollard::container::LogsOptions::<String> {
        stdout: true,
        stderr: true,
        tail: tail.to_string(),
        timestamps: false,
        ..Default::default()
    };
    let mut stream = dkr.logs(&r, Some(opts));
    let mut text = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(out) => {
                // LogOutput derefs to the raw bytes of the line.
                text.push_str(&String::from_utf8_lossy(&out.into_bytes()));
            }
            Err(e) => {
                if text.is_empty() {
                    return Err(anyhow!(friendly_docker_err(&e)));
                }
                break;
            }
        }
    }
    // If there's no output, a constantly-restarting container is the usual
    // cause. Surface its state + last exit code so the user understands why.
    if text.trim().is_empty() {
        if let Ok(c) = dkr.inspect_container(&r, None).await {
            let st = c.state.as_ref();
            let status = st
                .and_then(|s| s.status.map(|x| format!("{x:?}").to_lowercase()))
                .unwrap_or_default();
            let exit = st.and_then(|s| s.exit_code).unwrap_or(0);
            let err = st.and_then(|s| s.error.clone()).unwrap_or_default();
            let restarts = c.restart_count.unwrap_or(0);
            let mut hint = format!(
                "（容器暂无日志输出）\n状态：{status} · 退出码：{exit} · 重启次数：{restarts}"
            );
            if !err.trim().is_empty() {
                hint.push_str(&format!("\n错误：{}", err.trim()));
            }
            if restarts != 0 || status == "restarting" {
                hint.push_str(
                    "\n\n提示：容器可能因默认命令立即退出而不断重启。请在创建时开启「分配终端」或填写常驻启动命令（如 sleep infinity），或将重启策略设为 no。",
                );
            }
            text = hint;
        }
    }
    Ok(json!({ "logs": text }))
}

/// List networks: id, name, driver, scope.
async fn list_networks() -> Result<Value> {
    let dkr = dkr()?;
    let nets = dkr
        .list_networks::<String>(None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut items = Vec::new();
    for n in nets {
        let id =
            n.id.clone()
                .unwrap_or_default()
                .chars()
                .take(12)
                .collect::<String>();
        items.push(json!({
            "id": id,
            "name": n.name.clone().unwrap_or_default(),
            "driver": n.driver.clone().unwrap_or_default(),
            "scope": n.scope.clone().unwrap_or_default(),
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
    let dkr = dkr()?;
    let c = dkr
        .inspect_container(&r, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let attached: Vec<String> = c
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

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
    let qualified =
        has_slash && (first.contains('.') || first.contains(':') || first == "localhost");
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

    let mirror = req
        .mirror
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

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

    let shown = final_ref
        .clone()
        .unwrap_or_else(|| with_default_tag(&image));
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
                        if let Err(e) = tag_image(&pull_ref, final_ref).await {
                            op_finish(&op_id_t, "error", &e.to_string(), "");
                            return;
                        }
                        let _ = remove_image_quiet(&pull_ref).await; // best-effort
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

/// Tag an image `source` as `target` (target = repo[:tag]).
async fn tag_image(source: &str, target: &str) -> Result<()> {
    let (repo, tag) = match target.rsplit_once(':') {
        // Avoid splitting on a registry-port colon when there's no real tag.
        Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
        _ => (target.to_string(), "latest".to_string()),
    };
    let opts = bollard::image::TagImageOptions { repo, tag };
    dkr()?
        .tag_image(source, Some(opts))
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))
}

/// Remove an image, ignoring errors (best-effort cleanup after a retag).
async fn remove_image_quiet(reference: &str) {
    if let Ok(dkr) = dkr() {
        let opts = bollard::image::RemoveImageOptions {
            force: true,
            ..Default::default()
        };
        let _ = dkr.remove_image(reference, Some(opts), None).await;
    }
}

/// Pull `pull_ref` via the daemon's create_image stream, pushing each progress
/// status line into the op registry.
async fn run_pull_detached(op_id: &str, pull_ref: &str) -> Result<()> {
    let dkr = dkr()?;
    let opts = bollard::image::CreateImageOptions {
        from_image: pull_ref.to_string(),
        ..Default::default()
    };
    let mut stream = dkr.create_image(Some(opts), None, None);
    let mut last = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                // Build a concise progress line: "<status> <progress>".
                let mut line = info.status.unwrap_or_default();
                if let Some(p) = info.progress {
                    if !p.is_empty() {
                        line.push(' ');
                        line.push_str(&p);
                    }
                }
                let line = line.trim().to_string();
                if !line.is_empty() && line != last {
                    op_push(op_id, &line);
                    last = line;
                }
            }
            Err(e) => return Err(anyhow!(friendly_docker_err(&e))),
        }
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
    let bad = s.chars().any(|c| {
        matches!(
            c,
            ';' | '|' | '&' | '$' | '`' | '\n' | '\r' | '"' | '\'' | '\\' | '<' | '>' | '*'
        )
    });
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
    let (k, _v) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("环境变量需为 KEY=VALUE 格式"))?;
    if k.is_empty() {
        return Err(anyhow!("环境变量名不能为空"));
    }
    let key_ok = k
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    if !key_ok {
        return Err(anyhow!(
            "环境变量名只能包含字母、数字、下划线，且不以数字开头"
        ));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(anyhow!("环境变量包含非法字符"));
    }
    Ok(())
}

/// A validated container creation spec, ready for the bollard create API.
struct CreateSpec {
    image: String,
    name: Option<String>,
    start: bool,
    config: bollard::container::Config<String>,
}

/// Build a bollard create config from a validated request. Every user value is
/// validated before it lands in the config (no shell, no CLI args).
fn build_create_spec(req: &Req) -> Result<(CreateSpec, String)> {
    use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};

    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    // Name (optional).
    let mut display_name = String::new();
    let mut name: Option<String> = None;
    if let Some(n) = req.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_name(n)?;
        display_name = n.to_string();
        name = Some(n.to_string());
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
    let restart_policy = RestartPolicy {
        name: Some(match restart {
            "always" => RestartPolicyNameEnum::ALWAYS,
            "no" => RestartPolicyNameEnum::NO,
            _ => RestartPolicyNameEnum::UNLESS_STOPPED,
        }),
        maximum_retry_count: None,
    };

    // Network (optional; must be an existing network). Empty => default bridge.
    let mut network: Option<String> = None;
    if let Some(net) = req
        .network
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_token(net)?;
        network = Some(net.to_string());
    }

    // Port mappings -> exposed_ports + host port bindings.
    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    let mut bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
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
            let key = format!("{}/{}", p.container, proto);
            exposed.insert(key.clone(), HashMap::new());
            bindings.insert(
                key,
                Some(vec![PortBinding {
                    host_ip: None,
                    host_port: Some(p.host.to_string()),
                }]),
            );
        }
    }

    // Environment variables.
    let mut env: Vec<String> = Vec::new();
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
            env.push(e.to_string());
        }
    }

    // Volume mounts -> binds.
    let mut binds: Vec<String> = Vec::new();
    if let Some(vols) = &req.volumes {
        if vols.len() > 50 {
            return Err(anyhow!("挂载过多"));
        }
        for v in vols {
            let host = v.host.trim();
            let container = v.container.trim();
            validate_path(host)?;
            validate_path(container)?;
            binds.push(if v.readonly {
                format!("{host}:{container}:ro")
            } else {
                format!("{host}:{container}")
            });
        }
    }

    // Resource limits (cgroup v2). Validated formats only, capped to the host.
    let mut nano_cpus: Option<i64> = None;
    let mut memory: Option<i64> = None;
    if let Some(cpus) = req.cpus.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_cpus(cpus)?;
        let host = host_cpus();
        let v: f64 = cpus.parse().unwrap_or(0.0);
        if host > 0 && v > host as f64 {
            return Err(anyhow!("CPU 限制不能超过宿主机核数（{host}）"));
        }
        // docker NanoCPUs = cpus * 1e9.
        nano_cpus = Some((v * 1_000_000_000.0) as i64);
    }
    if let Some(mem) = req
        .memory
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        validate_memory(mem)?;
        let host = host_mem_bytes();
        let bytes = mem_to_bytes(mem);
        if host > 0 && bytes > host {
            return Err(anyhow!("内存限制不能超过宿主机内存"));
        }
        memory = Some(bytes as i64);
    }

    let tty = req.tty.unwrap_or(false);

    // Optional command override.
    let cmd: Option<Vec<String>> = match req
        .command
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(c) => Some(split_command(c)?),
        None => None,
    };

    let host_config = HostConfig {
        restart_policy: Some(restart_policy),
        binds: if binds.is_empty() { None } else { Some(binds) },
        port_bindings: if bindings.is_empty() {
            None
        } else {
            Some(bindings)
        },
        nano_cpus,
        memory,
        network_mode: network.clone(),
        ..Default::default()
    };

    let config = bollard::container::Config {
        image: Some(image.clone()),
        cmd,
        env: if env.is_empty() { None } else { Some(env) },
        tty: Some(tty),
        open_stdin: Some(tty),
        exposed_ports: if exposed.is_empty() {
            None
        } else {
            Some(exposed)
        },
        host_config: Some(host_config),
        ..Default::default()
    };

    Ok((
        CreateSpec {
            image,
            name,
            start: req.start.unwrap_or(true),
            config,
        },
        display_name,
    ))
}

/// Validate a `--cpus` value: a positive decimal like "0.5", "1", "2.5".
fn validate_cpus(s: &str) -> Result<()> {
    let v: f64 = s
        .parse()
        .map_err(|_| anyhow!("CPU 限制格式不正确（如 0.5、1、2）"))?;
    if v <= 0.0 || v > 1024.0 {
        return Err(anyhow!("CPU 限制超出范围"));
    }
    // Restrict the charset too (parse alone would accept "inf"/"NaN").
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(anyhow!("CPU 限制格式不正确"));
    }
    Ok(())
}

/// Validate a `--memory` value: a positive integer with an optional b/k/m/g
/// suffix, e.g. "512m", "1g", "268435456".
fn validate_memory(s: &str) -> Result<()> {
    let lower = s.to_ascii_lowercase();
    let (num, _suffix) = match lower.chars().last() {
        Some(c) if matches!(c, 'b' | 'k' | 'm' | 'g') => (&lower[..lower.len() - 1], Some(c)),
        _ => (lower.as_str(), None),
    };
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("内存限制格式不正确（如 512m、1g）"));
    }
    let n: u64 = num.parse().map_err(|_| anyhow!("内存限制格式不正确"))?;
    if n == 0 {
        return Err(anyhow!("内存限制需大于 0"));
    }
    Ok(())
}

/// Convert a validated `--memory` value to bytes (for the host cap). Returns 0
/// for an unparseable value (treated as "no cap" by the caller).
fn mem_to_bytes(s: &str) -> u64 {
    let lower = s.to_ascii_lowercase();
    let (num, mult) = match lower.chars().last() {
        Some('b') => (&lower[..lower.len() - 1], 1u64),
        Some('k') => (&lower[..lower.len() - 1], 1024),
        Some('m') => (&lower[..lower.len() - 1], 1024 * 1024),
        Some('g') => (&lower[..lower.len() - 1], 1024 * 1024 * 1024),
        _ => (lower.as_str(), 1),
    };
    num.parse::<u64>()
        .ok()
        .map(|n| n.saturating_mul(mult))
        .unwrap_or(0)
}

/// Split a command string into argv. Supports simple single/double quoting; no
/// shell features (no globbing, pipes, substitution). Each token is a separate
/// argv entry passed to `docker run`, so there's no shell-injection surface.
fn split_command(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut has_token = false;
    for c in s.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    has_token = true;
                }
                ' ' | '\t' => {
                    if has_token {
                        out.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                '\n' | '\r' => return Err(anyhow!("命令不能包含换行")),
                _ => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err(anyhow!("命令引号未闭合"));
    }
    if has_token {
        out.push(cur);
    }
    if out.len() > 100 {
        return Err(anyhow!("命令参数过多"));
    }
    Ok(out)
}

/// Validate the request, register a detached op, create the container via the
/// daemon API, and (when requested) start it. Returns an op_id.
fn start_create(req: &Req) -> Result<Value> {
    let (spec, display_name) = build_create_spec(req)?;
    let target = if display_name.is_empty() {
        spec.image.clone()
    } else {
        display_name.clone()
    };

    let op_id = new_op_id();
    op_create(&op_id, "create", &target);

    let op_id_t = op_id.clone();
    let target_t = target.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, "正在创建容器 …");
        match create_container(spec).await {
            Ok((id, started)) => {
                let short = id.chars().take(12).collect::<String>();
                op_push(
                    &op_id_t,
                    &format!(
                        "容器已{}：{}",
                        if started { "创建并启动" } else { "创建" },
                        short
                    ),
                );
                op_finish(&op_id_t, "done", "", &target_t);
            }
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });

    Ok(json!({ "op_id": op_id, "target": target }))
}

/// Create (and optionally start) a container via the daemon API. Returns the
/// new container id and whether it was started.
async fn create_container(spec: CreateSpec) -> Result<(String, bool)> {
    let dkr = dkr()?;
    let options = spec
        .name
        .clone()
        .map(|name| bollard::container::CreateContainerOptions {
            name,
            platform: None,
        });
    let created = dkr
        .create_container(options, spec.config)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let id = created.id;
    if spec.start {
        dkr.start_container(
            &id,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
    Ok((id, spec.start))
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
                return Ok(
                    json!({ "op_id": INSTALL_OP, "target": "docker", "already_running": true }),
                );
            }
        }
    }

    if !is_root() {
        return Err(anyhow!(
            "安装 Docker 需要 root 权限，请用 root 运行 Agent 后重试"
        ));
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
    use tokio::process::Command;

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
    let status = child
        .wait()
        .await
        .map_err(|e| anyhow!("安装脚本失败：{e}"))?;
    if let Some(mut e) = child.stderr.take() {
        let mut err = String::new();
        let _ = e.read_to_string(&mut err).await;
        for line in err
            .lines()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
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
        assert_eq!(
            docker_io_path("nginx"),
            Some("docker.io/library/nginx:latest".into())
        );
        assert_eq!(
            docker_io_path("nginx:1.25"),
            Some("docker.io/library/nginx:1.25".into())
        );
        assert_eq!(
            docker_io_path("user/app"),
            Some("docker.io/user/app:latest".into())
        );
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
            command: None,
            tty: None,
            cpus: None,
            memory: None,
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
    fn build_create_spec_basic() {
        let mut req = mk_req("nginx:latest");
        req.name = Some("web".into());
        req.ports = Some(vec![PortMap {
            host: 8080,
            container: 80,
            proto: None,
        }]);
        req.env = Some(vec!["FOO=bar".into()]);
        req.volumes = Some(vec![VolumeMap {
            host: "/srv/html".into(),
            container: "/usr/share/nginx/html".into(),
            readonly: true,
        }]);
        let (spec, name) = build_create_spec(&req).unwrap();
        assert_eq!(name, "web");
        assert_eq!(spec.name.as_deref(), Some("web"));
        assert_eq!(spec.config.image.as_deref(), Some("nginx:latest"));
        let hc = spec.config.host_config.as_ref().unwrap();
        // default restart policy applied
        assert_eq!(
            hc.restart_policy.as_ref().unwrap().name,
            Some(bollard::models::RestartPolicyNameEnum::UNLESS_STOPPED)
        );
        // port binding host 8080 -> container 80/tcp
        let pb = hc.port_bindings.as_ref().unwrap();
        let bind = pb.get("80/tcp").unwrap().as_ref().unwrap();
        assert_eq!(bind[0].host_port.as_deref(), Some("8080"));
        // env + bind present
        assert!(spec
            .config
            .env
            .as_ref()
            .unwrap()
            .contains(&"FOO=bar".to_string()));
        assert!(hc
            .binds
            .as_ref()
            .unwrap()
            .contains(&"/srv/html:/usr/share/nginx/html:ro".to_string()));
        assert!(spec.start);
    }

    #[test]
    fn build_create_spec_rejects_bad_port() {
        let mut req = mk_req("nginx");
        req.ports = Some(vec![PortMap {
            host: 0,
            container: 80,
            proto: None,
        }]);
        assert!(build_create_spec(&req).is_err());
    }

    #[test]
    fn build_create_spec_rejects_bad_restart() {
        let mut req = mk_req("nginx");
        req.restart = Some("on-failure".into());
        assert!(build_create_spec(&req).is_err());
    }

    #[test]
    fn build_create_spec_includes_network() {
        let mut req = mk_req("nginx");
        req.network = Some("my-net".into());
        let (spec, _) = build_create_spec(&req).unwrap();
        let hc = spec.config.host_config.as_ref().unwrap();
        assert_eq!(hc.network_mode.as_deref(), Some("my-net"));
    }

    #[test]
    fn build_create_spec_rejects_bad_network() {
        let mut req = mk_req("nginx");
        req.network = Some("bad net".into());
        assert!(build_create_spec(&req).is_err());
    }

    #[test]
    fn build_create_spec_tty_and_command() {
        let mut req = mk_req("ubuntu");
        req.tty = Some(true);
        req.command = Some("sleep infinity".into());
        let (spec, _) = build_create_spec(&req).unwrap();
        assert_eq!(spec.config.tty, Some(true));
        assert_eq!(spec.config.open_stdin, Some(true));
        assert_eq!(
            spec.config.cmd.as_ref().unwrap(),
            &vec!["sleep".to_string(), "infinity".to_string()]
        );
    }

    #[test]
    fn build_create_spec_resource_limits() {
        let mut req = mk_req("nginx");
        req.cpus = Some("0.5".into());
        req.memory = Some("512m".into());
        let (spec, _) = build_create_spec(&req).unwrap();
        let hc = spec.config.host_config.as_ref().unwrap();
        assert_eq!(hc.nano_cpus, Some(500_000_000));
        assert_eq!(hc.memory, Some(512 * 1024 * 1024));
    }

    #[test]
    fn validates_limits() {
        assert!(validate_cpus("0.5").is_ok());
        assert!(validate_cpus("2").is_ok());
        assert!(validate_cpus("0").is_err());
        assert!(validate_cpus("abc").is_err());
        assert!(validate_memory("512m").is_ok());
        assert!(validate_memory("1g").is_ok());
        assert!(validate_memory("268435456").is_ok());
        assert!(validate_memory("0").is_err());
        assert!(validate_memory("12x").is_err());
    }

    #[test]
    fn mem_to_bytes_units() {
        assert_eq!(mem_to_bytes("512m"), 512 * 1024 * 1024);
        assert_eq!(mem_to_bytes("1g"), 1024 * 1024 * 1024);
        assert_eq!(mem_to_bytes("2048"), 2048);
        assert_eq!(mem_to_bytes("1k"), 1024);
    }

    #[test]
    fn splits_command() {
        assert_eq!(
            split_command("sleep infinity").unwrap(),
            vec!["sleep", "infinity"]
        );
        assert_eq!(
            split_command("sh -c \"echo hi there\"").unwrap(),
            vec!["sh", "-c", "echo hi there"]
        );
        assert!(split_command("bad 'quote").is_err());
    }
}
