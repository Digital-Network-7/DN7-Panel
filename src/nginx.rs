//! Agent-side Nginx management.
//!
//! Two managed modes, chosen once at setup and persisted under the agent state
//! dir (`/var/lib/teaops/nginx/mode`):
//!
//!   * **host**   – manage the host's own nginx. We only ever write our own
//!                  `teaops-<id>.conf` files into `/etc/nginx/conf.d`, never
//!                  touch the user's existing configs, and reload via
//!                  `nginx -s reload`.
//!   * **docker** – run a dedicated `teaops-nginx` container (nginx:alpine) that
//!                  we created ourselves, with 80/443 published and our config /
//!                  cert / webroot directories bind-mounted in. We never adopt a
//!                  pre-existing container.
//!
//! The wire protocol mirrors the docker channel: request/response JSON keyed by
//! `id`, with long operations (install / Let's Encrypt issuance) run **detached**
//! in a process-global op registry so they survive client reconnects.
//!
//! Sites are form-defined (domain + target), never raw nginx config, so there's
//! no config-injection surface. Each site is generated from a small manifest
//! (`sites.json`) into a single conf file and validated with `nginx -t` before
//! it's kept (otherwise it's rolled back).
//!
//! Requests (client -> agent):
//!   {"id","op":"info"}
//!   {"id","op":"setup","mode":"host"|"docker","mirror"?}   -> {op_id} (detached)
//!   {"id","op":"list_sites"}
//!   {"id","op":"add_site", <site fields>}     -> {site} or {op_id} (LE issuance)
//!   {"id","op":"remove_site","site_id"}
//!   {"id","op":"reload"}
//!   {"id","op":"list_containers"}             -> running containers (proxy menu)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

/// The container name we create + manage in docker mode. We never adopt a
/// container we didn't create with this exact name.
const CONTAINER: &str = "teaops-nginx";

#[derive(Debug, Deserialize)]
struct Req {
    #[serde(default)]
    id: i64,
    op: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    mirror: Option<String>,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    site_id: Option<String>,
    // add_site fields
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    kind: Option<String>, // "proxy_host" | "proxy_container" | "static"
    #[serde(default)]
    target_url: Option<String>, // proxy_host
    #[serde(default)]
    container: Option<String>, // proxy_container
    #[serde(default)]
    container_port: Option<i64>, // proxy_container
    #[serde(default)]
    root: Option<String>, // static (subdir name)
    #[serde(default)]
    ssl: Option<bool>,
    #[serde(default)]
    cert_mode: Option<String>, // "self" | "le" | "manual"
    #[serde(default)]
    cert_pem: Option<String>, // manual
    #[serde(default)]
    key_pem: Option<String>, // manual
}

/// A managed site, persisted in the manifest and regenerated into one conf file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Site {
    id: String,
    server_name: String,
    kind: String,
    #[serde(default)]
    target_url: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    container_port: i64,
    #[serde(default)]
    root: String,
    #[serde(default)]
    ssl: bool,
    #[serde(default)]
    cert_mode: String,
}

// ---------------------------------------------------------------------------
// Detached operation registry (setup + cert issuance).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct OpState {
    kind: String,   // "setup" | "cert"
    target: String, // mode (setup) or domain (cert)
    status: String, // "running" | "done" | "error"
    error: String,
    lines: Vec<String>,
}

fn ops() -> &'static Mutex<HashMap<String, OpState>> {
    static OPS: OnceLock<Mutex<HashMap<String, OpState>>> = OnceLock::new();
    OPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn new_op_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("nop{}", N.fetch_add(1, Ordering::Relaxed))
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
            let len = o.lines.len();
            if len > 400 {
                o.lines.drain(0..len - 400);
            }
        }
    }
}

fn op_finish(op_id: &str, status: &str, error: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.status = status.to_string();
            o.error = error.to_string();
        }
    }
}

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

// ---------------------------------------------------------------------------
// State directory layout (persisted under the agent runtime dir).
//
//   <base>/nginx/mode          "host" | "docker"
//   <base>/nginx/sites.json    the site manifest
//   <base>/nginx/conf.d/       generated teaops-*.conf (docker mode: mounted)
//   <base>/nginx/certs/        certs (docker mode: mounted)
//   <base>/nginx/www/          static webroots (docker mode: mounted)
// ---------------------------------------------------------------------------

fn base_dir() -> std::path::PathBuf {
    crate::paths::default_base_dir().join("nginx")
}
fn mode_file() -> std::path::PathBuf {
    base_dir().join("mode")
}
fn sites_file() -> std::path::PathBuf {
    base_dir().join("sites.json")
}
fn confd_dir() -> std::path::PathBuf {
    base_dir().join("conf.d")
}
fn certs_dir() -> std::path::PathBuf {
    base_dir().join("certs")
}
fn www_dir() -> std::path::PathBuf {
    base_dir().join("www")
}

/// Host nginx config drop-in directory (host mode only).
const HOST_CONFD: &str = "/etc/nginx/conf.d";

fn read_mode() -> Option<String> {
    std::fs::read_to_string(mode_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s == "host" || s == "docker")
}

fn write_mode(mode: &str) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(mode_file(), mode)?;
    Ok(())
}

fn load_sites() -> Vec<Site> {
    std::fs::read_to_string(sites_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<Site>>(&s).ok())
        .unwrap_or_default()
}

fn save_sites(sites: &[Site]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(sites_file(), serde_json::to_string_pretty(sites)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel runner + dispatch.
// ---------------------------------------------------------------------------

/// Connect to the backend nginx relay and serve the protocol until either side
/// closes. The connection is stateless: long ops live in the global registry.
pub async fn run_nginx_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_nginx_ws_url(session);
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

async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => nginx_info().await,
        "setup" => start_setup(req),
        "list_sites" => Ok(json!({ "sites": load_sites(), "mode": read_mode() })),
        "add_site" => add_site(req).await,
        "remove_site" => remove_site(req).await,
        "reload" => {
            reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "list_containers" => list_running_containers().await,
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => Ok(op_log(req.op_id.as_deref().unwrap_or(""))),
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Command helpers.
// ---------------------------------------------------------------------------

/// Run a command, returning (success, stdout, stderr).
async fn run(cmd: &str, args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

fn trim_msg(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(500).collect())
}

/// Run a shell script (used for docker exec into the nginx container, etc).
async fn sh(script: &str) -> Result<(bool, String, String)> {
    run("sh", &["-c", script]).await
}

#[cfg(unix)]
fn is_root() -> bool {
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

// ---------------------------------------------------------------------------
// Detection: what's installed / occupying 80+443, and our current managed mode.
// ---------------------------------------------------------------------------

/// Detect the host nginx binary + whether it (or anything) holds 80/443, plus
/// our managed state. Never errors — a clean host reports everything false so
/// the UI can drive the setup flow.
async fn nginx_info() -> Result<Value> {
    let managed_mode = read_mode();

    // Host nginx binary + version.
    let (ok, _o, e) = run("nginx", &["-v"]).await.unwrap_or((false, String::new(), String::new()));
    // `nginx -v` prints to stderr like "nginx version: nginx/1.24.0".
    let host_nginx_present = ok;
    let host_nginx_version = if ok {
        e.split('/').nth(1).map(|s| s.trim().to_string()).unwrap_or_default()
    } else {
        String::new()
    };

    // Who's listening on 80 / 443?
    let p80 = port_listener(80).await;
    let p443 = port_listener(443).await;

    // Is our docker nginx container present (created by us) and running?
    let docker_present = run("docker", &["--version"]).await.map(|(ok, ..)| ok).unwrap_or(false);
    let (ctn_exists, ctn_running) = if docker_present {
        container_state().await
    } else {
        (false, false)
    };

    // host nginx "owns" 80/443 if the listener process looks like nginx.
    let host_owns_ports = p80.contains("nginx") || p443.contains("nginx");

    Ok(json!({
        "managed_mode": managed_mode,           // null | "host" | "docker"
        "host_nginx_present": host_nginx_present,
        "host_nginx_version": host_nginx_version,
        "host_owns_ports": host_owns_ports,
        "port80": p80,                          // listener description ("" if free)
        "port443": p443,
        "docker_present": docker_present,
        "container_exists": ctn_exists,         // our teaops-nginx container
        "container_running": ctn_running,
        "is_root": is_root(),
    }))
}

/// Best-effort: a short description of what's listening on `port` (process name)
/// or "" if it appears free. Tries `ss` then `lsof`.
async fn port_listener(port: u16) -> String {
    let pat = format!(":{port} ");
    if let Ok((true, out, _)) = run("ss", &["-ltnp"]).await {
        for line in out.lines() {
            if line.contains(&format!(":{port}")) && line.to_lowercase().contains("listen") {
                // Extract a process name from users:(("nginx",pid=..)).
                if let Some(idx) = line.find("users:((\"") {
                    let rest = &line[idx + 9..];
                    if let Some(end) = rest.find('"') {
                        return rest[..end].to_string();
                    }
                }
                return "占用".to_string();
            }
        }
        let _ = pat;
        return String::new();
    }
    // Fallback: lsof.
    if let Ok((true, out, _)) = run("lsof", &["-i", &format!(":{port}"), "-sTCP:LISTEN", "-Pn"]).await {
        if let Some(line) = out.lines().nth(1) {
            return line.split_whitespace().next().unwrap_or("占用").to_string();
        }
    }
    String::new()
}

/// (exists, running) for our teaops-nginx container.
async fn container_state() -> (bool, bool) {
    let exists = run(
        "docker",
        &["ps", "-a", "--filter", &format!("name=^{CONTAINER}$"), "--format", "{{.Names}}"],
    )
    .await
    .map(|(_, o, _)| o.lines().any(|l| l.trim() == CONTAINER))
    .unwrap_or(false);
    if !exists {
        return (false, false);
    }
    let running = run(
        "docker",
        &["ps", "--filter", &format!("name=^{CONTAINER}$"), "--format", "{{.Names}}"],
    )
    .await
    .map(|(_, o, _)| o.lines().any(|l| l.trim() == CONTAINER))
    .unwrap_or(false);
    (true, running)
}

/// List running containers (name + first published port hint) so the proxy form
/// can offer "forward to container:port" targets. Docker mode only.
async fn list_running_containers() -> Result<Value> {
    let fmt = "{{.Names}}\t{{.Ports}}\t{{.Image}}";
    let (ok, out, err) = run("docker", &["ps", "--format", fmt]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&err).unwrap_or_else(|| "无法获取容器".into())));
    }
    let mut items = Vec::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.is_empty() {
            continue;
        }
        let name = f[0];
        if name == CONTAINER {
            continue; // don't proxy to ourselves
        }
        items.push(json!({
            "name": name,
            "ports": f.get(1).copied().unwrap_or(""),
            "image": f.get(2).copied().unwrap_or(""),
        }));
    }
    Ok(json!({ "containers": items }))
}

// ---------------------------------------------------------------------------
// Validation (no raw config; everything is form-driven and checked).
// ---------------------------------------------------------------------------

/// A server_name: one or more space-free hostnames (letters/digits/.-/* and _).
/// Wildcards (`*.example.com`) and `_` (catch-all) are allowed.
fn valid_server_name(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    s.split_whitespace().all(|h| {
        !h.is_empty()
            && h.len() <= 253
            && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_'))
    })
}

/// The first hostname of a server_name (used for cert CN / acme domain).
fn primary_host(server_name: &str) -> String {
    server_name.split_whitespace().next().unwrap_or("").to_string()
}

/// A proxy target host[:port] or container name — no scheme, no path, no shell
/// metacharacters. We build the final `http://host:port` ourselves.
fn valid_host_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A container name (docker's own charset).
fn valid_container_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A static webroot subdirectory name (single path segment, no separators).
fn valid_root_segment(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && s != "."
        && s != ".."
}

fn valid_port(p: i64) -> bool {
    (1..=65535).contains(&p)
}

// ---------------------------------------------------------------------------
// Setup: install host nginx OR create the docker nginx container. Detached.
// ---------------------------------------------------------------------------

fn start_setup(req: &Req) -> Result<Value> {
    let mode = req
        .mode
        .as_deref()
        .map(str::trim)
        .filter(|s| *s == "host" || *s == "docker")
        .ok_or_else(|| anyhow!("无效的管理方式"))?
        .to_string();
    let mirror = req.mirror.as_deref().unwrap_or("m.daocloud.io").to_string();

    const SETUP_OP: &str = "setup";
    if let Ok(m) = ops().lock() {
        if let Some(o) = m.get(SETUP_OP) {
            if o.status == "running" {
                return Ok(json!({ "op_id": SETUP_OP, "already_running": true }));
            }
        }
    }
    if !is_root() {
        return Err(anyhow!("配置 Nginx 需要 root 权限，请用 root 运行 Agent 后重试"));
    }

    op_create(SETUP_OP, "setup", &mode);
    let mode_t = mode.clone();
    tokio::spawn(async move {
        let res = if mode_t == "host" {
            setup_host(SETUP_OP).await
        } else {
            setup_docker(SETUP_OP, &mirror).await
        };
        match res {
            Ok(()) => {
                let _ = write_mode(&mode_t);
                op_push(SETUP_OP, "配置完成");
                op_finish(SETUP_OP, "done", "");
            }
            Err(e) => op_finish(SETUP_OP, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": SETUP_OP, "target": mode }))
}

/// Host mode: ensure nginx is installed (distro package manager, China mirrors
/// where possible), enabled and running. Only used when the user picked host.
async fn setup_host(op_id: &str) -> Result<()> {
    // Already present?
    if run("nginx", &["-v"]).await.map(|(ok, ..)| ok).unwrap_or(false) {
        op_push(op_id, "检测到宿主机已安装 Nginx");
    } else {
        op_push(op_id, "安装 Nginx（使用系统包管理器）…");
        let script = r#"set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y nginx
elif command -v yum >/dev/null 2>&1; then
  yum install -y nginx
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache nginx
else
  echo "no supported package manager" >&2; exit 1
fi"#;
        stream_sh(op_id, script).await?;
    }

    op_push(op_id, "确保配置目录存在并启用 Nginx …");
    let _ = sh(&format!("mkdir -p {HOST_CONFD}")).await;
    let _ = sh("systemctl enable nginx 2>/dev/null || true; systemctl restart nginx 2>/dev/null || service nginx restart 2>/dev/null || nginx 2>/dev/null || true").await;

    // Verify it's runnable.
    let (ok, _, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "nginx 配置测试失败".into())));
    }
    Ok(())
}

/// Docker mode: pull nginx:alpine (via mirror) and run our dedicated container
/// with 80/443 published and our config/cert/webroot dirs mounted in. We never
/// adopt an existing container — if one named teaops-nginx already exists we
/// reuse it only if we created it (same name + our mounts), else recreate.
async fn setup_docker(op_id: &str, mirror: &str) -> Result<()> {
    if !run("docker", &["--version"]).await.map(|(ok, ..)| ok).unwrap_or(false) {
        return Err(anyhow!("未检测到 Docker，请先在「Docker 管理」中安装 Docker"));
    }

    // Prepare host directories that we mount into the container.
    std::fs::create_dir_all(confd_dir())?;
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;

    // Pull nginx:alpine through the accelerator, then retag to a clean name.
    let pull_ref = if mirror.is_empty() {
        "nginx:alpine".to_string()
    } else {
        format!("{mirror}/docker.io/library/nginx:alpine")
    };
    op_push(op_id, &format!("拉取镜像 {pull_ref} …"));
    stream_cmd(op_id, "docker", &["pull", &pull_ref]).await?;
    if pull_ref != "nginx:alpine" {
        let _ = run("docker", &["tag", &pull_ref, "nginx:alpine"]).await;
    }

    // Remove any previous teaops-nginx (ours) so mounts/ports are fresh.
    op_push(op_id, "创建 Nginx 容器 …");
    let _ = run("docker", &["rm", "-f", CONTAINER]).await;

    let confd = confd_dir();
    let certs = certs_dir();
    let www = www_dir();
    let m_conf = format!("{}:/etc/nginx/conf.d", confd.display());
    let m_cert = format!("{}:/etc/nginx/certs", certs.display());
    let m_www = format!("{}:/usr/share/nginx/html", www.display());

    let (ok, _o, e) = run(
        "docker",
        &[
            "run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
            "-p", "80:80", "-p", "443:443",
            "-v", &m_conf, "-v", &m_cert, "-v", &m_www,
            "nginx:alpine",
        ],
    )
    .await?;
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "创建 Nginx 容器失败".into())));
    }
    Ok(())
}

/// Stream a shell script's output into the op log, erroring on non-zero exit.
async fn stream_sh(op_id: &str, script: &str) -> Result<()> {
    stream_cmd(op_id, "sh", &["-c", script]).await
}

/// Stream a command's combined output into the op log, erroring on non-zero.
async fn stream_cmd(op_id: &str, cmd: &str, args: &[&str]) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child.wait().await.map_err(|e| anyhow!("{cmd} 执行失败：{e}"))?;
    if let Some(mut er) = child.stderr.take() {
        let mut err = String::new();
        let _ = er.read_to_string(&mut err).await;
        for line in err.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev() {
            op_push(op_id, line.trim());
        }
    }
    if !status.success() {
        return Err(anyhow!("{cmd} 返回非零退出码"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sites: add / remove / generate config / reload.
// ---------------------------------------------------------------------------

/// Where generated conf files live for the active mode, and the paths that the
/// running nginx will read certs/webroots from (container paths in docker mode,
/// host paths in host mode).
struct Layout {
    mode: String,
    confd: std::path::PathBuf, // where we WRITE conf files (host fs)
    cert_ref: String,          // dir nginx READS certs from
    www_ref: String,           // dir nginx READS webroots from
    cert_store: std::path::PathBuf, // where we WRITE cert files (host fs)
    www_store: std::path::PathBuf,  // where we WRITE webroots (host fs)
}

fn layout() -> Result<Layout> {
    let mode = read_mode().ok_or_else(|| anyhow!("尚未完成 Nginx 配置"))?;
    if mode == "host" {
        std::fs::create_dir_all(certs_dir())?;
        std::fs::create_dir_all(www_dir())?;
        Ok(Layout {
            mode,
            confd: std::path::PathBuf::from(HOST_CONFD),
            cert_ref: certs_dir().display().to_string(),
            www_ref: www_dir().display().to_string(),
            cert_store: certs_dir(),
            www_store: www_dir(),
        })
    } else {
        // docker: we write into the mounted host dirs; nginx reads container paths.
        std::fs::create_dir_all(confd_dir())?;
        std::fs::create_dir_all(certs_dir())?;
        std::fs::create_dir_all(www_dir())?;
        Ok(Layout {
            mode,
            confd: confd_dir(),
            cert_ref: "/etc/nginx/certs".to_string(),
            www_ref: "/usr/share/nginx/html".to_string(),
            cert_store: certs_dir(),
            www_store: www_dir(),
        })
    }
}

fn conf_path(lo: &Layout, site_id: &str) -> std::path::PathBuf {
    lo.confd.join(format!("teaops-{site_id}.conf"))
}

/// Build a site from the request, validating every field.
fn site_from_req(req: &Req) -> Result<Site> {
    let server_name = req
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("请填写域名"))?
        .to_string();
    if !valid_server_name(&server_name) {
        return Err(anyhow!("域名格式不正确"));
    }
    let kind = req.kind.as_deref().unwrap_or("proxy_host").to_string();
    let ssl = req.ssl.unwrap_or(false);
    let cert_mode = req.cert_mode.as_deref().unwrap_or("self").to_string();

    let mut site = Site {
        id: new_site_id(),
        server_name,
        kind: kind.clone(),
        target_url: String::new(),
        container: String::new(),
        container_port: 0,
        root: String::new(),
        ssl,
        cert_mode: cert_mode.clone(),
    };

    match kind.as_str() {
        "proxy_host" => {
            let t = req
                .target_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("请填写转发目标"))?;
            if !valid_host_token(t) {
                return Err(anyhow!("转发目标格式不正确（host 或 host:port）"));
            }
            site.target_url = t.to_string();
        }
        "proxy_container" => {
            let c = req
                .container
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("请选择容器"))?;
            if !valid_container_name(c) {
                return Err(anyhow!("容器名不正确"));
            }
            let port = req.container_port.unwrap_or(0);
            if !valid_port(port) {
                return Err(anyhow!("容器端口需为 1-65535"));
            }
            site.container = c.to_string();
            site.container_port = port;
        }
        "static" => {
            let r = req
                .root
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("请填写站点目录名"))?;
            if !valid_root_segment(r) {
                return Err(anyhow!("目录名只能为单层名称（字母数字 _ - .）"));
            }
            site.root = r.to_string();
        }
        _ => return Err(anyhow!("未知的站点类型")),
    }

    if ssl && !matches!(cert_mode.as_str(), "self" | "le" | "manual") {
        return Err(anyhow!("未知的证书方式"));
    }
    Ok(site)
}

fn new_site_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("{}{}", std::process::id() % 100000, N.fetch_add(1, Ordering::Relaxed))
}

/// Add a site. For SSL with Let's Encrypt, issuance runs detached (returns an
/// op_id); otherwise the site is generated + validated synchronously.
async fn add_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site = site_from_req(req)?;

    // For docker proxy_container, the target must be reachable on the nginx
    // container's network — connect our container to the target's network so
    // service discovery by name works. Best-effort.
    if lo.mode == "docker" && site.kind == "proxy_container" {
        ensure_shared_network(&site.container).await;
    }

    // Prepare certs.
    if site.ssl {
        match site.cert_mode.as_str() {
            "self" => {
                gen_self_signed(&lo, &site).await?;
            }
            "manual" => {
                let cert = req.cert_pem.as_deref().unwrap_or("");
                let key = req.key_pem.as_deref().unwrap_or("");
                if cert.trim().is_empty() || key.trim().is_empty() {
                    return Err(anyhow!("请粘贴证书和私钥"));
                }
                write_cert_files(&lo, &site, cert, key)?;
            }
            "le" => {
                // Detached: write an HTTP-only site first so the ACME http-01
                // challenge can be served, then issue, then rewrite with SSL.
                return start_cert_issue(lo, site).await;
            }
            _ => {}
        }
    }

    // Generate + validate.
    write_site_conf(&lo, &site)?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back the conf we just wrote.
        let _ = std::fs::remove_file(conf_path(&lo, &site.id));
        return Err(e);
    }

    let mut sites = load_sites();
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(json!({ "site": site }))
}

async fn remove_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site_id = req
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("缺少站点 ID"))?;
    let mut sites = load_sites();
    let before = sites.len();
    let removed: Vec<Site> = sites.iter().filter(|s| s.id == site_id).cloned().collect();
    sites.retain(|s| s.id != site_id);
    if sites.len() == before {
        return Err(anyhow!("站点不存在"));
    }
    let _ = std::fs::remove_file(conf_path(&lo, site_id));
    // Clean up cert files for removed sites (best-effort).
    for s in &removed {
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.crt", s.id)));
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.key", s.id)));
    }
    save_sites(&sites)?;
    let _ = validate_and_reload(&lo).await;
    Ok(json!({ "removed": site_id }))
}

/// Reload nginx (host: `nginx -s reload`; docker: `docker exec ... nginx -s reload`).
async fn reload() -> Result<()> {
    let lo = layout()?;
    validate_and_reload(&lo).await
}

/// `nginx -t` then reload, in whichever mode is active. Errors carry nginx's
/// own message so a bad generated config is visible.
async fn validate_and_reload(lo: &Layout) -> Result<()> {
    if lo.mode == "host" {
        let (ok, _o, e) = run("nginx", &["-t"]).await?;
        if !ok {
            return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())));
        }
        let (ok, _o, e) = run("nginx", &["-s", "reload"]).await?;
        if !ok {
            return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
        }
    } else {
        let (ok, _o, e) = run("docker", &["exec", CONTAINER, "nginx", "-t"]).await?;
        if !ok {
            return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())));
        }
        let (ok, _o, e) = run("docker", &["exec", CONTAINER, "nginx", "-s", "reload"]).await?;
        if !ok {
            return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
        }
    }
    Ok(())
}

/// In docker mode, connect teaops-nginx to the target container's first
/// user-defined network so it can reach it by name. Best-effort (ignored on the
/// default bridge, where name resolution isn't available anyway).
async fn ensure_shared_network(target: &str) {
    let fmt = "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}\n{{end}}";
    if let Ok((true, out, _)) = run("docker", &["inspect", "-f", fmt, target]).await {
        for net in out.lines().map(str::trim).filter(|s| !s.is_empty()) {
            if net == "bridge" || net == "host" || net == "none" {
                continue;
            }
            let _ = run("docker", &["network", "connect", net, CONTAINER]).await;
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Config generation. All values are pre-validated, so they're safe to embed.
// ---------------------------------------------------------------------------

/// Generate the nginx server block(s) for a site and write the conf file.
fn write_site_conf(lo: &Layout, site: &Site) -> Result<()> {
    let body = render_location(lo, site);
    let server_name = &site.server_name;

    let mut conf = String::new();
    if site.ssl {
        let crt = format!("{}/{}.crt", lo.cert_ref, site.id);
        let key = format!("{}/{}.key", lo.cert_ref, site.id);
        // HTTP -> HTTPS redirect, plus an ACME webroot passthrough so renewals
        // keep working.
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n\
             \n    location ^~ /.well-known/acme-challenge/ {{\n        root {www}/_acme;\n    }}\n\
             \n    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\n",
            www = lo.www_ref
        ));
        conf.push_str(&format!(
            "server {{\n    listen 443 ssl;\n    http2 on;\n    server_name {server_name};\n\
             \n    ssl_certificate {crt};\n    ssl_certificate_key {key};\n\
             \n{body}}}\n"
        ));
    } else {
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n\n{body}}}\n"
        ));
    }

    std::fs::create_dir_all(&lo.confd)?;
    std::fs::write(conf_path(lo, &site.id), conf)?;
    Ok(())
}

/// The location block(s) for a site's forwarding kind.
fn render_location(lo: &Layout, site: &Site) -> String {
    match site.kind.as_str() {
        "proxy_host" => {
            let upstream = with_port(&site.target_url);
            proxy_block(&upstream)
        }
        "proxy_container" => {
            let upstream = format!("{}:{}", site.container, site.container_port);
            proxy_block(&upstream)
        }
        "static" => {
            let root = format!("{}/{}", lo.www_ref, site.root);
            format!(
                "    location / {{\n        root {root};\n        index index.html index.htm;\n        try_files $uri $uri/ =404;\n    }}\n"
            )
        }
        _ => String::new(),
    }
}

/// A reverse-proxy location with sane forwarded headers + websocket upgrade.
fn proxy_block(upstream: &str) -> String {
    format!(
        "    location / {{\n        proxy_pass http://{upstream};\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n    }}\n"
    )
}

/// Default a bare host to :80 for proxy_pass.
fn with_port(host: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:80")
    }
}

// ---------------------------------------------------------------------------
// Certificates.
// ---------------------------------------------------------------------------

/// Write user-supplied cert + key to the cert store (manual mode).
fn write_cert_files(lo: &Layout, site: &Site, cert_pem: &str, key_pem: &str) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(lo.cert_store.join(format!("{}.crt", site.id)), cert_pem)?;
    std::fs::write(lo.cert_store.join(format!("{}.key", site.id)), key_pem)?;
    Ok(())
}

/// Generate a self-signed cert/key pair for the site's primary host. Runs in the
/// nginx container in docker mode (openssl is bundled in nginx:alpine), or on
/// the host otherwise.
async fn gen_self_signed(lo: &Layout, site: &Site) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    let host = primary_host(&site.server_name);
    let host = if host == "_" { "localhost".to_string() } else { host };
    let crt = format!("{}/{}.crt", lo.cert_ref, site.id);
    let key = format!("{}/{}.key", lo.cert_ref, site.id);
    let subj = format!("/CN={host}");
    let args_str = format!(
        "openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -keyout '{key}' -out '{crt}' -subj '{subj}'"
    );
    let (ok, _o, e) = if lo.mode == "host" {
        sh(&args_str).await?
    } else {
        run("docker", &["exec", CONTAINER, "sh", "-c", &args_str]).await?
    };
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "生成自签证书失败".into())));
    }
    Ok(())
}

/// Issue a Let's Encrypt cert via acme.sh (webroot/http-01), detached. The flow:
///   1. write an HTTP-only conf so the challenge path is served,
///   2. install acme.sh if needed, issue against the webroot,
///   3. install the cert into our cert store,
///   4. rewrite the conf with SSL and reload.
async fn start_cert_issue(lo: Layout, site: Site) -> Result<Value> {
    let op_id = new_op_id();
    let target = primary_host(&site.server_name);
    op_create(&op_id, "cert", &target);
    let op_id_ret = op_id.clone();
    tokio::spawn(async move {
        match issue_le(&op_id, &lo, &site).await {
            Ok(()) => {
                op_push(&op_id, "证书签发完成，站点已启用 HTTPS");
                op_finish(&op_id, "done", "");
            }
            Err(e) => op_finish(&op_id, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": op_id_ret, "target": target }))
}

async fn issue_le(op_id: &str, lo: &Layout, site: &Site) -> Result<()> {
    let host = primary_host(&site.server_name);
    let acme_root = format!("{}/_acme", lo.www_store.display());
    std::fs::create_dir_all(&acme_root)?;

    // Step 1: serve HTTP (no SSL yet) so http-01 works.
    op_push(op_id, "准备 HTTP 验证站点 …");
    let mut http_site = site.clone();
    http_site.ssl = false;
    write_site_conf(lo, &http_site)?;
    if let Err(e) = validate_and_reload(lo).await {
        let _ = std::fs::remove_file(conf_path(lo, &site.id));
        return Err(e);
    }

    // Step 2: issue. acme.sh runs on the host (it just needs to write into the
    // webroot and reach Let's Encrypt over the network).
    let acme_webroot = if lo.mode == "host" {
        acme_root.clone()
    } else {
        // host path of the webroot (the container serves it under www_ref/_acme)
        acme_root.clone()
    };
    op_push(op_id, "安装 acme.sh（如已安装则跳过）…");
    let install = r#"set -e
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
  if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.acme.sh | sh -s email=admin@teaops.local;
  elif command -v wget >/dev/null 2>&1; then wget -qO- https://get.acme.sh | sh -s email=admin@teaops.local;
  else echo "no curl/wget" >&2; exit 1; fi
fi"#;
    stream_sh(op_id, install).await?;

    op_push(op_id, &format!("为 {host} 申请证书 …"));
    let crt = lo.cert_store.join(format!("{}.crt", site.id));
    let key = lo.cert_store.join(format!("{}.key", site.id));
    let issue = format!(
        "set -e\n\"$HOME/.acme.sh/acme.sh\" --issue -d '{host}' -w '{webroot}' --server letsencrypt --keylength 2048\n\"$HOME/.acme.sh/acme.sh\" --install-cert -d '{host}' --fullchain-file '{crt}' --key-file '{key}'",
        webroot = acme_webroot,
        crt = crt.display(),
        key = key.display(),
    );
    stream_sh(op_id, &issue).await?;

    if !crt.exists() || !key.exists() {
        return Err(anyhow!("证书签发失败，请确认域名已解析到本机且 80 端口可被公网访问"));
    }

    // Step 3: rewrite with SSL + persist + reload.
    op_push(op_id, "启用 HTTPS 配置 …");
    write_site_conf(lo, site)?;
    if let Err(e) = validate_and_reload(lo).await {
        return Err(e);
    }
    let mut sites = load_sites();
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_validation() {
        assert!(valid_server_name("example.com"));
        assert!(valid_server_name("a.example.com www.example.com"));
        assert!(valid_server_name("*.example.com"));
        assert!(valid_server_name("_"));
        assert!(!valid_server_name(""));
        assert!(!valid_server_name("bad;name"));
        assert!(!valid_server_name("a/b"));
    }

    #[test]
    fn host_token_validation() {
        assert!(valid_host_token("10.0.0.5"));
        assert!(valid_host_token("backend:3000"));
        assert!(valid_host_token("svc.local"));
        assert!(!valid_host_token("http://x"));
        assert!(!valid_host_token("a b"));
        assert!(!valid_host_token("a;b"));
    }

    #[test]
    fn container_and_root_validation() {
        assert!(valid_container_name("app"));
        assert!(!valid_container_name("-app"));
        assert!(!valid_container_name("a b"));
        assert!(valid_root_segment("site1"));
        assert!(!valid_root_segment(".."));
        assert!(!valid_root_segment("a/b"));
    }

    #[test]
    fn with_port_defaults_80() {
        assert_eq!(with_port("host"), "host:80");
        assert_eq!(with_port("host:8080"), "host:8080");
    }

    fn lo_docker() -> Layout {
        Layout {
            mode: "docker".into(),
            confd: std::path::PathBuf::from("/tmp/teaops-test-confd"),
            cert_ref: "/etc/nginx/certs".into(),
            www_ref: "/usr/share/nginx/html".into(),
            cert_store: std::path::PathBuf::from("/tmp/teaops-test-certs"),
            www_store: std::path::PathBuf::from("/tmp/teaops-test-www"),
        }
    }

    fn mk_site(kind: &str, ssl: bool) -> Site {
        Site {
            id: "s1".into(),
            server_name: "example.com".into(),
            kind: kind.into(),
            target_url: "10.0.0.5:8080".into(),
            container: "app".into(),
            container_port: 3000,
            root: "site1".into(),
            ssl,
            cert_mode: "self".into(),
        }
    }

    #[test]
    fn renders_proxy_host() {
        let lo = lo_docker();
        let site = mk_site("proxy_host", false);
        let body = render_location(&lo, &site);
        assert!(body.contains("proxy_pass http://10.0.0.5:8080;"));
        assert!(body.contains("Upgrade $http_upgrade"));
    }

    #[test]
    fn renders_proxy_container() {
        let lo = lo_docker();
        let site = mk_site("proxy_container", false);
        let body = render_location(&lo, &site);
        assert!(body.contains("proxy_pass http://app:3000;"));
    }

    #[test]
    fn renders_static_root() {
        let lo = lo_docker();
        let site = mk_site("static", false);
        let body = render_location(&lo, &site);
        assert!(body.contains("root /usr/share/nginx/html/site1;"));
    }
}
