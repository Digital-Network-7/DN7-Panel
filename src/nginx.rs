//! Agent-side Nginx management.
//!
//! Two managed modes, chosen once at setup and persisted under the agent state
//! dir (`/var/lib/teaops/nginx/mode`):
//!
//! * **host**   – manage the host's own nginx. We only ever write our own
//!   `teaops-<id>.conf` files into `/etc/nginx/conf.d`, never touch the user's
//!   existing configs, and reload via `nginx -s reload`.
//! * **docker** – run a dedicated `teaops-nginx` container (nginx:alpine) that
//!   we created ourselves, with 80/443 published and our config / cert / webroot
//!   directories bind-mounted in. We never adopt a pre-existing container.
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
pub const CONTAINER: &str = "teaops-nginx";

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

/// Estimate 0..100 progress from docker pull log lines during setup (the nginx
/// container image pull — shared with the docker module's phase-weighted
/// logic). Returns -1 when indeterminate.
fn pull_pct(lines: &[String], status: &str) -> i64 {
    crate::docker::pull_pct(lines, status)
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
                "pct": pull_pct(&o.lines, &o.status),
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
            "pct": pull_pct(&o.lines, &o.status),
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

/// Public entrypoint for the local web console: parse a JSON request and run it.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))?;
    handle(&r).await
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
    let (ok, _o, e) = run("nginx", &["-v"])
        .await
        .unwrap_or((false, String::new(), String::new()));
    // `nginx -v` prints to stderr like "nginx version: nginx/1.24.0".
    let host_nginx_present = ok;
    let host_nginx_version = if ok {
        e.split('/')
            .nth(1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Who's listening on 80 / 443?
    let p80 = port_listener(80).await;
    let p443 = port_listener(443).await;

    // Is our docker nginx container present (created by us) and running?
    let docker_present = match crate::docker::dkr() {
        Ok(d) => d.version().await.is_ok(),
        Err(_) => false,
    };
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
/// or "" if it appears free. Tries `ss`, then `lsof`, then a pure-Rust
/// `/proc/net` fallback so it still works when neither tool is installed.
async fn port_listener(port: u16) -> String {
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
        return String::new();
    }
    // Fallback: lsof.
    if let Ok((true, out, _)) =
        run("lsof", &["-i", &format!(":{port}"), "-sTCP:LISTEN", "-Pn"]).await
    {
        if let Some(line) = out.lines().nth(1) {
            return line.split_whitespace().next().unwrap_or("占用").to_string();
        }
    }
    // Last resort: parse /proc directly (no external tools needed).
    proc_port_listener(port)
}

/// Pure-Rust port-listener probe: scan `/proc/net/tcp` + `tcp6` for a socket in
/// the LISTEN state on `port`, then resolve its owning process name by matching
/// the socket inode against `/proc/<pid>/fd`. Returns the process name, a
/// generic "占用" if the port is held but the owner can't be resolved, or "" if
/// the port appears free.
fn proc_port_listener(port: u16) -> String {
    let inode = match listening_inode("/proc/net/tcp", port)
        .or_else(|| listening_inode("/proc/net/tcp6", port))
    {
        Some(i) => i,
        None => return String::new(),
    };
    proc_name_for_inode(inode).unwrap_or_else(|| "占用".to_string())
}

/// Find the socket inode listening on `port` in a `/proc/net/tcp{,6}` file.
/// Columns: `sl local_address rem_address st ... inode`. `local_address` is
/// `HEXIP:HEXPORT`; LISTEN state is `0A`.
fn listening_inode(path: &str, port: u16) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if cols[3] != "0A" {
            continue; // not LISTEN
        }
        let local_port = cols[1]
            .rsplit(':')
            .next()
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        if local_port != Some(port) {
            continue;
        }
        if let Ok(inode) = cols[9].parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

/// Resolve the process name owning a socket `inode` by scanning `/proc/<pid>/fd`
/// for a `socket:[<inode>]` symlink, then reading `/proc/<pid>/comm`.
fn proc_name_for_inode(inode: u64) -> Option<String> {
    let want = format!("socket:[{inode}]");
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = match name.to_str().and_then(|s| s.parse::<u32>().ok()) {
            Some(p) => p,
            None => continue, // not a pid dir
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => continue, // no permission / process gone
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == want {
                    return std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
            }
        }
    }
    None
}

/// (exists, running) for our teaops-nginx container (via the daemon API).
async fn container_state() -> (bool, bool) {
    let dkr = match crate::docker::dkr() {
        Ok(d) => d,
        Err(_) => return (false, false),
    };
    match dkr.inspect_container(CONTAINER, None).await {
        Ok(c) => {
            let running = c.state.as_ref().and_then(|s| s.running).unwrap_or(false);
            (true, running)
        }
        Err(_) => (false, false),
    }
}

/// List running containers (name + published port hint) so the proxy form can
/// offer "forward to container:port" targets. Docker mode only. Uses the daemon
/// API (no `docker` CLI).
async fn list_running_containers() -> Result<Value> {
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: false,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(trim_msg(&e.to_string()).unwrap_or_else(|| "无法获取容器".into())))?;
    let mut items = Vec::new();
    for c in containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        if name.is_empty() || name == CONTAINER {
            continue; // don't proxy to ourselves
        }
        let ports = c
            .ports
            .as_ref()
            .map(|ps| {
                let mut v: Vec<String> = ps
                    .iter()
                    .map(|p| {
                        let proto = p
                            .typ
                            .map(|t| format!("{t:?}").to_lowercase())
                            .unwrap_or_else(|| "tcp".into());
                        match p.public_port {
                            Some(pp) => format!("{pp}->{}/{proto}", p.private_port),
                            None => format!("{}/{proto}", p.private_port),
                        }
                    })
                    .collect();
                v.sort();
                v.dedup();
                v.join(", ")
            })
            .unwrap_or_default();
        items.push(json!({
            "name": name,
            "ports": ports,
            "image": c.image.clone().unwrap_or_default(),
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
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '*' | '_'))
    })
}

/// The first hostname of a server_name (used for cert CN / acme domain).
fn primary_host(server_name: &str) -> String {
    server_name
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// A proxy target host[:port] or container name — no scheme, no path, no shell
/// metacharacters. We build the final `http://host:port` ourselves.
fn valid_host_token(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 255
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// A container name (docker's own charset).
fn valid_container_name(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A static webroot subdirectory name (single path segment, no separators).
fn valid_root_segment(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
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
        return Err(anyhow!(
            "配置 Nginx 需要 root 权限，请用 root 运行 Agent 后重试"
        ));
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
    if run("nginx", &["-v"])
        .await
        .map(|(ok, ..)| ok)
        .unwrap_or(false)
    {
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
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置测试失败".into())
        ));
    }
    Ok(())
}

/// Docker mode: pull nginx:alpine (via mirror) and run our dedicated container
/// with 80/443 published and our config/cert/webroot dirs mounted in, via the
/// daemon API (no `docker` CLI). We never adopt a container we didn't create —
/// any existing teaops-nginx is removed and recreated with our mounts.
async fn setup_docker(op_id: &str, mirror: &str) -> Result<()> {
    use bollard::container::{Config, CreateContainerOptions, RemoveContainerOptions};
    use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};
    use futures::StreamExt;

    let dkr = crate::docker::dkr()
        .map_err(|_| anyhow!("未检测到 Docker，请先在「Docker 管理」中安装 Docker"))?;
    dkr.version()
        .await
        .map_err(|_| anyhow!("未检测到 Docker，请先在「Docker 管理」中安装 Docker"))?;

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
    {
        let opts = bollard::image::CreateImageOptions {
            from_image: pull_ref.clone(),
            ..Default::default()
        };
        let mut stream = dkr.create_image(Some(opts), None, None);
        let mut last = String::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(info) => {
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
                Err(e) => return Err(anyhow!("拉取镜像失败：{e}")),
            }
        }
    }
    if pull_ref != "nginx:alpine" {
        let opts = bollard::image::TagImageOptions {
            repo: "nginx".to_string(),
            tag: "alpine".to_string(),
        };
        let _ = dkr.tag_image(&pull_ref, Some(opts)).await;
    }

    // Remove any previous teaops-nginx (ours) so mounts/ports are fresh.
    op_push(op_id, "创建 Nginx 容器 …");
    let _ = dkr
        .remove_container(
            CONTAINER,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    let m_conf = format!("{}:/etc/nginx/conf.d", confd_dir().display());
    let m_cert = format!("{}:/etc/nginx/certs", certs_dir().display());
    let m_www = format!("{}:/usr/share/nginx/html", www_dir().display());

    let mut port_bindings: std::collections::HashMap<String, Option<Vec<PortBinding>>> =
        std::collections::HashMap::new();
    for p in ["80", "443"] {
        port_bindings.insert(
            format!("{p}/tcp"),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(p.to_string()),
            }]),
        );
    }
    let mut exposed: std::collections::HashMap<String, std::collections::HashMap<(), ()>> =
        std::collections::HashMap::new();
    exposed.insert("80/tcp".to_string(), std::collections::HashMap::new());
    exposed.insert("443/tcp".to_string(), std::collections::HashMap::new());

    let config = Config {
        image: Some("nginx:alpine".to_string()),
        exposed_ports: Some(exposed),
        host_config: Some(HostConfig {
            binds: Some(vec![m_conf, m_cert, m_www]),
            port_bindings: Some(port_bindings),
            restart_policy: Some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    dkr.create_container(
        Some(CreateContainerOptions {
            name: CONTAINER.to_string(),
            platform: None,
        }),
        config,
    )
    .await
    .map_err(|e| {
        anyhow!(trim_msg(&e.to_string()).unwrap_or_else(|| "创建 Nginx 容器失败".into()))
    })?;
    dkr.start_container(
        CONTAINER,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| {
        anyhow!(trim_msg(&e.to_string()).unwrap_or_else(|| "启动 Nginx 容器失败".into()))
    })?;
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
    let status = child
        .wait()
        .await
        .map_err(|e| anyhow!("{cmd} 执行失败：{e}"))?;
    if let Some(mut er) = child.stderr.take() {
        let mut err = String::new();
        let _ = er.read_to_string(&mut err).await;
        for line in err
            .lines()
            .rev()
            .take(6)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
        {
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
    confd: std::path::PathBuf,      // where we WRITE conf files (host fs)
    cert_ref: String,               // dir nginx READS certs from
    www_ref: String,                // dir nginx READS webroots from
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
    format!(
        "{}{}",
        std::process::id() % 100000,
        N.fetch_add(1, Ordering::Relaxed)
    )
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
    write_site_conf(&lo, &site).await?;
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
            return Err(anyhow!(
                trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())
            ));
        }
        let (ok, _o, e) = run("nginx", &["-s", "reload"]).await?;
        if !ok {
            return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
        }
    } else {
        // Docker mode: exec `nginx -t` then `nginx -s reload` inside our
        // container via the daemon API (no `docker` CLI).
        let (code, out) = ctn_exec(CONTAINER, &["nginx", "-t"]).await?;
        if code != 0 {
            return Err(anyhow!(
                trim_msg(&out).unwrap_or_else(|| "nginx 配置无效".into())
            ));
        }
        let (code, out) = ctn_exec(CONTAINER, &["nginx", "-s", "reload"]).await?;
        if code != 0 {
            return Err(anyhow!(trim_msg(&out).unwrap_or_else(|| "重载失败".into())));
        }
    }
    Ok(())
}

/// Exec a command inside a container via the daemon API; returns (exit_code,
/// combined stdout+stderr).
async fn ctn_exec(container: &str, cmd: &[&str]) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
    use futures::StreamExt;

    let dkr = crate::docker::dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(cmd.iter().map(|s| s.to_string()).collect()),
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
    let code = dkr
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code)
        .unwrap_or(0);
    Ok((code, buf))
}

/// In docker mode, connect teaops-nginx to the target container's first
/// user-defined network so it can reach it by name. Best-effort (ignored on the
/// default bridge, where name resolution isn't available anyway).
async fn ensure_shared_network(target: &str) {
    let dkr = match crate::docker::dkr() {
        Ok(d) => d,
        Err(_) => return,
    };
    let nets: Vec<String> = match dkr.inspect_container(target, None).await {
        Ok(c) => c
            .network_settings
            .and_then(|n| n.networks)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default(),
        Err(_) => return,
    };
    for net in nets {
        if net == "bridge" || net == "host" || net == "none" {
            continue;
        }
        let cfg = bollard::network::ConnectNetworkOptions {
            container: CONTAINER.to_string(),
            endpoint_config: Default::default(),
        };
        let _ = dkr.connect_network(&net, cfg).await;
        return;
    }
}

/// Resolve a container's first reachable IPv4 address from the Docker daemon
/// (used in **host mode**, where the host's nginx can't resolve a container
/// *name* — only an IP works). Returns the IP from a user-defined network if
/// present, else the default bridge IP, else None.
async fn container_ip(target: &str) -> Option<String> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let networks = inspect.network_settings.and_then(|n| n.networks)?;
    // Prefer a user-defined network's IP; fall back to the bridge.
    let mut bridge_ip: Option<String> = None;
    for (name, ep) in networks {
        let ip = ep.ip_address.filter(|s| !s.is_empty());
        match ip {
            Some(ip) if name == "bridge" => bridge_ip = Some(ip),
            Some(ip) => return Some(ip), // user-defined network IP preferred
            None => {}
        }
    }
    bridge_ip
}

/// In **host mode**, find the host port that publishes the container's
/// `container_port` (so the host's nginx can proxy to `127.0.0.1:<host_port>`,
/// which is stable across container restarts — unlike the container IP). Returns
/// None when that port isn't published to the host.
async fn published_host_port(target: &str, container_port: i64) -> Option<u16> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let ports = inspect.network_settings.and_then(|n| n.ports)?;
    // Docker keys ports like "3000/tcp" -> [{HostIp, HostPort}, ...].
    let key_tcp = format!("{container_port}/tcp");
    let key_udp = format!("{container_port}/udp");
    for (key, binds) in ports {
        if key != key_tcp && key != key_udp {
            continue;
        }
        if let Some(binds) = binds {
            for b in binds {
                if let Some(hp) = b.host_port.and_then(|p| p.parse::<u16>().ok()) {
                    return Some(hp);
                }
            }
        }
    }
    None
}

/// Resolve the proxy upstream (`host:port`) for a site, accounting for mode:
///  - **docker mode + proxy_container**: use the container *name* (teaops-nginx
///    is joined to its network, so Docker DNS resolves it).
///  - **host mode + proxy_container**: the host's nginx can't resolve a
///    container name. Prefer the published host port (`127.0.0.1:<hostport>`,
///    stable across restarts); otherwise fall back to the container's bridge IP.
///  - **proxy_host**: the user-supplied host[:port] as-is.
async fn resolve_upstream(lo: &Layout, site: &Site) -> Result<String> {
    match site.kind.as_str() {
        "proxy_host" => Ok(with_port(&site.target_url)),
        "proxy_container" => {
            if lo.mode == "docker" {
                Ok(format!("{}:{}", site.container, site.container_port))
            } else if let Some(hp) = published_host_port(&site.container, site.container_port).await
            {
                // Reachable + restart-stable via the host's published port.
                Ok(format!("127.0.0.1:{hp}"))
            } else {
                // Not published — fall back to the container's bridge IP (the
                // host can route to docker0). Less stable, but works.
                let ip = container_ip(&site.container).await.ok_or_else(|| {
                    anyhow!(
                        "容器 {} 未映射端口 {} 到宿主机，且无法解析其 IP；请为容器发布该端口后重试",
                        site.container,
                        site.container_port
                    )
                })?;
                Ok(format!("{}:{}", ip, site.container_port))
            }
        }
        _ => Ok(String::new()),
    }
}

// ---------------------------------------------------------------------------
// Config generation. All values are pre-validated, so they're safe to embed.
// ---------------------------------------------------------------------------

/// Generate the nginx server block(s) for a site and write the conf file.
async fn write_site_conf(lo: &Layout, site: &Site) -> Result<()> {
    let body = render_location(lo, site).await?;
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

/// The location block(s) for a site's forwarding kind. Async because a
/// `proxy_container` site in host mode must resolve the container's IP (the
/// host's nginx can't resolve a container name).
async fn render_location(lo: &Layout, site: &Site) -> Result<String> {
    match site.kind.as_str() {
        "proxy_host" | "proxy_container" => {
            let upstream = resolve_upstream(lo, site).await?;
            Ok(proxy_block(&upstream))
        }
        "static" => {
            let root = format!("{}/{}", lo.www_ref, site.root);
            Ok(format!(
                "    location / {{\n        root {root};\n        index index.html index.htm;\n        try_files $uri $uri/ =404;\n    }}\n"
            ))
        }
        _ => Ok(String::new()),
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

/// Generate a self-signed cert/key pair for the site's primary host using
/// pure-Rust `rcgen` (no `openssl` dependency). Writes directly into the host
/// cert store; in docker mode that directory is bind-mounted into the nginx
/// container, so the container reads the very same files.
async fn gen_self_signed(lo: &Layout, site: &Site) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    let host = primary_host(&site.server_name);
    let host = if host == "_" {
        "localhost".to_string()
    } else {
        host
    };

    let mut params = rcgen::CertificateParams::new(vec![host.clone()])
        .map_err(|e| anyhow!("生成证书参数失败：{e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.clone());
    // 10-year validity (self-signed; the browser will warn regardless).
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(3650 * 24 * 3600)).into();

    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("签发自签证书失败：{e}"))?;

    let crt_path = lo.cert_store.join(format!("{}.crt", site.id));
    let key_path = lo.cert_store.join(format!("{}.key", site.id));
    std::fs::write(&crt_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    // Keep the private key readable only by us.
    set_key_perms(&key_path);
    Ok(())
}

/// Best-effort: restrict a private key file to owner-only (0600).
fn set_key_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
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
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

    let host = primary_host(&site.server_name);
    if host.is_empty() || host == "_" || host.contains('*') {
        return Err(anyhow!(
            "Let's Encrypt 需要一个具体域名（不支持通配符/默认站点）"
        ));
    }
    let acme_root = format!(
        "{}/_acme/.well-known/acme-challenge",
        lo.www_store.display()
    );
    std::fs::create_dir_all(&acme_root)?;

    // Step 1: serve HTTP (no SSL yet) so the http-01 challenge path is reachable.
    op_push(op_id, "准备 HTTP 验证站点 …");
    let mut http_site = site.clone();
    http_site.ssl = false;
    write_site_conf(lo, &http_site).await?;
    if let Err(e) = validate_and_reload(lo).await {
        let _ = std::fs::remove_file(conf_path(lo, &site.id));
        return Err(e);
    }

    // Step 2: create (or implicitly register) an ACME account with Let's Encrypt.
    op_push(op_id, "连接 Let's Encrypt 并创建账户 …");
    let (account, _creds) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        instant_acme::LetsEncrypt::Production.url(),
        None,
    )
    .await
    .map_err(|e| anyhow!("创建 ACME 账户失败：{e}"))?;

    // Step 3: place an order for the domain.
    op_push(op_id, &format!("为 {host} 申请证书 …"));
    let identifier = Identifier::Dns(host.clone());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .map_err(|e| anyhow!("创建订单失败：{e}"))?;

    // Step 4: satisfy the HTTP-01 challenge for each authorization.
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| anyhow!("获取授权失败：{e}"))?;
    let mut challenge_files: Vec<std::path::PathBuf> = Vec::new();
    for authz in &authorizations {
        if !matches!(authz.status, AuthorizationStatus::Pending) {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("该域名不支持 HTTP-01 验证"))?;

        // Write the key authorization to <webroot>/.well-known/acme-challenge/<token>.
        let token = &challenge.token;
        let key_auth = order.key_authorization(challenge);
        let file = std::path::Path::new(&acme_root).join(token);
        std::fs::write(&file, key_auth.as_str())?;
        challenge_files.push(file);

        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| anyhow!("提交验证失败：{e}"))?;
    }

    // Step 5: poll the order until it's ready (or fails), then finalize.
    op_push(op_id, "等待域名验证 …");
    let mut tries = 0;
    let cert_chain_pem = loop {
        tokio::time::sleep(std::time::Duration::from_secs(if tries == 0 {
            1
        } else {
            3
        }))
        .await;
        let state = order
            .refresh()
            .await
            .map_err(|e| anyhow!("查询订单状态失败：{e}"))?;
        match state.status {
            OrderStatus::Ready => {
                op_push(op_id, "验证通过，正在签发证书 …");
                let key_pair =
                    rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
                let mut csr_params = rcgen::CertificateParams::new(vec![host.clone()])
                    .map_err(|e| anyhow!("生成 CSR 参数失败：{e}"))?;
                csr_params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, host.clone());
                let csr = csr_params
                    .serialize_request(&key_pair)
                    .map_err(|e| anyhow!("生成 CSR 失败：{e}"))?;
                order
                    .finalize(csr.der())
                    .await
                    .map_err(|e| anyhow!("finalize 失败：{e}"))?;
                // Persist the issued chain + our key.
                let chain = wait_for_cert(&mut order).await?;
                // Save the key alongside (PEM).
                let key_path = lo.cert_store.join(format!("{}.key", site.id));
                std::fs::write(&key_path, key_pair.serialize_pem())?;
                set_key_perms(&key_path);
                break chain;
            }
            OrderStatus::Invalid => {
                let _ = cleanup_files(&challenge_files);
                return Err(anyhow!(
                    "域名验证失败，请确认 {host} 已解析到本机且 80 端口可被公网访问"
                ));
            }
            _ => {
                tries += 1;
                if tries > 40 {
                    let _ = cleanup_files(&challenge_files);
                    return Err(anyhow!("验证超时，请确认域名解析与 80 端口可达"));
                }
            }
        }
    };

    // Clean up challenge token files.
    let _ = cleanup_files(&challenge_files);

    // Write the issued certificate chain.
    let crt_path = lo.cert_store.join(format!("{}.crt", site.id));
    std::fs::write(&crt_path, cert_chain_pem)?;

    // Step 6: rewrite with SSL + persist + reload.
    op_push(op_id, "启用 HTTPS 配置 …");
    write_site_conf(lo, site).await?;
    validate_and_reload(lo).await?;
    let mut sites = load_sites();
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(())
}

/// Poll an order's certificate endpoint until the chain PEM is available.
async fn wait_for_cert(order: &mut instant_acme::Order) -> Result<String> {
    for _ in 0..15 {
        match order.certificate().await {
            Ok(Some(pem)) => return Ok(pem),
            Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            Err(e) => return Err(anyhow!("下载证书失败：{e}")),
        }
    }
    Err(anyhow!("证书签发超时"))
}

/// Best-effort cleanup of the written HTTP-01 challenge token files.
fn cleanup_files(files: &[std::path::PathBuf]) -> std::io::Result<()> {
    for f in files {
        let _ = std::fs::remove_file(f);
    }
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

    #[tokio::test]
    async fn renders_proxy_host() {
        let lo = lo_docker();
        let site = mk_site("proxy_host", false);
        let body = render_location(&lo, &site).await.unwrap();
        assert!(body.contains("proxy_pass http://10.0.0.5:8080;"));
        assert!(body.contains("Upgrade $http_upgrade"));
    }

    #[tokio::test]
    async fn renders_proxy_container() {
        // Docker mode resolves the container by name (no daemon call needed).
        let lo = lo_docker();
        let site = mk_site("proxy_container", false);
        let body = render_location(&lo, &site).await.unwrap();
        assert!(body.contains("proxy_pass http://app:3000;"));
    }

    #[tokio::test]
    async fn renders_static_root() {
        let lo = lo_docker();
        let site = mk_site("static", false);
        let body = render_location(&lo, &site).await.unwrap();
        assert!(body.contains("root /usr/share/nginx/html/site1;"));
    }
}
