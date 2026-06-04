//! Agent-side MySQL / MariaDB management.
//!
//! TeaOps provisions and manages MySQL/MariaDB **inside Docker containers** on
//! the user's server. We only ever touch instances *we* created: each managed
//! container carries the label `teaops.mysql=1` plus a `teaops.mysql.id` and a
//! local manifest under `<data>/mysql/<id>.json` (0600) recording the engine,
//! version, port mapping, data volume, and the at-rest-encrypted root password.
//! A user's own, hand-run MySQL is never listed or modified.
//!
//! When the backend pushes an `open-mysql` command, the agent dials back
//! `/agent/mysql?session=` (token in the Authorization header) and serves a
//! request/response JSON protocol backed by the local Docker daemon (bollard):
//!
//!   backend WS  <->  agent  <->  local Docker daemon  <->  mysql container
//!
//! Requests (client -> agent):
//!   {"id","op":"info"}                                  docker present? + engines/versions
//!   {"id","op":"list"}                                  TeaOps-managed instances
//!   {"id","op":"install","engine","version","port"?,"expose"?}  -> {op_id} (detached)
//!   {"id","op":"start"|"stop"|"restart","inst"}
//!   {"id","op":"remove","inst","keep_data"?}
//!   {"id","op":"reset_password","inst"}                 -> {password}
//!   {"id","op":"change_port","inst","port"?,"expose"}   -> recreate, keep volume
//!   {"id","op":"switch_version","inst","version"}       -> {op_id} (detached)
//!   {"id","op":"databases","inst"}                      -> [{name,tables,size}]
//!   {"id","op":"credentials","inst"}                    -> {host,port,user,password}
//!   {"id","op":"list_users","inst"}                     -> [{user,host,system}]
//!   {"id","op":"create_user","inst","username","host","password"}
//!   {"id","op":"drop_user","inst","username","host"}
//!   {"id","op":"grant"|"revoke","inst","username","host","database","privilege"}
//!   {"id","op":"query","inst","sql"}                     -> {columns,rows,truncated}
//!   {"id","op":"backup","inst"}                          -> {op_id} (detached dump)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}
//! Responses: {"id","ok":true,"data":..} / {"id","ok":false,"error":".."}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use bollard::Docker;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, http::header::AUTHORIZATION, Message},
};

use crate::config::AgentConfig;

/// Label marking a TeaOps-managed MySQL/MariaDB container.
const LABEL_MANAGED: &str = "teaops.mysql";
/// Label carrying our instance id on a managed container.
const LABEL_ID: &str = "teaops.mysql.id";
/// Label carrying the engine ("mysql"|"mariadb").
const LABEL_ENGINE: &str = "teaops.mysql.engine";

/// Connect to the local Docker daemon (or fail with a friendly hint).
fn dkr() -> Result<Docker> {
    Docker::connect_with_defaults().map_err(|e| {
        anyhow!("无法连接 Docker 守护进程：{e}（请先在 Docker 管理中安装并启动 Docker）")
    })
}

#[derive(Debug, Deserialize)]
struct Req {
    #[serde(default)]
    id: i64,
    op: String,
    /// instance id (start/stop/remove/...)
    #[serde(default)]
    inst: Option<String>,
    /// engine "mysql" | "mariadb" (install)
    #[serde(default)]
    engine: Option<String>,
    /// image version tag (install / switch_version)
    #[serde(default)]
    version: Option<String>,
    /// host port to publish 3306 on (install / change_port)
    #[serde(default)]
    port: Option<i64>,
    /// whether to publish the port to the host (install / change_port)
    #[serde(default)]
    expose: Option<bool>,
    /// keep the data volume on remove (default false = delete data too)
    #[serde(default)]
    keep_data: Option<bool>,
    /// op id (op_log / dismiss_op)
    #[serde(default)]
    op_id: Option<String>,
    /// account management: username / host / password / privileges / database
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    database: Option<String>,
    /// privilege scope: "all" (read+write) | "ro" (read-only) | "custom" later
    #[serde(default)]
    privilege: Option<String>,
    /// raw SQL for the query runner
    #[serde(default)]
    sql: Option<String>,
}

/// Persisted per-instance manifest (`<data>/mysql/<id>.json`, 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    id: String,
    engine: String,    // "mysql" | "mariadb"
    version: String,   // image tag, e.g. "8.0"
    container: String, // container name (teaops-mysql-<id>)
    volume: String,    // named data volume (teaops-mysql-<id>-data)
    /// host port if exposed, else None.
    port: Option<i64>,
    /// at-rest-encrypted root password (nonce:cipher), via crate::crypto.
    root_enc: String,
    created_at: i64,
}

// ---------------------------------------------------------------------------
// Supported engines + versions (curated). 8.0 is the default in the UI.
// ---------------------------------------------------------------------------

/// Curated version list per engine, newest first. The UI defaults to "8.0".
fn supported_versions(engine: &str) -> &'static [&'static str] {
    match engine {
        "mysql" => &["8.4", "8.0", "5.7"],
        "mariadb" => &["11.4", "10.11", "10.6"],
        _ => &[],
    }
}

/// Validate an engine name.
fn valid_engine(e: &str) -> bool {
    e == "mysql" || e == "mariadb"
}

/// Validate a version against the curated list for the engine (prevents an
/// arbitrary tag / injection into the image reference).
fn valid_version(engine: &str, version: &str) -> bool {
    supported_versions(engine).contains(&version)
}

/// The Docker image reference for an engine+version (official images only).
fn image_ref(engine: &str, version: &str) -> String {
    // Both `mysql` and `mariadb` are official Docker Hub images.
    format!("{engine}:{version}")
}

// ---------------------------------------------------------------------------
// Manifest store: <data>/mysql/<id>.json, 0600.
// ---------------------------------------------------------------------------

fn mysql_dir() -> std::path::PathBuf {
    crate::paths::data_dir().join("mysql")
}

fn manifest_path(id: &str) -> std::path::PathBuf {
    mysql_dir().join(format!("{id}.json"))
}

fn save_manifest(m: &Manifest) -> Result<()> {
    let dir = mysql_dir();
    std::fs::create_dir_all(&dir)?;
    let path = manifest_path(&m.id);
    let body = serde_json::to_string_pretty(m)?;
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_manifest(id: &str) -> Result<Manifest> {
    let raw = std::fs::read_to_string(manifest_path(id))
        .map_err(|_| anyhow!("找不到该实例（可能已删除）"))?;
    let m: Manifest = serde_json::from_str(&raw).map_err(|e| anyhow!("实例清单损坏：{e}"))?;
    Ok(m)
}

fn delete_manifest(id: &str) {
    let _ = std::fs::remove_file(manifest_path(id));
}

fn all_manifests() -> Vec<Manifest> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(mysql_dir()) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(raw) = std::fs::read_to_string(&p) {
                    if let Ok(m) = serde_json::from_str::<Manifest>(&raw) {
                        out.push(m);
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    out
}

/// Generate a strong random root password (no shell-special chars so it's safe
/// to pass as a separate argv entry / env value; length 24).
fn gen_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// A short instance id (8 hex chars).
fn new_inst_id() -> String {
    let mut rng = rand::thread_rng();
    let n: u64 = rng.gen();
    format!("{:08x}", (n & 0xffff_ffff) as u32)
}

// ---------------------------------------------------------------------------
// Detached op registry (install / switch_version): the client starts an op and
// polls list_ops / op_log so a long image pull survives leaving the page.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct OpState {
    kind: String,   // "install" | "switch"
    target: String, // instance id
    status: String, // "running" | "done" | "error"
    error: String,
    inst_id: String, // resulting instance id on success
    lines: Vec<String>,
}

fn ops() -> &'static Mutex<HashMap<String, OpState>> {
    static OPS: OnceLock<Mutex<HashMap<String, OpState>>> = OnceLock::new();
    OPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn new_op_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("mop{}", N.fetch_add(1, Ordering::Relaxed))
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
                inst_id: String::new(),
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

fn op_finish(op_id: &str, status: &str, error: &str, inst_id: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get_mut(op_id) {
            o.status = status.to_string();
            o.error = error.to_string();
            o.inst_id = inst_id.to_string();
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
                "inst_id": o.inst_id,
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
            "inst_id": o.inst_id,
            "kind": o.kind,
            "target": o.target,
        }),
        None => json!({ "lines": [], "status": "gone", "error": "" }),
    }
}

fn op_dismiss(op_id: &str) {
    if let Ok(mut m) = ops().lock() {
        if let Some(o) = m.get(op_id) {
            // Only forget finished ops; a running op stays.
            if o.status != "running" {
                m.remove(op_id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channel loop.
// ---------------------------------------------------------------------------

/// Connect to the backend mysql relay and serve the protocol until either side
/// closes. Stateless: long ops live in the global registry.
pub async fn run_mysql_channel(cfg: &AgentConfig, agent_token: &str, session: &str) -> Result<()> {
    let url = cfg.agent_mysql_ws_url(session);
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

/// Dispatch one request.
async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => info().await,
        "list" => list_instances().await,
        "install" => start_install(req),
        "switch_version" => start_switch(req),
        "start" => {
            let m = load_manifest(need_inst(req)?)?;
            dkr()?
                .start_container(
                    &m.container,
                    None::<bollard::container::StartContainerOptions<String>>,
                )
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "started": m.id }))
        }
        "stop" => {
            let m = load_manifest(need_inst(req)?)?;
            let opts = bollard::container::StopContainerOptions { t: 20 };
            dkr()?
                .stop_container(&m.container, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "stopped": m.id }))
        }
        "restart" => {
            let m = load_manifest(need_inst(req)?)?;
            let opts = bollard::container::RestartContainerOptions { t: 20 };
            dkr()?
                .restart_container(&m.container, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "restarted": m.id }))
        }
        "remove" => remove_instance(req).await,
        "reset_password" => reset_password(req).await,
        "change_port" => change_port(req).await,
        "databases" => databases(req).await,
        "credentials" => credentials(req).await,
        "list_users" => list_users(req).await,
        "create_user" => create_user(req).await,
        "drop_user" => drop_user(req).await,
        "grant" => grant(req).await,
        "revoke" => revoke(req).await,
        "query" => query(req).await,
        "backup" => start_backup(req),
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => Ok(op_log(req.op_id.as_deref().unwrap_or(""))),
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
        other => Err(anyhow!("不支持的操作：{other}")),
    }
}

fn need_inst(req: &Req) -> Result<&str> {
    req.inst
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("缺少实例 id"))
}

// ---------------------------------------------------------------------------
// info / list.
// ---------------------------------------------------------------------------

/// Detect Docker availability and report the curated engine/version catalog so
/// the client can render the install form (or prompt to set up Docker first).
async fn info() -> Result<Value> {
    let docker_ok = match dkr() {
        Ok(d) => d.ping().await.is_ok(),
        Err(_) => false,
    };
    Ok(json!({
        "docker_ok": docker_ok,
        "engines": [
            { "key": "mysql", "name": "MySQL", "versions": supported_versions("mysql"), "default": "8.0" },
            { "key": "mariadb", "name": "MariaDB", "versions": supported_versions("mariadb"), "default": "10.11" },
        ],
        "default_engine": "mysql",
    }))
}

/// List TeaOps-managed instances (from manifests), enriched with live container
/// state. Manifests are the source of truth for ownership — we never list a
/// container we didn't create.
async fn list_instances() -> Result<Value> {
    let dkr = dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr.list_containers(Some(opts)).await.unwrap_or_default();

    let mut items = Vec::new();
    for m in all_manifests() {
        // Find the matching container by name (manifests are authoritative).
        let c = containers.iter().find(|c| {
            c.names
                .as_ref()
                .map(|ns| ns.iter().any(|n| n.trim_start_matches('/') == m.container))
                .unwrap_or(false)
        });
        let (state, status) = match c {
            Some(c) => (
                c.state.clone().unwrap_or_default(),
                c.status.clone().unwrap_or_default(),
            ),
            None => ("missing".to_string(), "容器不存在".to_string()),
        };

        // A `running` container may still be initializing its data dir (queries
        // fail until mysqld is up). Probe so the UI can show "初始化中" vs
        // "运行中". `restarting` usually means an init/config failure loop.
        let mut phase = state.clone();
        let mut ready = false;
        if state == "running" {
            let pwd = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
            ready = is_ready_cached(&m.container, &pwd).await;
            if !ready {
                phase = "initializing".to_string();
            }
        }

        items.push(json!({
            "id": m.id,
            "engine": m.engine,
            "version": m.version,
            "container": m.container,
            "port": m.port,
            "exposed": m.port.is_some(),
            "state": state,
            "phase": phase,
            "ready": ready,
            "status": status,
            "running": state == "running",
            "created_at": m.created_at,
        }));
    }
    Ok(json!({ "instances": items }))
}

/// Map a bollard error to a short friendly message.
fn friendly(e: &bollard::errors::Error) -> String {
    let s = e.to_string();
    if s.contains("No such container") || s.contains("404") {
        "容器不存在（实例可能已被手动删除）".to_string()
    } else if s.contains("Cannot connect") || s.contains("permission denied") {
        "无法连接 Docker 守护进程".to_string()
    } else {
        s.chars().take(300).collect()
    }
}

// ---------------------------------------------------------------------------
// install (detached): pull image, create data volume, create + start container.
// ---------------------------------------------------------------------------

fn validate_port(port: i64) -> Result<()> {
    if !(1..=65535).contains(&port) {
        return Err(anyhow!("端口需为 1-65535"));
    }
    Ok(())
}

/// Start a detached install op. Returns `{op_id}` immediately.
fn start_install(req: &Req) -> Result<Value> {
    let engine = req
        .engine
        .as_deref()
        .map(str::trim)
        .unwrap_or("mysql")
        .to_string();
    if !valid_engine(&engine) {
        return Err(anyhow!("不支持的数据库类型"));
    }
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("8.0")
        .to_string();
    if !valid_version(&engine, &version) {
        return Err(anyhow!("不支持的版本"));
    }
    let expose = req.expose.unwrap_or(false);
    let port = if expose {
        let p = req.port.unwrap_or(3306);
        validate_port(p)?;
        Some(p)
    } else {
        None
    };

    let inst_id = new_inst_id();
    let op_id = new_op_id();
    op_create(&op_id, "install", &inst_id);

    let op_t = op_id.clone();
    let inst_t = inst_id.clone();
    tokio::spawn(async move {
        match run_install_detached(&op_t, &engine, &version, port, &inst_t).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst_id }))
}

/// Pull the image (streaming progress), create the data volume, then create and
/// start the container with a generated root password. Writes the manifest on
/// success so the instance is tracked even across restarts.
async fn run_install_detached(
    op_id: &str,
    engine: &str,
    version: &str,
    port: Option<i64>,
    inst_id: &str,
) -> Result<()> {
    let dkr = dkr()?;
    let image = image_ref(engine, version);

    // 0. If exposing a host port, fail fast when it's already published by
    // another container (a clearer error than Docker's late "port is allocated").
    if let Some(p) = port {
        if let Some(owner) = host_port_owner(&dkr, p).await {
            return Err(anyhow!(
                "宿主机端口 {p} 已被容器 {owner} 占用，请换一个端口"
            ));
        }
    }

    // 1. Pull the image (stream status lines into the op log).
    op_push(op_id, &format!("正在拉取镜像 {image} …"));
    pull_image(&dkr, &image, op_id).await?;

    // 2. Create a named data volume so the data survives container recreation.
    let volume = format!("teaops-mysql-{inst_id}-data");
    op_push(op_id, "正在创建数据卷 …");
    create_volume(&dkr, &volume, inst_id, engine).await?;

    // 3. Generate + encrypt the root password.
    let password = gen_password();
    let root_enc = crate::crypto::encrypt(&password);

    // 4. Create + start the container.
    let container = format!("teaops-mysql-{inst_id}");
    op_push(op_id, "正在创建容器 …");
    create_mysql_container(
        &dkr, &container, &image, engine, inst_id, &volume, port, &password,
    )
    .await?;
    op_push(op_id, "正在启动 …");
    dkr.start_container(
        &container,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| anyhow!(friendly(&e)))?;

    // 5. Persist the manifest first (now the instance is officially
    // TeaOps-managed and will show up in the list even while initializing).
    let m = Manifest {
        id: inst_id.to_string(),
        engine: engine.to_string(),
        version: version.to_string(),
        container: container.clone(),
        volume,
        port,
        root_enc,
        created_at: now_secs(),
    };
    save_manifest(&m)?;

    // 6. Wait for mysqld to actually accept connections (data-dir init takes a
    // while on first run). The container is `running` almost immediately but
    // queries fail until this completes, so block the op until it's truly ready.
    op_push(op_id, "等待数据库就绪 …");
    if wait_ready(&container, &password, op_id, 180).await {
        op_push(op_id, "安装完成，数据库已就绪");
    } else {
        // Don't hard-fail: the container exists and may still come up. Surface
        // a clear hint so the user knows to check the container's state.
        op_push(
            op_id,
            "数据库初始化超时，请稍后在实例详情中查看状态（容器可能仍在初始化或反复重启）",
        );
    }
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Pull an image, pushing each progress status line into the op log.
async fn pull_image(dkr: &Docker, image: &str, op_id: &str) -> Result<()> {
    let opts = bollard::image::CreateImageOptions {
        from_image: image.to_string(),
        ..Default::default()
    };
    let mut stream = dkr.create_image(Some(opts), None, None);
    let mut last = String::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                let line = info.status.unwrap_or_default();
                if !line.is_empty() && line != last {
                    op_push(op_id, &line);
                    last = line;
                }
            }
            Err(e) => return Err(anyhow!("拉取镜像失败：{}", friendly(&e))),
        }
    }
    Ok(())
}

/// True if a host TCP port is already published by an existing container.
/// Returns the owning container's name when occupied, else None.
async fn host_port_owner(dkr: &Docker, port: i64) -> Option<String> {
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr.list_containers(Some(opts)).await.ok()?;
    for c in containers {
        if let Some(ports) = &c.ports {
            for p in ports {
                if p.public_port == Some(port as u16) {
                    let name = c
                        .names
                        .as_ref()
                        .and_then(|n| n.first())
                        .map(|s| s.trim_start_matches('/').to_string())
                        .unwrap_or_else(|| "未知".to_string());
                    return Some(name);
                }
            }
        }
    }
    None
}

/// Create a named volume tagged as TeaOps-managed.
async fn create_volume(dkr: &Docker, name: &str, inst_id: &str, engine: &str) -> Result<()> {
    let mut labels = HashMap::new();
    labels.insert(LABEL_MANAGED.to_string(), "1".to_string());
    labels.insert(LABEL_ID.to_string(), inst_id.to_string());
    labels.insert(LABEL_ENGINE.to_string(), engine.to_string());
    let opts = bollard::volume::CreateVolumeOptions {
        name: name.to_string(),
        labels,
        ..Default::default()
    };
    dkr.create_volume(opts)
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("创建数据卷失败：{}", friendly(&e)))
}

/// Create (not start) a MySQL/MariaDB container with the data volume mounted,
/// the root password set, TeaOps labels applied, and an optional host port
/// binding for 3306. All values are validated; nothing is passed to a shell.
#[allow(clippy::too_many_arguments)]
async fn create_mysql_container(
    dkr: &Docker,
    container: &str,
    image: &str,
    engine: &str,
    inst_id: &str,
    volume: &str,
    port: Option<i64>,
    password: &str,
) -> Result<()> {
    use bollard::models::{HostConfig, PortBinding, RestartPolicy, RestartPolicyNameEnum};

    // Root password env. MySQL reads MYSQL_ROOT_PASSWORD; MariaDB reads
    // MARIADB_ROOT_PASSWORD but also honors MYSQL_ROOT_PASSWORD — set both so
    // either engine initializes cleanly.
    let env = vec![
        format!("MYSQL_ROOT_PASSWORD={password}"),
        format!("MARIADB_ROOT_PASSWORD={password}"),
    ];

    // Mount the named volume at the data dir (same path for MySQL & MariaDB).
    let binds = vec![format!("{volume}:/var/lib/mysql")];

    // Optional host port -> container 3306/tcp.
    let mut exposed: HashMap<String, HashMap<(), ()>> = HashMap::new();
    let mut bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::new();
    exposed.insert("3306/tcp".to_string(), HashMap::new());
    if let Some(p) = port {
        bindings.insert(
            "3306/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(p.to_string()),
            }]),
        );
    }

    let mut labels = HashMap::new();
    labels.insert(LABEL_MANAGED.to_string(), "1".to_string());
    labels.insert(LABEL_ID.to_string(), inst_id.to_string());
    labels.insert(LABEL_ENGINE.to_string(), engine.to_string());

    let host_config = HostConfig {
        restart_policy: Some(RestartPolicy {
            name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
            maximum_retry_count: None,
        }),
        binds: Some(binds),
        port_bindings: if bindings.is_empty() {
            None
        } else {
            Some(bindings)
        },
        ..Default::default()
    };

    let config = bollard::container::Config {
        image: Some(image.to_string()),
        env: Some(env),
        labels: Some(labels),
        exposed_ports: Some(exposed),
        host_config: Some(host_config),
        ..Default::default()
    };

    let options = Some(bollard::container::CreateContainerOptions {
        name: container.to_string(),
        platform: None,
    });
    dkr.create_container(options, config)
        .await
        .map(|_| ())
        .map_err(|e| anyhow!("创建容器失败：{}", friendly(&e)))
}

// ---------------------------------------------------------------------------
// remove / credentials / reset_password.
// ---------------------------------------------------------------------------

/// Remove an instance: force-remove the container, optionally delete the data
/// volume, then drop the manifest. `keep_data=true` preserves the volume.
async fn remove_instance(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let keep_data = req.keep_data.unwrap_or(false);
    let dkr = dkr()?;

    // Force-remove the container (ignore "no such container").
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        v: false, // we manage the named volume separately
        ..Default::default()
    };
    if let Err(e) = dkr.remove_container(&m.container, Some(opts)).await {
        let s = e.to_string();
        if !s.contains("No such container") && !s.contains("404") {
            return Err(anyhow!(friendly(&e)));
        }
    }

    if !keep_data {
        // Remove the named data volume (force).
        if let Err(e) = dkr
            .remove_volume(
                &m.volume,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await
        {
            let s = e.to_string();
            if !s.contains("No such volume") && !s.contains("404") {
                return Err(anyhow!("删除数据卷失败：{}", friendly(&e)));
            }
        }
    }

    delete_manifest(&m.id);
    Ok(json!({ "removed": m.id, "kept_data": keep_data }))
}

/// Return connection credentials (decrypted root password) for an instance.
async fn credentials(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    Ok(json!({
        "host": "127.0.0.1",
        "port": m.port,
        "exposed": m.port.is_some(),
        "user": "root",
        "password": password,
        "engine": m.engine,
        "version": m.version,
    }))
}

/// Reset the root password: generate a new one, apply it inside the running
/// container via the mysql client, then persist the new ciphertext.
async fn reset_password(req: &Req) -> Result<Value> {
    let mut m = load_manifest(need_inst(req)?)?;
    let old = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let new = gen_password();

    // ALTER USER over the local socket, authenticating with the current root
    // password. Values are passed as separate argv entries (no shell).
    let sql = format!(
        "ALTER USER 'root'@'localhost' IDENTIFIED BY '{}'; ALTER USER 'root'@'%' IDENTIFIED BY '{}'; FLUSH PRIVILEGES;",
        sql_escape(&new),
        sql_escape(&new)
    );
    let (code, out) = mysql_exec(&m.container, &old, &sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "重置密码失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    m.root_enc = crate::crypto::encrypt(&new);
    save_manifest(&m)?;
    Ok(json!({ "password": new }))
}

/// Escape a value for safe inclusion inside a single-quoted SQL string literal.
/// Backslashes and single quotes are doubled/escaped. The password charset
/// already excludes quotes/backslashes, but we escape defensively.
fn sql_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

// ---------------------------------------------------------------------------
// change_port / switch_version: recreate the container, reusing the data volume.
// ---------------------------------------------------------------------------

/// Change (or remove) the host port mapping. Recreates the container against
/// the same data volume and root password; the data is untouched.
async fn change_port(req: &Req) -> Result<Value> {
    let mut m = load_manifest(need_inst(req)?)?;
    let expose = req.expose.unwrap_or(false);
    let new_port = if expose {
        let p = req.port.unwrap_or(3306);
        validate_port(p)?;
        Some(p)
    } else {
        None
    };

    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let image = image_ref(&m.engine, &m.version);
    // Reject a host port already owned by a *different* container.
    if let Some(p) = new_port {
        let dkr = dkr()?;
        if let Some(owner) = host_port_owner(&dkr, p).await {
            if owner != m.container {
                return Err(anyhow!(
                    "宿主机端口 {p} 已被容器 {owner} 占用，请换一个端口"
                ));
            }
        }
    }
    recreate_container(&m, &image, new_port, &password).await?;
    m.port = new_port;
    save_manifest(&m)?;
    Ok(json!({ "id": m.id, "port": new_port, "exposed": new_port.is_some() }))
}

/// Switch an instance to a different version (detached). Pulls the new image,
/// removes the old container (keeping the data volume), and recreates against
/// the new image. A downgrade across major versions can fail to start — the op
/// log surfaces the engine's error.
fn start_switch(req: &Req) -> Result<Value> {
    let inst = need_inst(req)?.to_string();
    let m = load_manifest(&inst)?;
    let version = req
        .version
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !valid_version(&m.engine, &version) {
        return Err(anyhow!("不支持的版本"));
    }
    if version == m.version {
        return Err(anyhow!("已是该版本"));
    }

    let op_id = new_op_id();
    op_create(&op_id, "switch", &inst);
    let op_t = op_id.clone();
    let inst_t = inst.clone();
    tokio::spawn(async move {
        match run_switch_detached(&op_t, &inst_t, &version).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst }))
}

async fn run_switch_detached(op_id: &str, inst: &str, version: &str) -> Result<()> {
    let mut m = load_manifest(inst)?;
    let dkr = dkr()?;
    let image = image_ref(&m.engine, version);

    op_push(op_id, &format!("正在拉取镜像 {image} …"));
    pull_image(&dkr, &image, op_id).await?;

    // Remove the old container (keep the data volume!).
    op_push(op_id, "正在停止旧容器 …");
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        v: false,
        ..Default::default()
    };
    if let Err(e) = dkr.remove_container(&m.container, Some(opts)).await {
        let s = e.to_string();
        if !s.contains("No such container") && !s.contains("404") {
            return Err(anyhow!(friendly(&e)));
        }
    }

    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    op_push(op_id, "正在用新版本重建容器 …");
    create_mysql_container(
        &dkr,
        &m.container,
        &image,
        &m.engine,
        &m.id,
        &m.volume,
        m.port,
        &password,
    )
    .await?;
    dkr.start_container(
        &m.container,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| anyhow!(friendly(&e)))?;

    m.version = version.to_string();
    save_manifest(&m)?;
    op_push(op_id, "等待数据库就绪 …");
    if wait_ready(&m.container, &password, op_id, 180).await {
        op_push(op_id, "版本切换完成，数据库已就绪");
    } else {
        op_push(
            op_id,
            "切换后数据库初始化超时，可能与目标版本不兼容（尤其是降级），请在实例详情中查看状态",
        );
    }
    Ok(())
}

/// Remove + recreate the container with the same labels/volume/password but a
/// new port mapping. Used by change_port.
async fn recreate_container(
    m: &Manifest,
    image: &str,
    port: Option<i64>,
    password: &str,
) -> Result<()> {
    let dkr = dkr()?;
    let opts = bollard::container::RemoveContainerOptions {
        force: true,
        v: false,
        ..Default::default()
    };
    if let Err(e) = dkr.remove_container(&m.container, Some(opts)).await {
        let s = e.to_string();
        if !s.contains("No such container") && !s.contains("404") {
            return Err(anyhow!(friendly(&e)));
        }
    }
    create_mysql_container(
        &dkr,
        &m.container,
        image,
        &m.engine,
        &m.id,
        &m.volume,
        port,
        password,
    )
    .await?;
    dkr.start_container(
        &m.container,
        None::<bollard::container::StartContainerOptions<String>>,
    )
    .await
    .map_err(|e| anyhow!(friendly(&e)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// databases: read-only listing of databases with table count + size.
// ---------------------------------------------------------------------------

/// List databases with table count and on-disk size (from information_schema).
/// System schemas are flagged so the UI can de-emphasize them.
async fn databases(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();

    // Tab-separated output: schema \t tables \t bytes. ORDER keeps it stable.
    let sql = "SELECT s.schema_name, \
        (SELECT COUNT(*) FROM information_schema.tables t WHERE t.table_schema = s.schema_name) AS tbls, \
        COALESCE((SELECT SUM(data_length + index_length) FROM information_schema.tables t WHERE t.table_schema = s.schema_name),0) AS bytes \
        FROM information_schema.schemata s ORDER BY s.schema_name;";
    let (code, out) = mysql_exec_query(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }

    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    let mut dbs = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() || name == "schema_name" {
            continue; // skip a header row if the client emits one
        }
        let tables: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let bytes: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        dbs.push(json!({
            "name": name,
            "tables": tables,
            "bytes": bytes,
            "system": SYS.contains(&name),
        }));
    }
    Ok(json!({ "databases": dbs }))
}

// ---------------------------------------------------------------------------
// Account management (B): list / create / drop users, grant / revoke.
// ---------------------------------------------------------------------------

/// Validate a MySQL identifier (username / database / host) used inside quoted
/// SQL. We allow a conservative charset so a value can't break out of its quote
/// even though we also escape; `%` is allowed for the host wildcard.
fn valid_ident(s: &str, allow_wildcard: bool) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || (allow_wildcard && c == '%')
    })
}

/// Backtick-escape an identifier (double any backticks) for `\`name\``.
fn ident_quote(s: &str) -> String {
    format!("`{}`", s.replace('`', "``"))
}

/// List non-system MySQL accounts as {user, host}. Reads mysql.user.
async fn list_users(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let sql = "SELECT User, Host FROM mysql.user ORDER BY User, Host;";
    let (code, out) = mysql_exec_query(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    // System/internal accounts we don't surface for management.
    const SYS_USERS: [&str; 6] = [
        "mysql.sys",
        "mysql.session",
        "mysql.infoschema",
        "root",
        "mariadb.sys",
        "healthcheck",
    ];
    let mut users = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let user = it.next().unwrap_or("").trim();
        let host = it.next().unwrap_or("").trim();
        if user.is_empty() {
            continue;
        }
        users.push(json!({
            "user": user,
            "host": host,
            "system": SYS_USERS.contains(&user),
        }));
    }
    Ok(json!({ "users": users }))
}

/// Create a user `'name'@'host'` with a password. Returns nothing extra.
async fn create_user(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let pwd = req.password.as_deref().unwrap_or("");
    if !valid_ident(user, false) {
        return Err(anyhow!("用户名只能包含字母、数字、_ - . 且不超过 64 字符"));
    }
    if !valid_ident(host, true) {
        return Err(anyhow!("主机格式不合法（可用 % 通配）"));
    }
    if pwd.is_empty() || pwd.len() > 128 {
        return Err(anyhow!("密码不能为空且不超过 128 字符"));
    }
    let sql = format!(
        "CREATE USER '{}'@'{}' IDENTIFIED BY '{}';",
        sql_escape(user),
        sql_escape(host),
        sql_escape(pwd)
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "created": user, "host": host }))
}

/// Drop a user `'name'@'host'`. root and system accounts are protected.
async fn drop_user(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(anyhow!("用户或主机不合法"));
    }
    if user.eq_ignore_ascii_case("root")
        || user.starts_with("mysql.")
        || user.starts_with("mariadb.")
    {
        return Err(anyhow!("不允许删除系统账号"));
    }
    let sql = format!("DROP USER '{}'@'{}';", sql_escape(user), sql_escape(host));
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "dropped": user, "host": host }))
}

/// Grant privileges on a database to a user. `privilege` is "all" (read+write)
/// or "ro" (SELECT only). Database "*" means all databases.
async fn grant(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let db = req.database.as_deref().map(str::trim).unwrap_or("*");
    let priv_kind = req.privilege.as_deref().unwrap_or("all");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(anyhow!("用户或主机不合法"));
    }
    let privs = match priv_kind {
        "ro" => "SELECT",
        "all" => "ALL PRIVILEGES",
        _ => return Err(anyhow!("不支持的权限类型")),
    };
    let scope = grant_scope(db)?;
    let sql = format!(
        "GRANT {privs} ON {scope} TO '{}'@'{}'; FLUSH PRIVILEGES;",
        sql_escape(user),
        sql_escape(host)
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "granted": priv_kind, "db": db }))
}

/// Revoke all privileges on a database from a user.
async fn revoke(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let db = req.database.as_deref().map(str::trim).unwrap_or("*");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(anyhow!("用户或主机不合法"));
    }
    let scope = grant_scope(db)?;
    let sql = format!(
        "REVOKE ALL PRIVILEGES, GRANT OPTION ON {scope} FROM '{}'@'{}'; FLUSH PRIVILEGES;",
        sql_escape(user),
        sql_escape(host)
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "revoked": db }))
}

/// Build a GRANT scope `\`db\`.*` or `*.*`. Validates the db identifier.
fn grant_scope(db: &str) -> Result<String> {
    if db == "*" {
        Ok("*.*".to_string())
    } else if valid_ident(db, false) {
        Ok(format!("{}.*", ident_quote(db)))
    } else {
        Err(anyhow!("数据库名不合法"))
    }
}

/// Run a statement expecting success; surfaces the engine's error message.
async fn run_stmt(container: &str, password: &str, sql: &str) -> Result<()> {
    let (code, out) = mysql_exec(container, password, sql).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            out.trim().chars().take(240).collect::<String>()
        ))
    }
}

// ---------------------------------------------------------------------------
// Query runner (B): run arbitrary SQL, return columns + rows for display.
// ---------------------------------------------------------------------------

/// Execute a user-supplied SQL statement and return a tabular result. Output is
/// capped to keep the payload small. This is a power-user tool: writes are
/// allowed (the UI warns), but the result is always truncated.
async fn query(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let sql = req.sql.as_deref().map(str::trim).unwrap_or("");
    if sql.is_empty() {
        return Err(anyhow!("SQL 不能为空"));
    }
    if sql.len() > 8192 {
        return Err(anyhow!("SQL 过长"));
    }

    // Column-mode (-B) keeps a header row + tab-separated columns; we cap rows.
    let (code, out) = mysql_exec_columns(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "{}",
            out.trim().chars().take(300).collect::<String>()
        ));
    }

    // Parse: first line = header (column names), rest = rows. NULLs render as
    // the literal "NULL" from the client; we pass them through.
    const MAX_ROWS: usize = 200;
    let mut lines = out.lines();
    let columns: Vec<String> = match lines.next() {
        Some(h) if !h.is_empty() => h.split('\t').map(|s| s.to_string()).collect(),
        _ => {
            // No result set (e.g. an UPDATE/DDL). Report affected as a note.
            return Ok(json!({ "columns": [], "rows": [], "note": "执行成功（无结果集）" }));
        }
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut truncated = false;
    for line in lines {
        if rows.len() >= MAX_ROWS {
            truncated = true;
            break;
        }
        rows.push(line.split('\t').map(|s| s.to_string()).collect());
    }
    Ok(json!({
        "columns": columns,
        "rows": rows,
        "truncated": truncated,
        "row_count": rows.len(),
    }))
}

// ---------------------------------------------------------------------------
// Backup (B): mysqldump the whole instance to a SQL file, return its text.
// ---------------------------------------------------------------------------

/// Start a detached backup op (mysqldump). The op log streams progress; on
/// success the dump is written to a file inside the container and its path +
/// size are reported. (Download wiring is a follow-up; this captures the dump
/// safely without holding it all in a single WS frame.)
fn start_backup(req: &Req) -> Result<Value> {
    let inst = need_inst(req)?.to_string();
    let _ = load_manifest(&inst)?; // validate it exists
    let op_id = new_op_id();
    op_create(&op_id, "backup", &inst);
    let op_t = op_id.clone();
    let inst_t = inst.clone();
    tokio::spawn(async move {
        match run_backup_detached(&op_t, &inst_t).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst }))
}

/// Run `mysqldump --all-databases` inside the container, writing to
/// `/var/lib/mysql/teaops-backup-<ts>.sql` (on the persistent data volume so it
/// survives), and report the path + size.
async fn run_backup_detached(op_id: &str, inst: &str) -> Result<()> {
    let m = load_manifest(inst)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    if !is_ready(&m.container, &password).await {
        return Err(anyhow!("实例未就绪，无法备份"));
    }
    op_push(op_id, "正在导出数据库（mysqldump）…");
    let ts = now_secs();
    let path = format!("/var/lib/mysql/teaops-backup-{ts}.sql");
    // Use the dump tool that matches the engine; both accept the same flags.
    let script = format!(
        "if command -v mysqldump >/dev/null 2>&1; then DUMP=mysqldump; else DUMP=mariadb-dump; fi; \
         \"$DUMP\" -uroot --all-databases --single-transaction --routines --events > '{}' 2>/tmp/dumperr; \
         rc=$?; if [ $rc -ne 0 ]; then cat /tmp/dumperr; exit $rc; fi; \
         wc -c < '{}'",
        path, path
    );
    let (code, out) = exec_sh(&m.container, &password, &script).await?;
    if code != 0 {
        return Err(anyhow!(
            "备份失败：{}",
            out.trim().chars().take(240).collect::<String>()
        ));
    }
    let bytes: i64 = out
        .trim()
        .lines()
        .last()
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    op_push(op_id, &format!("备份完成：{path}（{bytes} 字节）"));
    Ok(())
}

// ---------------------------------------------------------------------------
// In-container mysql client exec helpers.
// ---------------------------------------------------------------------------

/// Run a SQL statement inside the container using the bundled `mysql`/`mariadb`
/// client over the local socket, authenticating as root. The password is passed
/// via the `MYSQL_PWD` env var (not argv) and the SQL via `-e`. Returns
/// (exit_code, combined_output).
async fn mysql_exec(container: &str, password: &str, sql: &str) -> Result<(i64, String)> {
    exec_client(container, password, sql, false).await
}

/// Like `mysql_exec` but requests batch/tab-separated, header-less output
/// (`-N -B`) suitable for parsing query results.
async fn mysql_exec_query(container: &str, password: &str, sql: &str) -> Result<(i64, String)> {
    exec_client(container, password, sql, true).await
}

/// Run a SQL statement returning batch/tab-separated output *with* the header
/// row (`-B`, no `-N`), used by the query runner to render column names.
async fn mysql_exec_columns(container: &str, password: &str, sql: &str) -> Result<(i64, String)> {
    exec_argv(
        container,
        password,
        vec![
            "-uroot".to_string(),
            "--protocol=socket".to_string(),
            "-B".to_string(),
            "-e".to_string(),
            sql.to_string(),
        ],
    )
    .await
}

/// Run an arbitrary `/bin/sh -c` script inside the container with `MYSQL_PWD`
/// set (so a dump tool can authenticate). Returns (exit_code, combined output).
async fn exec_sh(container: &str, password: &str, script: &str) -> Result<(i64, String)> {
    exec_raw(
        container,
        password,
        vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
    )
    .await
}

/// Exec the mysql client inside the container. `batch` adds `-N -B` for
/// machine-readable output. `MYSQL_PWD` carries the password so it never
/// appears in argv / process list.
async fn exec_client(
    container: &str,
    password: &str,
    sql: &str,
    batch: bool,
) -> Result<(i64, String)> {
    let mut args: Vec<String> = vec!["-uroot".to_string(), "--protocol=socket".to_string()];
    if batch {
        args.push("-N".to_string());
        args.push("-B".to_string());
    }
    args.push("-e".to_string());
    args.push(sql.to_string());
    exec_argv(container, password, args).await
}

/// Run the mysql/mariadb client inside the container with the given client args
/// (a small shell test picks whichever client binary exists). `MYSQL_PWD`
/// carries the password. Returns (exit_code, combined output).
async fn exec_argv(
    container: &str,
    password: &str,
    client_args: Vec<String>,
) -> Result<(i64, String)> {
    let mut cmd: Vec<String> = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        // `exec` so the client's exit code is the exec's exit code.
        "if command -v mysql >/dev/null 2>&1; then exec mysql \"$@\"; else exec mariadb \"$@\"; fi"
            .to_string(),
        "sh".to_string(),
    ];
    cmd.extend(client_args);
    exec_raw(container, password, cmd).await
}

/// Low-level container exec: run `cmd` (argv) with `MYSQL_PWD` set. Returns
/// (exit_code, combined stdout+stderr).
async fn exec_raw(container: &str, password: &str, cmd: Vec<String>) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};

    let dkr = dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                env: Some(vec![format!("MYSQL_PWD={password}")]),
                cmd: Some(cmd),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{}", friendly(&e)))?;

    let started = dkr
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{}", friendly(&e)))?;

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

// ---------------------------------------------------------------------------
// Readiness probe.
// ---------------------------------------------------------------------------

/// Whether mysqld inside the container actually accepts connections yet. A
/// freshly-started container is `running` long before the server finishes
/// initializing its data dir, so we probe with a real `SELECT 1`.
async fn is_ready(container: &str, password: &str) -> bool {
    match mysql_exec_query(container, password, "SELECT 1;").await {
        Ok((code, _)) => code == 0,
        Err(_) => false,
    }
}

/// Cached readiness check for the polled `list` path: the client polls `list`
/// (e.g. every 1.5s) and probing every running instance with an exec each time
/// is wasteful. Cache the result briefly so repeated list calls don't re-exec.
/// `wait_ready` deliberately bypasses this and probes fresh.
async fn is_ready_cached(container: &str, password: &str) -> bool {
    use std::sync::OnceLock;
    use std::time::Instant;
    static CACHE: OnceLock<Mutex<HashMap<String, (bool, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    const TTL: std::time::Duration = std::time::Duration::from_secs(5);

    if let Ok(m) = cache.lock() {
        if let Some((ready, at)) = m.get(container) {
            if at.elapsed() < TTL {
                return *ready;
            }
        }
    }
    let ready = is_ready(container, password).await;
    if let Ok(mut m) = cache.lock() {
        m.insert(container.to_string(), (ready, Instant::now()));
    }
    ready
}

/// Poll `is_ready` until it returns true or the timeout elapses. Pushes a few
/// progress lines into the op log so the UI shows "初始化中…" rather than a
/// silent hang. Returns true once ready, false on timeout.
async fn wait_ready(container: &str, password: &str, op_id: &str, timeout_secs: u64) -> bool {
    let start = std::time::Instant::now();
    let mut announced = false;
    loop {
        if is_ready(container, password).await {
            return true;
        }
        if start.elapsed().as_secs() >= timeout_secs {
            return false;
        }
        if !announced {
            op_push(op_id, "数据库正在初始化，请稍候 …");
            announced = true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_and_versions() {
        assert!(valid_engine("mysql"));
        assert!(valid_engine("mariadb"));
        assert!(!valid_engine("postgres"));
        assert!(valid_version("mysql", "8.0"));
        assert!(valid_version("mariadb", "10.11"));
        assert!(!valid_version("mysql", "10.11"));
        assert!(!valid_version("mysql", "8.0; rm -rf /"));
    }

    #[test]
    fn image_refs() {
        assert_eq!(image_ref("mysql", "8.0"), "mysql:8.0");
        assert_eq!(image_ref("mariadb", "10.11"), "mariadb:10.11");
    }

    #[test]
    fn password_is_shell_safe() {
        let p = gen_password();
        assert_eq!(p.len(), 24);
        assert!(!p.contains('\'') && !p.contains('"') && !p.contains('\\') && !p.contains('$'));
    }

    #[test]
    fn sql_escape_quotes() {
        assert_eq!(sql_escape("a'b"), "a\\'b");
        assert_eq!(sql_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn port_validation() {
        assert!(validate_port(3306).is_ok());
        assert!(validate_port(0).is_err());
        assert!(validate_port(70000).is_err());
    }

    #[test]
    fn ident_validation() {
        assert!(valid_ident("app_user", false));
        assert!(valid_ident("my-db.1", false));
        assert!(!valid_ident("", false));
        assert!(!valid_ident("bad name", false));
        assert!(!valid_ident("drop;table", false));
        // wildcard only allowed for host.
        assert!(valid_ident("%", true));
        assert!(!valid_ident("%", false));
        assert!(!valid_ident(&"x".repeat(65), false));
    }

    #[test]
    fn ident_quote_escapes_backticks() {
        assert_eq!(ident_quote("db"), "`db`");
        assert_eq!(ident_quote("a`b"), "`a``b`");
    }

    #[test]
    fn grant_scope_forms() {
        assert_eq!(grant_scope("*").unwrap(), "*.*");
        assert_eq!(grant_scope("mydb").unwrap(), "`mydb`.*");
        assert!(grant_scope("bad db").is_err());
    }
}
