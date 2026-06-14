//! On-box Docker management for the web console.
//!
//! A request/response JSON protocol backed by the local Docker daemon (bollard,
//! no `docker` CLI), invoked directly by `web::server` via `web_dispatch`.
//!
//! Every request carries an `id`. Operations are a
//! fixed whitelist (no arbitrary command pass-through); user-supplied values
//! (image names, container ids, ...) are passed as separate argv entries to
//! `docker`, never interpolated into a shell, so there's no injection surface.
//!
//! Long-running operations (image pulls, Docker install) run **detached** in a
//! process-global registry, so they keep running even if the client leaves the
//! page. The client starts one (`pull_image`/`install`, which return an `op_id`
//! immediately) and then polls `list_ops` / `op_log` to watch progress and pick
//! up the result when it reconnects.
//!
//! Requests (client -> panel):
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
//! Responses (panel -> client): {"id","ok":true,"data":<json>} / {"id","ok":false,"error":".."}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Result};
use bollard::Docker;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    #[allow(dead_code)]
    id: i64,
    op: String,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    mirror: Option<String>,
    /// Pull from a configured private registry (host prefix); empty = Docker Hub.
    #[serde(default)]
    registry: Option<String>,
    /// Docker settings payload (set_settings).
    #[serde(default)]
    settings: Option<Value>,
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
    // network create options
    #[serde(default)]
    driver: Option<String>,
    #[serde(default)]
    subnet: Option<String>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    ip_range: Option<String>,
    // create_container: networking endpoint options
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    domainname: Option<String>,
    #[serde(default)]
    dns: Option<Vec<String>>,
    // create_container: extra resource limits
    #[serde(default)]
    cpu_shares: Option<i64>,
    #[serde(default)]
    privileged: Option<bool>,
    // edit/upgrade: when set, remove this existing container (by id/name) before
    // creating the new one so it can reuse the same name.
    #[serde(default)]
    replace: Option<String>,
    // rename_container
    #[serde(default)]
    new_name: Option<String>,
    // commit_container -> image repo:tag
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    // backup file name (list/delete/restore/download)
    #[serde(default)]
    backup: Option<String>,
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
    // docker install options
    #[serde(default)]
    channel: Option<String>, // "distro" (docker.io, default) | "ce" (official latest)
    #[serde(default)]
    region: Option<String>, // "auto" (default) | "cn" | "global"
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

/// Build a localizable progress line for the op log: a sentinel-delimited
/// `MSG` record the web console maps to `msg.<code>` (positional `{0}`, `{1}`…
/// args). An arg prefixed with `@` is itself a translation key resolved on the
/// client. Plain command output is pushed verbatim and rendered as-is.
fn pmsg(code: &str, args: &[&str]) -> String {
    let mut s = format!("\u{1e}MSG\u{1e}{code}");
    for a in args {
        s.push('\u{1e}');
        s.push_str(a);
    }
    s
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

/// Estimate 0..100 progress from pull/install log lines (counts layers that
/// Estimate 0..100 progress from pull/install log lines, weighting each layer
/// by its phase (downloading → download-complete → extracting → complete) and
/// averaging across all layers seen. Returns -1 when indeterminate. This makes
/// the bar advance steadily during download/extract instead of only jumping
/// when whole layers finish. The web/mini-program render an indeterminate bar
/// for -1. Shared by the nginx/mysql modules (their image pulls log the same
/// docker progress lines).
pub(crate) fn pull_pct(lines: &[String], status: &str) -> i64 {
    if status == "done" {
        return 100;
    }
    use std::collections::HashMap;
    // Per-layer phase weight (0.0..1.0), keyed by the layer's leading hex id.
    let mut layers: HashMap<String, f64> = HashMap::new();
    let phase = |l: &str| -> Option<f64> {
        if l.contains("Already exists") || l.contains("Pull complete") {
            Some(1.0)
        } else if l.contains("Extracting") {
            Some(0.80)
        } else if l.contains("Verifying Checksum") || l.contains("Download complete") {
            Some(0.55)
        } else if l.contains("Downloading") {
            Some(0.45)
        } else if l.contains("Waiting") || l.contains("Pulling fs layer") {
            Some(0.05)
        } else {
            None
        }
    };
    for ln in lines {
        let l = ln.as_str();
        if l.contains("Pulling from") || l.contains("Digest:") || l.contains("Status:") {
            continue;
        }
        let p = match phase(l) {
            Some(p) => p,
            None => continue,
        };
        let key: String = l
            .split_whitespace()
            .next()
            .map(|s| s.trim_end_matches(':').to_string())
            .unwrap_or_else(|| l.to_string());
        // Keep the furthest phase seen for this layer (never go backwards).
        let entry = layers.entry(key).or_insert(0.0);
        if p > *entry {
            *entry = p;
        }
    }
    if layers.is_empty() {
        return -1;
    }
    let sum: f64 = layers.values().sum();
    let pct = (sum / layers.len() as f64) * 100.0;
    pct.clamp(1.0, 99.0) as i64
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
                "pct": pull_pct(&o.lines, &o.status),
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

/// Public entrypoint for the local web console: parse a JSON request object
/// (same `{op, ...}` shape used over the backend relay) and run it. Returns the
/// op result `data` on success.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad docker request: {e}"))?;
    handle(&r).await
}

/// Dispatch one request. Long ops (`pull_image`, `install`) start a detached
/// task and return an `op_id` immediately.
async fn handle(req: &Req) -> Result<Value> {
    // Guard: DN7 Panel-managed service containers/images (nginx / mysql) can't be
    // operated on from the generic Docker channel at all — they're managed by
    // their own modules so state/volumes stay consistent. This applies to every
    // caller (web console AND the mini-program relay).
    const CONTAINER_OPS: &[&str] = &[
        "start_container",
        "stop_container",
        "restart_container",
        "remove_container",
        "logs",
        "inspect_container",
        "inspect_container_networks",
        "connect_network",
        "disconnect_network",
    ];
    if CONTAINER_OPS.contains(&req.op.as_str()) {
        if let Some(r) = req.reference.as_deref() {
            if let Some(why) = managed_container_guard(r).await {
                return Err(anyhow!(why));
            }
        }
    }
    if req.op == "remove_image" {
        if let Some(r) = req.reference.as_deref() {
            if managed_image_guard(r).await {
                return Err(anyhow!("ERR_CODE:docker.image_in_use_builtin"));
            }
        }
    }
    match req.op.as_str() {
        "info" => docker_info().await,
        "list_images" => list_images().await,
        "pull_image" => start_pull(req),
        "create_container" => start_create(req),
        "install" => start_install(req),
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
            // Protect DN7 Panel-managed service containers (nginx / mysql) from
            // deletion here — they must be removed from their own pages so the
            // associated state/volumes are handled correctly.
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
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
                .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_network_name"))?;
            validate_name(name)?;
            // Driver (whitelisted; default bridge).
            let driver = req
                .driver
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("bridge");
            if !net_driver_allowed(driver) {
                return Err(anyhow!("ERR_CODE:docker.bad_net_driver"));
            }
            // Optional IPv4 IPAM config.
            let subnet = opt_trim(&req.subnet);
            let gateway = opt_trim(&req.gateway);
            let ip_range = opt_trim(&req.ip_range);
            if let Some(s) = subnet.as_deref() {
                valid_cidr(s)?;
            }
            if let Some(g) = gateway.as_deref() {
                valid_ipv4(g)?;
            }
            if let Some(r) = ip_range.as_deref() {
                valid_cidr(r)?;
            }
            // Gateway / range only make sense with a subnet.
            if subnet.is_none() && (gateway.is_some() || ip_range.is_some()) {
                return Err(anyhow!("ERR_CODE:docker.net_range_needs_subnet"));
            }
            let ipam = if subnet.is_some() {
                bollard::models::Ipam {
                    config: Some(vec![bollard::models::IpamConfig {
                        subnet,
                        gateway,
                        ip_range,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }
            } else {
                Default::default()
            };
            let opts = bollard::network::CreateNetworkOptions {
                name: name.to_string(),
                driver: driver.to_string(),
                ipam,
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
                    "ERR_CODE:docker.network_in_use".to_string()
                } else if raw.contains("predefined") || raw.contains("pre-defined") {
                    "ERR_CODE:docker.network_predefined".to_string()
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
        "list_volumes" => list_volumes().await,
        "create_volume" => create_volume_op(req).await,
        "remove_volume" => remove_volume_op(req).await,
        "get_settings" => Ok(dk_settings_json()),
        "set_settings" => set_dk_settings(req).await,
        "pause_container" => {
            let r = need_ref(req)?;
            dkr()?
                .pause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "paused": r }))
        }
        "unpause_container" => {
            let r = need_ref(req)?;
            dkr()?
                .unpause_container(&r)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "resumed": r }))
        }
        "kill_container" => {
            let r = need_ref(req)?;
            if let Some(why) = managed_container_guard(&r).await {
                return Err(anyhow!(why));
            }
            dkr()?
                .kill_container(&r, None::<bollard::container::KillContainerOptions<String>>)
                .await
                .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            Ok(json!({ "killed": r }))
        }
        "rename_container" => rename_container(req).await,
        "commit_container" => commit_container_op(req).await,
        "container_stats" => container_stats(req).await,
        "get_container_config" => get_container_config(req).await,
        "backup_container" => start_backup_container(req),
        "list_backups" => list_backups(req).await,
        "delete_backup" => delete_backup(req),
        "restore_backup" => start_restore_backup(req),
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

/// DN7 Panel-managed service containers (nginx / mysql) must not be removed from
/// the generic Docker page — they have their own management pages that also
/// clean up the associated state/volumes. Returns `Some(reason)` to block the
/// removal, `None` to allow it. Identifies the target by inspecting its real
/// name + labels (the UI passes a short id, so a name string match isn't
/// enough). Inspect failures don't block (fail-open: a normal container).
async fn managed_container_guard(reference: &str) -> Option<String> {
    let dkr = dkr().ok()?;
    let c = dkr.inspect_container(reference, None).await.ok()?;
    let name = c.name.unwrap_or_default();
    let name = name.trim_start_matches('/');
    let labels = c
        .config
        .as_ref()
        .and_then(|cf| cf.labels.clone())
        .unwrap_or_default();
    let is_mysql = name == crate::mysql::CONTAINER || labels.contains_key("dn7.mysql");
    if is_mysql {
        Some("ERR_CODE:docker.container_managed_mysql".to_string())
    } else {
        None
    }
}

/// True if `reference` is an image used by a DN7 Panel-managed service container
/// (nginx / mysql) — such images can't be removed from the Docker page.
async fn managed_image_guard(reference: &str) -> bool {
    let dkr = match dkr() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let managed = managed_image_refs(&dkr).await;
    if managed.contains(reference) {
        return true;
    }
    // The caller may pass a short id; resolve the ref's image id and compare.
    if let Ok(insp) = dkr.inspect_image(reference).await {
        if let Some(id) = insp.id {
            let short = id
                .strip_prefix("sha256:")
                .unwrap_or(&id)
                .chars()
                .take(12)
                .collect::<String>();
            if managed.contains(&short) {
                return true;
            }
        }
        if let Some(tags) = insp.repo_tags {
            if tags.iter().any(|t| managed.contains(t)) {
                return true;
            }
        }
    }
    false
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
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_network_name"))?;
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
async fn list_images() -> Result<Value> {
    let dkr = dkr()?;
    // Determine which images are used by DN7 Panel-managed service containers
    // (nginx / mysql) so the UI can mark them "内置" and the panel can refuse
    // to remove them.
    let managed_images = managed_image_refs(&dkr).await;
    let used_images = all_used_image_refs(&dkr).await;
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
            "managed": managed_images.contains(&name) || managed_images.contains(&short_id),
            "in_use": used_images.contains(&name) || used_images.contains(&short_id),
        }));
    }
    Ok(json!({ "images": items }))
}

/// The set of image refs (repo:tag) + short ids used by DN7 Panel-managed service
/// containers (nginx / mysql). Used to mark those images "内置" and protect
/// them from removal.
async fn managed_image_refs(dkr: &Docker) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = match dkr.list_containers(Some(opts)).await {
        Ok(c) => c,
        Err(_) => return out,
    };
    for c in containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let has_mysql_label = c
            .labels
            .as_ref()
            .map(|l| l.contains_key("dn7.mysql"))
            .unwrap_or(false);
        let managed = name == crate::mysql::CONTAINER || has_mysql_label;
        if managed {
            if let Some(image) = c.image.clone() {
                out.insert(image);
            }
            if let Some(iid) = c.image_id.clone() {
                let short = iid
                    .strip_prefix("sha256:")
                    .unwrap_or(&iid)
                    .chars()
                    .take(12)
                    .collect::<String>();
                out.insert(short);
            }
        }
    }
    out
}

/// The set of image refs (repo:tag) + short ids used by ANY container (running
/// or stopped). Drives the image "in use" status badge.
async fn all_used_image_refs(dkr: &Docker) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = match dkr.list_containers(Some(opts)).await {
        Ok(c) => c,
        Err(_) => return out,
    };
    for c in containers {
        if let Some(image) = c.image.clone() {
            out.insert(image);
        }
        if let Some(iid) = c.image_id.clone() {
            let short = iid
                .strip_prefix("sha256:")
                .unwrap_or(&iid)
                .chars()
                .take(12)
                .collect::<String>();
            out.insert(short);
        }
    }
    out
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

    // Probe shell availability for all running containers concurrently rather
    // than sequentially — each probe waits up to ~500ms, so for N running
    // containers this turns ~N*500ms into ~500ms total.
    let shell_futs = containers.iter().map(|c| {
        let dkr = dkr.clone();
        let id = c.id.clone().unwrap_or_default();
        let running = c.state.as_deref() == Some("running");
        async move {
            if running {
                container_has_shell(&dkr, &id).await
            } else {
                false
            }
        }
    });
    let shells = futures_util::future::join_all(shell_futs).await;

    let mut items = Vec::new();
    for (c, has_shell) in containers.into_iter().zip(shells) {
        let id = c.id.clone().unwrap_or_default();
        let short_id = id.chars().take(12).collect::<String>();
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        let state = c.state.clone().unwrap_or_default();
        // DN7 Panel-managed service containers (nginx / mysql) are marked so the UI
        // can show "内置" and hide direct controls (the panel also refuses ops
        // on them — see `managed_container_guard`).
        let has_mysql_label = c
            .labels
            .as_ref()
            .map(|l| l.contains_key("dn7.mysql"))
            .unwrap_or(false);
        let managed = name == crate::mysql::CONTAINER || has_mysql_label;
        items.push(json!({
            "id": short_id,
            "name": name,
            "image": c.image.clone().unwrap_or_default(),
            "state": state,
            "status": c.status.clone().unwrap_or_default(),
            "ports": fmt_ports(&c.ports),
            "has_shell": has_shell,
            "managed": managed,
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
                cmd: Some(vec![
                    "/bin/sh",
                    "-c",
                    "for s in /bin/bash /bin/sh /bin/ash; do [ -x \"$s\" ] && exit 0; done; exit 1",
                ]),
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
        // First IPv4 subnet from the IPAM config (so the UI can suggest a
        // static address when joining this network).
        let subnet = n
            .ipam
            .as_ref()
            .and_then(|i| i.config.as_ref())
            .and_then(|cfgs| cfgs.iter().find_map(|c| c.subnet.clone()))
            .filter(|s| s.contains('.'))
            .unwrap_or_default();
        items.push(json!({
            "id": id,
            "name": n.name.clone().unwrap_or_default(),
            "driver": n.driver.clone().unwrap_or_default(),
            "scope": n.scope.clone().unwrap_or_default(),
            "subnet": subnet,
        }));
    }
    Ok(json!({ "networks": items }))
}

/// For one container, report the networks it's attached to and the networks it
/// could still be connected to (so the UI can offer connect/disconnect).
/// Predefined networks (`host`, `none`) aren't offered as attach targets and
/// the predefined ones can't be disconnected when they're the only one — the
/// UI surfaces the panel's docker error in that case rather than guessing.
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
    load_dk_settings().mirrors.iter().any(|m| m == host)
}

/// Whether `host` is a configured private registry (pull selector).
fn registry_allowed(host: &str) -> bool {
    load_dk_settings().registries.iter().any(|r| r == host)
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
    let registry = req
        .registry
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    // Decide the actual pull source and whether a rename is needed afterwards.
    let (pull_ref, final_ref) = if let Some(reg) = registry {
        // Private registry: pull `<registry>/<image>` verbatim (no Docker Hub
        // mirror applies). Validate against the configured list.
        if !registry_allowed(reg) {
            return Err(anyhow!("ERR_CODE:docker.bad_registry"));
        }
        (format!("{reg}/{}", with_default_tag(&image)), None)
    } else {
        match mirror {
            Some(host) => {
                if !mirror_allowed(host) {
                    return Err(anyhow!("ERR_CODE:docker.bad_mirror"));
                }
                match docker_io_path(&image) {
                    Some(path) => (format!("{host}/{path}"), Some(with_default_tag(&image))),
                    None => (image.clone(), None),
                }
            }
            None => (image.clone(), None),
        }
    };

    let shown = final_ref
        .clone()
        .unwrap_or_else(|| with_default_tag(&image));
    let op_id = new_op_id();
    op_create(&op_id, "pull", &shown);

    let op_id_t = op_id.clone();
    let shown_t = shown.clone();
    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.pulling", &[pull_ref.as_str()]));
        match run_pull_detached(&op_id_t, &pull_ref).await {
            Ok(()) => {
                if let Some(final_ref) = final_ref.as_deref() {
                    if final_ref != pull_ref {
                        op_push(&op_id_t, &pmsg("dk.renaming", &[final_ref]));
                        if let Err(e) = tag_image(&pull_ref, final_ref).await {
                            op_finish(&op_id_t, "error", &e.to_string(), "");
                            return;
                        }
                        let _ = remove_image_quiet(&pull_ref).await; // best-effort
                    }
                }
                op_push(&op_id_t, &pmsg("dk.done", &[]));
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
/// Pull `pull_ref` via the daemon's create_image stream, pushing each progress
/// status line into the op registry. Detects mid-stream errors (the daemon
/// reports a failed layer via the `error` field WITHOUT ending the stream as a
/// transport error) and verifies the image actually exists afterward, so a
/// failed pull (common on mainland networks without a mirror) never reports
/// success.
async fn run_pull_detached(op_id: &str, pull_ref: &str) -> Result<()> {
    let dkr = dkr()?;
    let opts = bollard::image::CreateImageOptions {
        from_image: pull_ref.to_string(),
        ..Default::default()
    };
    let mut stream = dkr.create_image(Some(opts), None, None);
    let mut last = String::new();
    let mut stream_error: Option<String> = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => {
                // The daemon signals a layer/pull failure inline via `error`
                // rather than closing the stream with a transport error.
                if let Some(err) = info.error {
                    let e = err.trim();
                    if !e.is_empty() {
                        op_push(op_id, &pmsg("dk.error", &[e]));
                        stream_error = Some(trim_msg(e).unwrap_or_else(|| "拉取失败".into()));
                        continue;
                    }
                }
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
    if let Some(err) = stream_error {
        return Err(anyhow!(err));
    }
    // Final verification: the image must actually exist now. The stream can end
    // without an explicit error even when nothing was pulled (e.g. a dropped
    // connection mid-transfer), so confirm before reporting success.
    dkr.inspect_image(pull_ref)
        .await
        .map_err(|_| anyhow!("ERR_CODE:docker.pull_incomplete"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Detached create container
// ---------------------------------------------------------------------------

/// Whitelisted restart policies.
fn restart_allowed(p: &str) -> bool {
    matches!(p, "no" | "unless-stopped" | "always")
}

/// Trim an optional string and drop it when empty.
fn opt_trim(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whitelisted network drivers offered in the create-network dialog.
fn net_driver_allowed(d: &str) -> bool {
    matches!(
        d,
        "bridge" | "macvlan" | "ipvlan" | "overlay" | "host" | "none"
    )
}

/// Validate an IPv4 dotted-quad address (no port, no CIDR suffix).
fn valid_ipv4(s: &str) -> Result<()> {
    let ok = s.parse::<std::net::Ipv4Addr>().is_ok();
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_ipv4"));
    }
    Ok(())
}

/// Validate an IPv4 CIDR block like `172.20.0.0/16`.
fn valid_cidr(s: &str) -> Result<()> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_cidr"))?;
    if addr.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(anyhow!("ERR_CODE:docker.bad_cidr"));
    }
    match prefix.parse::<u8>() {
        Ok(p) if p <= 32 => Ok(()),
        _ => Err(anyhow!("ERR_CODE:docker.bad_cidr")),
    }
}

/// Validate a MAC address: six colon-separated hex octets, e.g. `02:42:ac:11:00:02`.
fn valid_mac(s: &str) -> Result<()> {
    let parts: Vec<&str> = s.split(':').collect();
    let ok = parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_mac"));
    }
    Ok(())
}

/// Validate a hostname / domainname label set per RFC 1123 (letters, digits,
/// hyphen, dots between labels; max 253 chars).
fn valid_hostname(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 253 {
        return Err(anyhow!("ERR_CODE:docker.bad_hostname"));
    }
    let ok = s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    if !ok {
        return Err(anyhow!("ERR_CODE:docker.bad_hostname"));
    }
    Ok(())
}

/// Validate a container name: docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]+.
fn validate_name(s: &str) -> Result<()> {
    if s.len() > 128 {
        return Err(anyhow!("ERR_CODE:docker.name_too_long"));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !ok || s.starts_with('-') {
        return Err(anyhow!("ERR_CODE:docker.bad_name"));
    }
    Ok(())
}

/// Validate a host filesystem path (no shell metacharacters; must be absolute).
fn validate_path(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 1024 || !s.starts_with('/') {
        return Err(anyhow!("ERR_CODE:docker.path_not_absolute"));
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
        return Err(anyhow!("ERR_CODE:docker.path_bad_chars"));
    }
    Ok(())
}

/// Validate an env var entry "KEY=VALUE". KEY must be a valid identifier; VALUE
/// is taken verbatim (it's a separate argv entry, so no shell interpretation),
/// but we still reject newlines.
fn validate_env(s: &str) -> Result<()> {
    if s.len() > 4096 {
        return Err(anyhow!("ERR_CODE:docker.env_too_long"));
    }
    let (k, _v) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("ERR_CODE:docker.env_format"))?;
    if k.is_empty() {
        return Err(anyhow!("ERR_CODE:docker.env_name_empty"));
    }
    let key_ok = k
        .chars()
        .enumerate()
        .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
    if !key_ok {
        return Err(anyhow!("ERR_CODE:docker.env_name_rules"));
    }
    if s.contains('\n') || s.contains('\r') {
        return Err(anyhow!("ERR_CODE:docker.env_bad_chars"));
    }
    Ok(())
}

/// A validated container creation spec, ready for the bollard create API.
struct CreateSpec {
    image: String,
    name: Option<String>,
    start: bool,
    config: bollard::container::Config<String>,
    /// When set, remove this existing container before creating (edit/upgrade).
    replace: Option<String>,
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
        return Err(anyhow!("ERR_CODE:docker.bad_restart_policy"));
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
            return Err(anyhow!("ERR_CODE:docker.too_many_ports"));
        }
        for p in ports {
            if p.host < 1 || p.host > 65535 || p.container < 1 || p.container > 65535 {
                return Err(anyhow!("ERR_CODE:docker.port_range"));
            }
            let proto = p.proto.as_deref().unwrap_or("tcp");
            if proto != "tcp" && proto != "udp" {
                return Err(anyhow!("ERR_CODE:docker.bad_proto"));
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
            return Err(anyhow!("ERR_CODE:docker.too_many_envs"));
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
            return Err(anyhow!("ERR_CODE:docker.too_many_mounts"));
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
            return Err(anyhow!("ERR_CODE:docker.mem_over_host"));
        }
        memory = Some(bytes as i64);
    }

    let tty = req.tty.unwrap_or(false);

    // CPU weight (cpu-shares). Default 1024 (docker's own default). 0 or unset
    // means "leave at default".
    let cpu_shares: Option<i64> = match req.cpu_shares {
        Some(v) if v > 0 => {
            if !(2..=262144).contains(&v) {
                return Err(anyhow!("ERR_CODE:docker.cpu_shares_range"));
            }
            Some(v)
        }
        _ => None,
    };

    let privileged = req.privileged.unwrap_or(false);

    // DNS servers (validated IPv4 each).
    let mut dns: Vec<String> = Vec::new();
    if let Some(list) = &req.dns {
        if list.len() > 8 {
            return Err(anyhow!("ERR_CODE:docker.too_many_dns"));
        }
        for d in list {
            let d = d.trim();
            if d.is_empty() {
                continue;
            }
            valid_ipv4(d)?;
            dns.push(d.to_string());
        }
    }

    // Hostname / domainname (optional).
    let hostname = match opt_trim(&req.hostname) {
        Some(h) => {
            valid_hostname(&h)?;
            Some(h)
        }
        None => None,
    };
    let domainname = match opt_trim(&req.domainname) {
        Some(d) => {
            valid_hostname(&d)?;
            Some(d)
        }
        None => None,
    };

    // Per-endpoint network options: static IPv4 and/or MAC address. These are
    // only honoured when a (user-defined) network is selected.
    let mac = match opt_trim(&req.mac) {
        Some(m) => {
            valid_mac(&m)?;
            Some(m)
        }
        None => None,
    };
    let ipv4 = match opt_trim(&req.ipv4) {
        Some(ip) => {
            valid_ipv4(&ip)?;
            Some(ip)
        }
        None => None,
    };
    if (mac.is_some() || ipv4.is_some()) && network.is_none() {
        return Err(anyhow!("ERR_CODE:docker.endpoint_needs_network"));
    }

    // Build the per-network endpoint config when MAC/IPv4 are requested.
    let networking_config = match (&network, mac.is_some() || ipv4.is_some()) {
        (Some(net), true) => {
            let mut endpoints = HashMap::new();
            endpoints.insert(
                net.clone(),
                bollard::models::EndpointSettings {
                    ipam_config: ipv4.clone().map(|ip| bollard::models::EndpointIpamConfig {
                        ipv4_address: Some(ip),
                        ..Default::default()
                    }),
                    mac_address: mac.clone(),
                    ..Default::default()
                },
            );
            Some(bollard::container::NetworkingConfig {
                endpoints_config: endpoints,
            })
        }
        _ => None,
    };

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
        cpu_shares,
        privileged: Some(privileged),
        dns: if dns.is_empty() { None } else { Some(dns) },
        network_mode: network.clone(),
        ..Default::default()
    };

    let config = bollard::container::Config {
        image: Some(image.clone()),
        cmd,
        env: if env.is_empty() { None } else { Some(env) },
        tty: Some(tty),
        open_stdin: Some(tty),
        hostname,
        domainname,
        exposed_ports: if exposed.is_empty() {
            None
        } else {
            Some(exposed)
        },
        host_config: Some(host_config),
        networking_config,
        ..Default::default()
    };

    Ok((
        CreateSpec {
            image,
            name,
            start: req.start.unwrap_or(true),
            config,
            replace: opt_trim(&req.replace),
        },
        display_name,
    ))
}

/// Validate a `--cpus` value: a positive decimal like "0.5", "1", "2.5".
fn validate_cpus(s: &str) -> Result<()> {
    let v: f64 = s
        .parse()
        .map_err(|_| anyhow!("ERR_CODE:docker.bad_cpu_format"))?;
    if v <= 0.0 || v > 1024.0 {
        return Err(anyhow!("ERR_CODE:docker.cpu_out_of_range"));
    }
    // Restrict the charset too (parse alone would accept "inf"/"NaN").
    if !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(anyhow!("ERR_CODE:docker.bad_cpu_format"));
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
        return Err(anyhow!("ERR_CODE:docker.bad_mem_format"));
    }
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("ERR_CODE:docker.bad_mem_format"))?;
    if n == 0 {
        return Err(anyhow!("ERR_CODE:docker.mem_too_small"));
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
                '\n' | '\r' => return Err(anyhow!("ERR_CODE:docker.cmd_no_newline")),
                _ => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err(anyhow!("ERR_CODE:docker.cmd_unclosed_quote"));
    }
    if has_token {
        out.push(cur);
    }
    if out.len() > 100 {
        return Err(anyhow!("ERR_CODE:docker.cmd_too_many_args"));
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
        op_push(&op_id_t, &pmsg("dk.creating_container", &[]));
        match create_container(spec).await {
            Ok((id, started)) => {
                let short = id.chars().take(12).collect::<String>();
                op_push(
                    &op_id_t,
                    &pmsg(
                        "dk.container_created",
                        &[
                            if started {
                                "@dklbl.created_started"
                            } else {
                                "@dklbl.created"
                            },
                            short.as_str(),
                        ],
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
    // Edit/upgrade: remove the container being replaced first so the new one can
    // reuse its name. Managed service containers are never replaced this way.
    if let Some(old) = spec.replace.as_deref() {
        if let Some(why) = managed_container_guard(old).await {
            return Err(anyhow!(why));
        }
        let opts = bollard::container::RemoveContainerOptions {
            force: true,
            ..Default::default()
        };
        dkr.remove_container(old, Some(opts))
            .await
            .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    }
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
// Lifecycle extras: rename, commit-to-image, stats, edit/upgrade prefill
// ---------------------------------------------------------------------------

/// Rename a container to `new_name` (validated like a create name).
async fn rename_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let name = req
        .new_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_name"))?;
    validate_name(name)?;
    dkr()?
        .rename_container(
            &r,
            bollard::container::RenameContainerOptions {
                name: name.to_string(),
            },
        )
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "renamed": name }))
}

/// Commit a container's current state to a new image (`repo:tag`).
async fn commit_container_op(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let repo = req
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_image_name"))?;
    validate_token(repo)?;
    let tag = req
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("latest");
    validate_token(tag)?;
    let opts = bollard::image::CommitContainerOptions {
        container: r.clone(),
        repo: repo.to_string(),
        tag: tag.to_string(),
        comment: String::new(),
        author: "DN7 Panel".to_string(),
        pause: true,
        changes: None,
    };
    dkr()?
        .commit_container(opts, bollard::container::Config::<String>::default())
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "image": format!("{repo}:{tag}") }))
}

/// One-shot resource stats for a container (CPU %, memory, network, block IO).
async fn container_stats(req: &Req) -> Result<Value> {
    use bollard::container::StatsOptions;
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let mut stream = dkr.stats(
        &r,
        Some(StatsOptions {
            stream: false,
            one_shot: false,
        }),
    );
    let s = match stream.next().await {
        Some(Ok(s)) => s,
        Some(Err(e)) => return Err(anyhow!(friendly_docker_err(&e))),
        None => return Err(anyhow!("ERR_CODE:docker.no_stats")),
    };

    // CPU %: delta(container) / delta(system) * online_cpus * 100 (docker formula).
    let cpu_delta =
        s.cpu_stats.cpu_usage.total_usage as f64 - s.precpu_stats.cpu_usage.total_usage as f64;
    let sys_delta = s.cpu_stats.system_cpu_usage.unwrap_or(0) as f64
        - s.precpu_stats.system_cpu_usage.unwrap_or(0) as f64;
    let online = s.cpu_stats.online_cpus.unwrap_or_else(|| {
        s.cpu_stats
            .cpu_usage
            .percpu_usage
            .as_ref()
            .map(|v| v.len() as u64)
            .unwrap_or(1)
    });
    let cpu_pct = if sys_delta > 0.0 && cpu_delta > 0.0 {
        (cpu_delta / sys_delta) * online as f64 * 100.0
    } else {
        0.0
    };

    // Memory: usage minus page cache (matches `docker stats`), against the limit.
    let mem_usage = s.memory_stats.usage.unwrap_or(0);
    let cache = match &s.memory_stats.stats {
        Some(bollard::container::MemoryStatsStats::V1(v1)) => v1.cache,
        Some(bollard::container::MemoryStatsStats::V2(v2)) => v2.inactive_file,
        None => 0,
    };
    let mem_used = mem_usage.saturating_sub(cache);
    let mem_limit = s.memory_stats.limit.unwrap_or(0);

    // Network: sum across interfaces.
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Some(nets) = &s.networks {
        for n in nets.values() {
            rx += n.rx_bytes;
            tx += n.tx_bytes;
        }
    }

    // Block IO: sum read/write byte counters.
    let (mut blk_r, mut blk_w) = (0u64, 0u64);
    if let Some(entries) = &s.blkio_stats.io_service_bytes_recursive {
        for e in entries {
            match e.op.to_ascii_lowercase().as_str() {
                "read" => blk_r += e.value,
                "write" => blk_w += e.value,
                _ => {}
            }
        }
    }

    Ok(json!({
        "cpu_pct": (cpu_pct * 100.0).round() / 100.0,
        "cpu_online": online,
        "mem_used": mem_used,
        "mem_limit": mem_limit,
        "net_rx": rx,
        "net_tx": tx,
        "blk_read": blk_r,
        "blk_write": blk_w,
    }))
}

/// Return a create-request-shaped JSON body describing an existing container,
/// used to pre-fill the edit/upgrade form and to snapshot config for backups.
async fn container_create_body(dkr: &Docker, reference: &str) -> Result<Value> {
    let c = dkr
        .inspect_container(reference, None)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let cfg = c.config.clone().unwrap_or_default();
    let hc = c.host_config.clone().unwrap_or_default();
    let name = c
        .name
        .clone()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();

    // Ports from host_config.port_bindings ("port/proto" -> [{host_port}]).
    let mut ports = Vec::new();
    if let Some(pb) = &hc.port_bindings {
        for (key, binds) in pb {
            let (cport, proto) = match key.split_once('/') {
                Some((p, pr)) => (p.parse::<i64>().unwrap_or(0), pr.to_string()),
                None => (key.parse::<i64>().unwrap_or(0), "tcp".to_string()),
            };
            if let Some(list) = binds {
                for b in list {
                    if let Some(hp) = b.host_port.as_deref().and_then(|s| s.parse::<i64>().ok()) {
                        ports.push(json!({ "host": hp, "container": cport, "proto": proto }));
                    }
                }
            }
        }
    }

    // Volume binds "host:container[:ro]".
    let mut volumes = Vec::new();
    if let Some(binds) = &hc.binds {
        for b in binds {
            let parts: Vec<&str> = b.split(':').collect();
            if parts.len() >= 2 && parts[0].starts_with('/') {
                volumes.push(json!({
                    "host": parts[0],
                    "container": parts[1],
                    "readonly": parts.get(2).map(|m| *m == "ro").unwrap_or(false),
                }));
            }
        }
    }

    let restart = hc
        .restart_policy
        .and_then(|p| p.name)
        .map(|n| match n {
            bollard::models::RestartPolicyNameEnum::ALWAYS => "always",
            bollard::models::RestartPolicyNameEnum::NO => "no",
            _ => "unless-stopped",
        })
        .unwrap_or("unless-stopped")
        .to_string();

    // Network + per-endpoint MAC / IPv4 (first user-defined network).
    let network_mode = hc.network_mode.clone().unwrap_or_default();
    let network = if network_mode.is_empty()
        || matches!(
            network_mode.as_str(),
            "default" | "bridge" | "host" | "none"
        ) {
        String::new()
    } else {
        network_mode.clone()
    };
    let (mut mac, mut ipv4) = (String::new(), String::new());
    if !network.is_empty() {
        if let Some(ns) = &c.network_settings {
            if let Some(nets) = &ns.networks {
                if let Some(ep) = nets.get(&network_mode).or_else(|| nets.values().next()) {
                    mac = ep.mac_address.clone().unwrap_or_default();
                    ipv4 = ep
                        .ipam_config
                        .as_ref()
                        .and_then(|i| i.ipv4_address.clone())
                        .unwrap_or_default();
                }
            }
        }
    }

    let cmd = cfg.cmd.as_ref().map(|v| v.join(" ")).unwrap_or_default();
    let cpus = hc
        .nano_cpus
        .filter(|n| *n > 0)
        .map(|n| format!("{:.2}", n as f64 / 1_000_000_000.0))
        .unwrap_or_default();
    let memory = hc.memory.filter(|m| *m > 0).map(|m| m.to_string());

    Ok(json!({
        "op": "create_container",
        "image": cfg.image.clone().unwrap_or_default(),
        "name": name,
        "restart": restart,
        "ports": ports,
        "env": cfg.env.clone().unwrap_or_default(),
        "volumes": volumes,
        "command": cmd,
        "tty": cfg.tty.unwrap_or(false),
        "network": network,
        "mac": mac,
        "ipv4": ipv4,
        "hostname": cfg.hostname.clone().unwrap_or_default(),
        "domainname": cfg.domainname.clone().unwrap_or_default(),
        "dns": hc.dns.clone().unwrap_or_default(),
        "cpu_shares": hc.cpu_shares.unwrap_or(0),
        "cpus": cpus,
        "memory": memory,
        "privileged": hc.privileged.unwrap_or(false),
    }))
}

/// get_container_config op: pre-fill the edit/upgrade form.
async fn get_container_config(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let dkr = dkr()?;
    let body = container_create_body(&dkr, &r).await?;
    Ok(json!({ "config": body }))
}

// ---------------------------------------------------------------------------
// Container backups (commit -> docker save -> gzip; restore = load + recreate)
// ---------------------------------------------------------------------------

/// Root directory holding all container backups (`<data>/docker-backups`).
fn backups_root() -> std::path::PathBuf {
    crate::paths::data_dir().join("docker-backups")
}

/// Validate a container name used as a backups subdirectory (defensive — the
/// name comes from the daemon, but we still keep it to a safe charset).
fn safe_dir_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Validate a backup file name (timestamp.tar.gz). No path separators.
fn valid_backup_name(s: &str) -> bool {
    s.len() <= 64
        && s.ends_with(".tar.gz")
        && !s.contains('/')
        && !s.contains("..")
        && s.trim_end_matches(".tar.gz")
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

/// Start a detached backup: commit the container to a temp image, `docker save`
/// it, gzip the stream to disk, and write a sidecar config snapshot.
fn start_backup_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .map(str::to_string)
        .unwrap_or_else(|| r.chars().take(12).collect());
    if !safe_dir_component(&name) {
        return Err(anyhow!("ERR_CODE:docker.bad_name"));
    }
    let op_id = new_op_id();
    op_create(&op_id, "backup", &name);
    let op_id_t = op_id.clone();
    let target = name.clone();
    tokio::spawn(async move {
        match backup_container(&op_id_t, &r, &name).await {
            Ok(file) => op_finish(&op_id_t, "done", "", &file),
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

async fn backup_container(op_id: &str, reference: &str, name: &str) -> Result<String> {
    use std::io::Write;
    let dkr = dkr()?;
    let ts = now_stamp();
    let dir = backups_root().join(name);
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("无法创建备份目录：{e}"))?;

    // Snapshot the create config (for recreate on restore).
    op_push(op_id, &pmsg("dk.bk_snapshot", &[]));
    let body = container_create_body(&dkr, reference).await?;
    let json_path = dir.join(format!("{ts}.json"));
    std::fs::write(
        &json_path,
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
    .map_err(|e| anyhow!("无法写入配置快照：{e}"))?;

    // Commit to a temporary image so the saved tar carries full config + layers.
    op_push(op_id, &pmsg("dk.bk_committing", &[]));
    let tmp_repo = "dn7-backup";
    let tmp_tag = format!("{name}-{ts}");
    let commit = bollard::image::CommitContainerOptions {
        container: reference.to_string(),
        repo: tmp_repo.to_string(),
        tag: tmp_tag.clone(),
        comment: "DN7 Panel backup".to_string(),
        author: "DN7 Panel".to_string(),
        pause: true,
        changes: None,
    };
    dkr.commit_container(commit, bollard::container::Config::<String>::default())
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let tmp_image = format!("{tmp_repo}:{tmp_tag}");

    // Stream `docker save` -> gzip -> file.
    op_push(op_id, &pmsg("dk.bk_saving", &[]));
    let tar_gz = dir.join(format!("{ts}.tar.gz"));
    let result = async {
        let file = std::fs::File::create(&tar_gz).map_err(|e| anyhow!("无法创建备份文件：{e}"))?;
        let mut enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut stream = dkr.export_image(&tmp_image);
        while let Some(item) = stream.next().await {
            let chunk = item.map_err(|e| anyhow!(friendly_docker_err(&e)))?;
            enc.write_all(&chunk)
                .map_err(|e| anyhow!("写入备份失败：{e}"))?;
        }
        enc.finish().map_err(|e| anyhow!("写入备份失败：{e}"))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Always remove the temp image tag; the tar is self-contained.
    let _ = dkr
        .remove_image(
            &tmp_image,
            Some(bollard::image::RemoveImageOptions {
                force: true,
                ..Default::default()
            }),
            None,
        )
        .await;

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tar_gz);
        let _ = std::fs::remove_file(&json_path);
        return Err(e);
    }
    Ok(format!("{ts}.tar.gz"))
}

/// List backups for a container name: file, size, created (mtime, secs).
async fn list_backups(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_name"))?;
    let dir = backups_root().join(name);
    let mut items = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if !fname.ends_with(".tar.gz") {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            items.push(json!({
                "file": fname,
                "size": meta.len(),
                "created": mtime,
            }));
        }
    }
    // Newest first.
    items.sort_by(|a, b| {
        b.get("created")
            .and_then(Value::as_u64)
            .cmp(&a.get("created").and_then(Value::as_u64))
    });
    Ok(json!({ "backups": items }))
}

/// Delete one backup file (and its sidecar config snapshot).
fn delete_backup(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_name"))?;
    let file = req
        .backup
        .as_deref()
        .map(str::trim)
        .filter(|s| valid_backup_name(s))
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_backup"))?;
    let dir = backups_root().join(name);
    let tar_gz = dir.join(file);
    if tar_gz.exists() {
        std::fs::remove_file(&tar_gz).map_err(|e| anyhow!("无法删除备份：{e}"))?;
    }
    let json_path = dir.join(file.replace(".tar.gz", ".json"));
    let _ = std::fs::remove_file(&json_path);
    Ok(json!({ "deleted": file }))
}

/// Start a detached restore: load the saved image then recreate the container
/// from the snapshot config (replacing any current container with the name).
fn start_restore_backup(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_name"))?
        .to_string();
    let file = req
        .backup
        .as_deref()
        .map(str::trim)
        .filter(|s| valid_backup_name(s))
        .ok_or_else(|| anyhow!("ERR_CODE:docker.bad_backup"))?
        .to_string();
    let op_id = new_op_id();
    op_create(&op_id, "restore", &name);
    let op_id_t = op_id.clone();
    let target = name.clone();
    tokio::spawn(async move {
        match restore_backup(&op_id_t, &name, &file).await {
            Ok(()) => op_finish(&op_id_t, "done", "", &name),
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

async fn restore_backup(op_id: &str, name: &str, file: &str) -> Result<()> {
    use tokio_util::codec::{BytesCodec, FramedRead};
    let dkr = dkr()?;
    let dir = backups_root().join(name);
    let tar_gz = dir.join(file);
    if !tar_gz.exists() {
        return Err(anyhow!("ERR_CODE:docker.backup_missing"));
    }

    // Load the saved image (`docker load`). The tarball records its own
    // repo:tag (dn7-backup:<name>-<ts>); capture it from the load output.
    op_push(op_id, &pmsg("dk.bk_loading", &[]));
    let f = tokio::fs::File::open(&tar_gz)
        .await
        .map_err(|e| anyhow!("无法打开备份：{e}"))?;
    let byte_stream = FramedRead::new(f, BytesCodec::new()).map(|r| r.unwrap_or_default().freeze());
    let mut loaded_image = String::new();
    let mut stream = dkr.import_image_stream(
        bollard::image::ImportImageOptions::default(),
        byte_stream,
        None,
    );
    while let Some(item) = stream.next().await {
        let info = item.map_err(|e| anyhow!(friendly_docker_err(&e)))?;
        if let Some(s) = info.stream {
            // "Loaded image: dn7-backup:foo-20260101-000000\n"
            if let Some(idx) = s.find("Loaded image:") {
                loaded_image = s[idx + "Loaded image:".len()..].trim().to_string();
            }
        }
    }

    // Read the config snapshot and recreate from the loaded image.
    op_push(op_id, &pmsg("dk.bk_recreating", &[]));
    let json_path = dir.join(file.replace(".tar.gz", ".json"));
    let mut body: Value = match std::fs::read(&json_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    };
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow!("ERR_CODE:docker.backup_bad_config"))?;
    if !loaded_image.is_empty() {
        obj.insert("image".to_string(), json!(loaded_image));
    }
    obj.insert("name".to_string(), json!(name));
    obj.insert("replace".to_string(), json!(name));
    obj.insert("start".to_string(), json!(true));
    let restore_req: Req =
        serde_json::from_value(body).map_err(|_| anyhow!("ERR_CODE:docker.backup_bad_config"))?;
    let (spec, _) = build_create_spec(&restore_req)?;
    create_container(spec).await?;
    Ok(())
}

/// A compact UTC-ish timestamp for backup file names (YYYYMMDD-HHMMSS-derived).
/// Uses seconds-since-epoch to avoid a chrono/time dependency; monotonic and
/// unique enough for backup ordering.
fn now_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

/// Open a container backup file for streaming download. Validates the
/// name/file to keep the read inside the backups directory.
pub async fn backup_read_stream(
    name: &str,
    file: &str,
) -> Result<(String, crate::file::ByteStream)> {
    use futures::StreamExt;
    if !safe_dir_component(name) || !valid_backup_name(file) {
        return Err(anyhow!("invalid backup reference"));
    }
    let path = backups_root().join(name).join(file);
    let f = tokio::fs::File::open(&path)
        .await
        .map_err(|e| anyhow!("无法打开备份：{e}"))?;
    let stream = tokio_util::codec::FramedRead::new(f, tokio_util::codec::BytesCodec::new())
        .map(|r| r.map(|b| b.freeze()));
    Ok((format!("{name}-{file}"), Box::pin(stream)))
}

/// Load a local image archive (`docker load`) from an uploaded byte stream. The
/// archive is the output of `docker save` (a tar, optionally gzipped). Returns
/// the loaded image ref(s).
pub async fn import_image_upload<S>(body: S) -> Result<Value>
where
    S: futures_util::Stream<Item = bytes::Bytes> + Send + 'static,
{
    let dkr = dkr()?;
    let mut loaded: Vec<String> = Vec::new();
    let mut stream =
        dkr.import_image_stream(bollard::image::ImportImageOptions::default(), body, None);
    while let Some(item) = stream.next().await {
        let info = item.map_err(|e| anyhow!(friendly_docker_err(&e)))?;
        if let Some(s) = info.stream {
            // "Loaded image: repo:tag\n" / "Loaded image ID: sha256:...\n"
            for marker in ["Loaded image: ", "Loaded image ID: "] {
                if let Some(idx) = s.find(marker) {
                    loaded.push(s[idx + marker.len()..].trim().to_string());
                }
            }
        }
    }
    if loaded.is_empty() {
        return Err(anyhow!("ERR_CODE:docker.import_no_image"));
    }
    Ok(json!({ "loaded": loaded }))
}

/// Open a docker image export (`docker save`) for streaming download as a tar.
pub async fn image_export_stream(image: &str) -> Result<(String, crate::file::ByteStream)> {
    use futures::StreamExt;
    validate_token(image)?;
    let dkr = dkr()?;
    // Confirm the image exists (gives a clean error instead of an empty stream).
    dkr.inspect_image(image)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let safe = image.replace([':', '/'], "_");
    let stream = dkr
        .export_image(image)
        .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())));
    Ok((format!("{safe}.tar"), Box::pin(stream)))
}

/// Start (or resume watching) a detached Docker install. Uses a fixed op id so
/// re-entering the page finds the in-progress install and its full log.
fn start_install(req: &Req) -> Result<Value> {
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
        return Err(anyhow!("ERR_CODE:docker.need_root"));
    }

    // "distro" (docker.io, default) | "ce"; "auto" (default) | "cn" | "global".
    let channel = match req.channel.as_deref() {
        Some("ce") => "ce",
        _ => "distro",
    }
    .to_string();
    let region = match req.region.as_deref() {
        Some("cn") => "cn",
        Some("global") => "global",
        _ => "auto",
    }
    .to_string();

    op_create(INSTALL_OP, "install", "docker");
    tokio::spawn(async move {
        match run_install_detached(INSTALL_OP, &channel, &region).await {
            Ok(()) => op_finish(INSTALL_OP, "done", "", ""),
            Err(e) => op_finish(INSTALL_OP, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": INSTALL_OP, "target": "docker" }))
}

async fn run_install_detached(op_id: &str, channel: &str, region_pref: &str) -> Result<()> {
    if docker_is_installed().await {
        op_push(op_id, &pmsg("dk.already_installed", &[]));
        return Ok(());
    }

    let os = detect_os();
    op_push(
        op_id,
        &pmsg("dk.detected_os", &[os.pretty.as_str(), os.family.as_str()]),
    );

    let region = resolve_region(region_pref).await;
    op_push(
        op_id,
        &pmsg(
            "dk.install_method",
            &[
                if channel == "ce" {
                    "@dklbl.ce"
                } else {
                    "@dklbl.distro"
                },
                if region == "cn" {
                    "@dklbl.cn"
                } else {
                    "@dklbl.global"
                },
            ],
        ),
    );

    // Primary attempt: native distro package (friendliest, uses the system's
    // existing mirrors — no external Docker repo), or the official convenience
    // script for the `ce` channel / unknown distros.
    let primary = build_install_script(&os.family, channel, region);
    op_push(op_id, &pmsg("dk.start_install", &[]));
    let _ = stream_shell_to_op(op_id, &primary).await;

    // Universal fallback: if the daemon still isn't present, run get.docker.com
    // (it handles the repo setup for every supported distro). Covers e.g. RHEL/
    // Rocky/Alma where the distro repos ship podman, not a `docker` package.
    if !docker_is_installed().await {
        op_push(op_id, &pmsg("dk.fallback_script", &[]));
        let _ = stream_shell_to_op(op_id, &get_docker_script(region)).await;
    }

    // Region tuning + enable/start. For CN, write registry-mirror accelerators
    // (faster image pulls) before restarting; otherwise just ensure it's up.
    if region == "cn" {
        op_push(op_id, &pmsg("dk.config_mirror", &[]));
        let _ = stream_shell_to_op(op_id, REGISTRY_MIRROR_SCRIPT).await;
    } else {
        op_push(op_id, &pmsg("dk.starting", &[]));
        let _ = stream_shell_to_op(op_id, ENABLE_START_SCRIPT).await;
    }

    op_push(op_id, &pmsg("dk.verify_install", &[]));
    if docker_is_installed().await {
        op_push(op_id, &pmsg("dk.install_done", &[]));
        Ok(())
    } else {
        Err(anyhow!("ERR_CODE:docker.install_failed"))
    }
}

/// True when the Docker daemon is reachable (installed + running).
async fn docker_is_installed() -> bool {
    docker_info()
        .await
        .ok()
        .and_then(|i| i.get("installed").and_then(Value::as_bool))
        == Some(true)
}

/// Detected host OS family + a human label.
struct OsInfo {
    family: String,
    pretty: String,
}

/// Classify the host distro from `/etc/os-release` into an install family.
fn detect_os() -> OsInfo {
    fn unquote(s: &str) -> String {
        s.trim().trim_matches('"').to_string()
    }
    let txt = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let (mut id, mut like, mut name, mut ver) =
        (String::new(), String::new(), String::new(), String::new());
    for line in txt.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = unquote(v);
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            like = unquote(v);
        } else if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            name = unquote(v);
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            ver = unquote(v);
        }
    }
    let hay = format!(" {} {} ", id.to_lowercase(), like.to_lowercase());
    let has = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));
    let family = if has(&["debian", "ubuntu", "linuxmint", "raspbian", "devuan", "pop"]) {
        "debian"
    } else if has(&[
        "rhel",
        "centos",
        "fedora",
        "rocky",
        "almalinux",
        "amzn",
        "ol",
        "oracle",
    ]) {
        "rhel"
    } else if has(&["suse", "sles", "opensuse"]) {
        "suse"
    } else if has(&["arch", "manjaro", "endeavouros"]) {
        "arch"
    } else if has(&["alpine"]) {
        "alpine"
    } else {
        "unknown"
    };
    let pretty = if !name.is_empty() {
        name
    } else if !id.is_empty() {
        format!("{id} {ver}").trim().to_string()
    } else {
        "Linux".to_string()
    };
    OsInfo {
        family: family.to_string(),
        pretty,
    }
}

/// Resolve the region preference to "cn" | "global". For "auto", probe whether
/// Docker's global infra is quickly reachable; if not, assume a CN network.
async fn resolve_region(pref: &str) -> &'static str {
    match pref {
        "cn" => "cn",
        "global" => "global",
        _ => {
            if tcp_reachable("download.docker.com:443", 2500).await {
                "global"
            } else {
                "cn"
            }
        }
    }
}

/// Best-effort: can we open a TCP connection to `addr` within `ms` ms?
async fn tcp_reachable(addr: &str, ms: u64) -> bool {
    let addrs = match tokio::net::lookup_host(addr).await {
        Ok(a) => a,
        Err(_) => return false,
    };
    for a in addrs {
        let ok = tokio::time::timeout(
            std::time::Duration::from_millis(ms),
            tokio::net::TcpStream::connect(a),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        if ok {
            return true;
        }
    }
    false
}

/// Build the primary install script for a distro family + channel + region.
fn build_install_script(family: &str, channel: &str, region: &str) -> String {
    // The `ce` channel and unknown distros use Docker's convenience script,
    // which sets up the official repo for every supported distro.
    if channel == "ce" || family == "unknown" {
        return get_docker_script(region);
    }
    match family {
        "debian" => "set -e\n\
             export DEBIAN_FRONTEND=noninteractive\n\
             apt-get update\n\
             apt-get install -y docker.io\n\
             apt-get install -y docker-compose-v2 >/dev/null 2>&1 || true"
            .to_string(),
        // Fedora / Amazon Linux ship a `docker`/`moby-engine` package; RHEL/
        // Rocky/Alma don't (they get caught by the get.docker.com fallback).
        "rhel" => "set -e\n\
             (dnf -y install docker || dnf -y install moby-engine || yum -y install docker)"
            .to_string(),
        "suse" => "set -e\nzypper --non-interactive install docker".to_string(),
        "arch" => "set -e\npacman -Sy --noconfirm docker".to_string(),
        "alpine" => "set -e\n\
             apk add --no-cache docker docker-cli-compose\n\
             rc-update add docker boot || true"
            .to_string(),
        _ => get_docker_script(region),
    }
}

/// Docker's official convenience script, mirrored to Aliyun for CN networks.
fn get_docker_script(region: &str) -> String {
    let mirror = if region == "cn" {
        " --mirror Aliyun"
    } else {
        ""
    };
    format!(
        "set -e\n\
         if command -v curl >/dev/null 2>&1; then curl -fsSL https://get.docker.com -o /tmp/dn7-get-docker.sh;\n\
         elif command -v wget >/dev/null 2>&1; then wget -qO /tmp/dn7-get-docker.sh https://get.docker.com;\n\
         else echo 'no curl/wget' >&2; exit 1; fi\n\
         sh /tmp/dn7-get-docker.sh{mirror}\n\
         rm -f /tmp/dn7-get-docker.sh"
    )
}

/// Ensure the docker service is enabled + started across init systems.
const ENABLE_START_SCRIPT: &str = "systemctl enable --now docker 2>/dev/null \
     || service docker start 2>/dev/null \
     || rc-service docker start 2>/dev/null || true";

/// Write CN registry-mirror accelerators into daemon.json and (re)start Docker.
/// NOTE: public CN accelerators change/shut down periodically — review these.
const REGISTRY_MIRROR_SCRIPT: &str = r#"set -e
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'JSON'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://docker.1ms.run",
    "https://dockerproxy.net"
  ]
}
JSON
systemctl daemon-reload 2>/dev/null || true
systemctl enable docker 2>/dev/null || true
systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || rc-service docker restart 2>/dev/null || true"#;

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

    // Drain stderr concurrently to avoid a stdout/stderr pipe deadlock.
    let stderr = child.stderr.take();
    let err_task = tokio::spawn(async move {
        let mut buf = String::new();
        if let Some(mut e) = stderr {
            let _ = e.read_to_string(&mut buf).await;
        }
        buf
    });
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
    let err = err_task.await.unwrap_or_default();
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
    if !status.success() {
        return Err(anyhow!("ERR_CODE:docker.install_script_nonzero"));
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

// ===========================================================================
// Volumes + Docker settings (panel mirror/registry lists + daemon.json knobs)
// ===========================================================================

/// List docker volumes with size/usage. DN7-managed volumes (e.g. the mysql
/// data volume) are flagged so the UI can protect them from removal.
async fn list_volumes() -> Result<Value> {
    let dkr = dkr()?;
    let resp = dkr
        .list_volumes(None::<bollard::volume::ListVolumesOptions<String>>)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut out = Vec::new();
    for v in resp.volumes.unwrap_or_default() {
        let managed = v.name.starts_with("dn7-")
            || v.labels.contains_key("dn7.mysql")
            || v.labels.contains_key("dn7.managed");
        let (size, refs) = match &v.usage_data {
            Some(u) => (
                if u.size >= 0 {
                    human_size(u.size as u64)
                } else {
                    "-".to_string()
                },
                u.ref_count,
            ),
            None => ("-".to_string(), -1),
        };
        out.push(json!({
            "name": v.name,
            "driver": v.driver,
            "mountpoint": v.mountpoint,
            "created": v.created_at.unwrap_or_default(),
            "size": size,
            "refs": refs,
            "managed": managed,
        }));
    }
    out.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or("")
            .cmp(b["name"].as_str().unwrap_or(""))
    });
    Ok(json!({ "volumes": out }))
}

async fn create_volume_op(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_volume_name"))?;
    validate_name(name)?;
    let opts = bollard::volume::CreateVolumeOptions {
        name: name.to_string(),
        driver: "local".to_string(),
        ..Default::default()
    };
    dkr()?
        .create_volume(opts)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "created": name }))
}

async fn remove_volume_op(req: &Req) -> Result<Value> {
    let name = need_ref(req)?;
    if name.starts_with("dn7-") {
        return Err(anyhow!("ERR_CODE:docker.volume_managed"));
    }
    let opts = bollard::volume::RemoveVolumeOptions { force: false };
    dkr()?.remove_volume(&name, Some(opts)).await.map_err(|e| {
        let raw = e.to_string().to_lowercase();
        if raw.contains("in use") {
            anyhow!("ERR_CODE:docker.volume_in_use")
        } else {
            anyhow!(friendly_docker_err(&e))
        }
    })?;
    Ok(json!({ "removed": name }))
}

// ---- Panel-side docker settings store (mirrors/registries + daemon knobs) ----

const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

fn default_mirrors() -> Vec<String> {
    [
        "docker.m.daocloud.io",
        "docker.1panel.live",
        "hub.rat.dev",
        "mirror.ccs.tencentyun.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn d_true() -> bool {
    true
}
fn d_cgroup() -> String {
    "systemd".to_string()
}
fn d_logsize() -> String {
    "10m".to_string()
}
fn d_logfile() -> u32 {
    3
}
fn d_socket() -> String {
    DEFAULT_SOCKET.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DockerSettings {
    #[serde(default = "default_mirrors")]
    mirrors: Vec<String>,
    #[serde(default)]
    registries: Vec<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default = "d_true")]
    iptables: bool,
    #[serde(default = "d_true")]
    live_restore: bool,
    #[serde(default = "d_cgroup")]
    cgroup_driver: String,
    #[serde(default = "d_true")]
    log_rotate: bool,
    #[serde(default = "d_logsize")]
    log_max_size: String,
    #[serde(default = "d_logfile")]
    log_max_file: u32,
    #[serde(default = "d_socket")]
    socket_path: String,
}
impl Default for DockerSettings {
    fn default() -> Self {
        DockerSettings {
            mirrors: default_mirrors(),
            registries: Vec::new(),
            ipv6: false,
            iptables: true,
            live_restore: true,
            cgroup_driver: d_cgroup(),
            log_rotate: true,
            log_max_size: d_logsize(),
            log_max_file: d_logfile(),
            socket_path: d_socket(),
        }
    }
}

fn dk_settings_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("docker-settings.json")
}
fn load_dk_settings() -> DockerSettings {
    std::fs::read_to_string(dk_settings_path())
        .ok()
        .and_then(|s| serde_json::from_str::<DockerSettings>(&s).ok())
        .unwrap_or_default()
}
fn save_dk_settings(s: &DockerSettings) -> Result<()> {
    let p = dk_settings_path();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&p, serde_json::to_string_pretty(s)?)?;
    Ok(())
}

fn dk_settings_json() -> Value {
    let s = load_dk_settings();
    json!({
        "mirrors": s.mirrors,
        "registries": s.registries,
        "ipv6": s.ipv6,
        "iptables": s.iptables,
        "live_restore": s.live_restore,
        "cgroup_driver": s.cgroup_driver,
        "log_rotate": s.log_rotate,
        "log_max_size": s.log_max_size,
        "log_max_file": s.log_max_file,
        "socket_path": s.socket_path,
        "configured": dk_settings_path().exists(),
    })
}

/// A host token (mirror/registry): letters/digits/.-: and an optional /path,
/// no scheme or shell metacharacters.
fn valid_host_line(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 200
        && !s.contains("//")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '/' | '_'))
}

/// Validate a docker size like "10m" / "512k" (used for log max-size).
fn valid_log_size(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 10
        && s.chars().take(s.len() - 1).all(|c| c.is_ascii_digit())
        && matches!(s.chars().last(), Some('k' | 'K' | 'm' | 'M' | 'g' | 'G'))
}

async fn set_dk_settings(req: &Req) -> Result<Value> {
    let v = req
        .settings
        .clone()
        .ok_or_else(|| anyhow!("ERR_CODE:docker.missing_settings"))?;
    let incoming: DockerSettings =
        serde_json::from_value(v).map_err(|_| anyhow!("ERR_CODE:docker.bad_settings"))?;

    // Validate.
    for m in incoming.mirrors.iter().chain(incoming.registries.iter()) {
        if !valid_host_line(m) {
            return Err(anyhow!("ERR_CODE:docker.bad_host_line"));
        }
    }
    if !matches!(incoming.cgroup_driver.as_str(), "systemd" | "cgroupfs") {
        return Err(anyhow!("ERR_CODE:docker.bad_cgroup"));
    }
    if !valid_log_size(&incoming.log_max_size) {
        return Err(anyhow!("ERR_CODE:docker.bad_log_size"));
    }
    if incoming.log_max_file == 0 || incoming.log_max_file > 100 {
        return Err(anyhow!("ERR_CODE:docker.bad_log_file"));
    }
    let sock = incoming.socket_path.trim();
    if !sock.starts_with('/') || !sock.ends_with(".sock") || sock.len() > 200 {
        return Err(anyhow!("ERR_CODE:docker.bad_socket"));
    }

    // Persist the panel-side store first (mirrors/registries take effect for
    // the pull dialog immediately, independent of the daemon restart).
    save_dk_settings(&incoming)?;

    // Apply the daemon.json-backed knobs (may restart dockerd). Best-effort with
    // backup + rollback; surfaces a clear error if the daemon won't come back.
    apply_daemon_settings(&incoming).await?;
    Ok(json!({ "ok": true }))
}

const DAEMON_JSON: &str = "/etc/docker/daemon.json";
const DROPIN_DIR: &str = "/etc/systemd/system/docker.service.d";
const DROPIN: &str = "/etc/systemd/system/docker.service.d/dn7-docker.conf";

/// Merge our knobs into daemon.json (preserving unrelated keys), back it up,
/// write, (re)configure the systemd socket override when needed, restart docker
/// and verify it comes back — rolling everything back on failure.
async fn apply_daemon_settings(s: &DockerSettings) -> Result<()> {
    // Read + parse existing daemon.json (preserve unknown keys).
    let prev = std::fs::read_to_string(DAEMON_JSON).unwrap_or_default();
    let mut obj: serde_json::Map<String, Value> = serde_json::from_str(&prev)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .unwrap_or_default();

    obj.insert("ipv6".into(), json!(s.ipv6));
    if s.ipv6 {
        obj.entry("fixed-cidr-v6")
            .or_insert_with(|| json!("fd00:dn7::/48"));
    } else {
        obj.remove("fixed-cidr-v6");
    }
    obj.insert("iptables".into(), json!(s.iptables));
    obj.insert("live-restore".into(), json!(s.live_restore));
    obj.insert(
        "exec-opts".into(),
        json!([format!("native.cgroupdriver={}", s.cgroup_driver)]),
    );
    if s.log_rotate {
        obj.insert("log-driver".into(), json!("json-file"));
        obj.insert(
            "log-opts".into(),
            json!({ "max-size": s.log_max_size, "max-file": s.log_max_file.to_string() }),
        );
    } else {
        obj.remove("log-opts");
    }
    // Custom socket: daemon.json `hosts` + a systemd drop-in that drops the
    // unit's `-H fd://` (otherwise dockerd refuses: "hosts conflict").
    let custom_sock = s.socket_path != DEFAULT_SOCKET && s.socket_path != "/run/docker.sock";
    let prev_dropin = std::fs::read_to_string(DROPIN).ok();
    if custom_sock {
        obj.insert(
            "hosts".into(),
            json!([format!("unix://{}", s.socket_path), "fd://"]),
        );
    } else {
        obj.remove("hosts");
    }

    let body = serde_json::to_string_pretty(&Value::Object(obj))?;

    // Backup + write daemon.json.
    let backup = format!("{DAEMON_JSON}.dn7-bak");
    if !prev.is_empty() {
        let _ = std::fs::write(&backup, &prev);
    }
    if let Some(dir) = std::path::Path::new(DAEMON_JSON).parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(DAEMON_JSON, &body)?;

    // systemd drop-in for the socket override.
    let mut reloaded = false;
    if custom_sock {
        std::fs::create_dir_all(DROPIN_DIR)?;
        let dockerd = which_dockerd();
        let dropin = format!("[Service]\nExecStart=\nExecStart={dockerd}\n");
        std::fs::write(DROPIN, dropin)?;
        let _ = sh("systemctl daemon-reload").await;
        reloaded = true;
    } else if prev_dropin.is_some() {
        let _ = std::fs::remove_file(DROPIN);
        let _ = sh("systemctl daemon-reload").await;
        reloaded = true;
    }

    // Restart docker and verify it comes back.
    let _ = sh("systemctl restart docker").await;
    if daemon_back().await {
        return Ok(());
    }

    // Rollback: restore daemon.json + drop-in, reload, restart.
    if prev.is_empty() {
        let _ = std::fs::remove_file(DAEMON_JSON);
    } else {
        let _ = std::fs::write(DAEMON_JSON, &prev);
    }
    match prev_dropin {
        Some(d) => {
            let _ = std::fs::write(DROPIN, d);
        }
        None => {
            let _ = std::fs::remove_file(DROPIN);
        }
    }
    if reloaded {
        let _ = sh("systemctl daemon-reload").await;
    }
    let _ = sh("systemctl restart docker").await;
    Err(anyhow!("ERR_CODE:docker.daemon_restart_failed"))
}

/// Locate the dockerd binary for the systemd ExecStart override.
fn which_dockerd() -> String {
    for p in [
        "/usr/bin/dockerd",
        "/usr/local/bin/dockerd",
        "/usr/sbin/dockerd",
    ] {
        if std::path::Path::new(p).exists() {
            return p.to_string();
        }
    }
    "/usr/bin/dockerd".to_string()
}

/// Poll the daemon for readiness after a restart (up to ~20s).
async fn daemon_back() -> bool {
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        if let Ok(d) = dkr() {
            if d.ping().await.is_ok() {
                return true;
            }
        }
    }
    false
}

/// Run a shell command, returning success only.
async fn sh(script: &str) -> Result<bool> {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .await?;
    Ok(out.status.success())
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
        // The default mirror list (no settings file present) gates the pull.
        assert!(mirror_allowed("docker.m.daocloud.io"));
        assert!(!mirror_allowed("evil.example.com"));
        assert!(!registry_allowed("evil.example.com"));
    }

    #[test]
    fn host_line_and_log_validation() {
        assert!(valid_host_line("registry.example.com:5000"));
        assert!(valid_host_line("docker.m.daocloud.io"));
        assert!(!valid_host_line("https://x.com"));
        assert!(!valid_host_line("a b"));
        assert!(valid_log_size("10m"));
        assert!(valid_log_size("512k"));
        assert!(!valid_log_size("10"));
        assert!(!valid_log_size("abc"));
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
            registry: None,
            settings: None,
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
            driver: None,
            subnet: None,
            gateway: None,
            ip_range: None,
            mac: None,
            ipv4: None,
            hostname: None,
            domainname: None,
            dns: None,
            cpu_shares: None,
            privileged: None,
            replace: None,
            new_name: None,
            repo: None,
            tag: None,
            backup: None,
            command: None,
            tty: None,
            cpus: None,
            memory: None,
            channel: None,
            region: None,
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
    fn install_script_selection() {
        // distro channel → native package per family
        assert!(build_install_script("debian", "distro", "global").contains("docker.io"));
        assert!(build_install_script("rhel", "distro", "global").contains("install docker"));
        assert!(build_install_script("arch", "distro", "cn").contains("pacman"));
        assert!(build_install_script("alpine", "distro", "cn").contains("apk add"));
        // ce channel + unknown distro → official convenience script
        assert!(build_install_script("debian", "ce", "global").contains("get.docker.com"));
        assert!(build_install_script("unknown", "distro", "global").contains("get.docker.com"));
        // CN networks add the Aliyun package mirror; global does not.
        assert!(get_docker_script("cn").contains("--mirror Aliyun"));
        assert!(!get_docker_script("global").contains("--mirror"));
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
    fn validates_network_fields() {
        assert!(valid_ipv4("172.20.0.5").is_ok());
        assert!(valid_ipv4("999.1.1.1").is_err());
        assert!(valid_ipv4("172.20.0.5/24").is_err());
        assert!(valid_cidr("172.20.0.0/16").is_ok());
        assert!(valid_cidr("172.20.0.0/33").is_err());
        assert!(valid_cidr("172.20.0.0").is_err());
        assert!(valid_mac("02:42:ac:11:00:02").is_ok());
        assert!(valid_mac("02-42-ac-11-00-02").is_err());
        assert!(valid_mac("02:42:ac:11:00").is_err());
        assert!(valid_hostname("web-01").is_ok());
        assert!(valid_hostname("web.example.com").is_ok());
        assert!(valid_hostname("-bad").is_err());
        assert!(valid_hostname("bad_underscore").is_err());
        assert!(net_driver_allowed("bridge"));
        assert!(net_driver_allowed("macvlan"));
        assert!(!net_driver_allowed("weird"));
    }

    #[test]
    fn build_create_spec_endpoint_and_resources() {
        let mut req = mk_req("nginx");
        req.network = Some("mynet".into());
        req.ipv4 = Some("172.20.0.10".into());
        req.mac = Some("02:42:ac:14:00:0a".into());
        req.hostname = Some("web-01".into());
        req.domainname = Some("example.com".into());
        req.dns = Some(vec!["1.1.1.1".into(), "8.8.8.8".into()]);
        req.cpu_shares = Some(2048);
        req.privileged = Some(true);
        let (spec, _) = build_create_spec(&req).unwrap();
        let hc = spec.config.host_config.as_ref().unwrap();
        assert_eq!(hc.cpu_shares, Some(2048));
        assert_eq!(hc.privileged, Some(true));
        assert_eq!(hc.dns.as_ref().unwrap().len(), 2);
        assert_eq!(spec.config.hostname.as_deref(), Some("web-01"));
        assert_eq!(spec.config.domainname.as_deref(), Some("example.com"));
        let nc = spec.config.networking_config.as_ref().unwrap();
        let ep = nc.endpoints_config.get("mynet").unwrap();
        assert_eq!(ep.mac_address.as_deref(), Some("02:42:ac:14:00:0a"));
        assert_eq!(
            ep.ipam_config.as_ref().unwrap().ipv4_address.as_deref(),
            Some("172.20.0.10")
        );
    }

    #[test]
    fn build_create_spec_rejects_endpoint_without_network() {
        let mut req = mk_req("nginx");
        req.ipv4 = Some("172.20.0.10".into());
        assert!(build_create_spec(&req).is_err());
    }

    #[test]
    fn build_create_spec_rejects_bad_cpu_shares() {
        let mut req = mk_req("nginx");
        req.cpu_shares = Some(1);
        assert!(build_create_spec(&req).is_err());
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
