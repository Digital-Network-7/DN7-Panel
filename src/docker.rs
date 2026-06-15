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
pub(crate) struct Req {
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
    /// Networks to join at create time (each with optional MAC / static IPv4).
    /// A container can be attached to several networks; the first is set on the
    /// create call, the rest are connected right after.
    #[serde(default)]
    networks: Option<Vec<NetAttach>>,
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
    // tag_image -> one or more new repo:tag references to add to an image
    #[serde(default)]
    tags: Option<Vec<String>>,
    // backup file name (list/delete/restore/download)
    #[serde(default)]
    backup: Option<String>,
    // list_dirs: a (partial) absolute host path to suggest directories for.
    #[serde(default)]
    path: Option<String>,
    // optional command override (argv, whitespace-split client-side or here)
    #[serde(default)]
    command: Option<String>,
    // allocate a pseudo-TTY (-t); keeps shells like `ubuntu`/`bash` alive
    #[serde(default)]
    tty: Option<bool>,
    // keep STDIN open (-i); maps to open_stdin so the container accepts input
    #[serde(default)]
    interactive: Option<bool>,
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
pub(crate) struct PortMap {
    host: i64,
    container: i64,
    #[serde(default)]
    proto: Option<String>, // "tcp" | "udp", default tcp
    #[serde(default)]
    ipv6: Option<bool>, // also bind the host IPv6 wildcard (::) for this port
}

/// One network attachment for a container: the network name plus an optional
/// MAC address and static IPv4 for the endpoint on that network.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct NetAttach {
    #[serde(default)]
    network: String,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    ipv4: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct VolumeMap {
    host: String,
    container: String,
    #[serde(default)]
    readonly: bool,
}

/// A validated container creation spec, ready for the bollard create API.
/// Kept in the parent so descendant submodules + tests can read its fields.
pub(crate) struct CreateSpec {
    image: String,
    name: Option<String>,
    start: bool,
    config: bollard::container::Config<String>,
    /// When set, remove this existing container before creating (edit/upgrade).
    replace: Option<String>,
    /// Networks (beyond the first) to connect after creation, each with an
    /// optional MAC / static IPv4.
    extra_networks: Vec<NetAttach>,
}

// ---------------------------------------------------------------------------
// Operation submodules (see .kiro/steering/code-structure.md). Shared structs
// (Req/PortMap/NetAttach/VolumeMap/CreateSpec) stay in this parent so
// descendant modules can read their private fields via `use super::*`.
// ---------------------------------------------------------------------------
mod backups;
mod containers;
mod create;
mod images;
mod info;
mod install;
mod lifecycle;
mod networks;
mod opreg;
mod pull;
mod settings;
mod validate;
mod volumes;
pub use backups::*;
use containers::*;
use create::*;
use images::*;
use info::*;
use install::*;
use lifecycle::*;
use networks::*;
pub(crate) use opreg::pull_pct;
use opreg::*;
use pull::*;
use settings::*;
use validate::*;
use volumes::*;

#[cfg(test)]
mod tests;

/// op result `data` on success.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad docker request: {e}"))?;
    handle(&r).await
}

/// Dispatch one request. Long ops (`pull_image`, `install`) start a detached
/// task and return an `op_id` immediately.
async fn handle(req: &Req) -> Result<Value> {
    guard_managed_ops(req).await?;
    match req.op.as_str() {
        "info" => docker_info().await,
        "list_images" => list_images().await,
        "pull_image" => start_pull(req),
        "create_container" => {
            check_port_conflicts(req).await?;
            start_create(req)
        }
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
        "remove_image" => remove_image_op(req).await,
        "tag_image" => add_image_tags(req).await,
        "retag_image" => retag_image(req).await,
        "list_containers" => list_containers().await,
        "list_dirs" => list_dir_suggest(req),
        "inspect_container" => inspect_container(req).await,
        "start_container" => container_action(req, "start").await,
        "stop_container" => container_action(req, "stop").await,
        "restart_container" => container_action(req, "restart").await,
        "remove_container" => container_action(req, "remove").await,
        "pause_container" => container_action(req, "pause").await,
        "unpause_container" => container_action(req, "unpause").await,
        "kill_container" => container_action(req, "kill").await,
        "logs" => container_logs(req).await,
        "list_networks" => list_networks().await,
        "create_network" => create_network_op(req).await,
        "remove_network" => remove_network_op(req).await,
        "inspect_container_networks" => inspect_container_networks(req).await,
        "rename_network" => rename_network(req).await,
        "network_ips" => network_ips(req).await,
        "set_network_ip" => set_network_ip(req).await,
        "connect_network" => connect_network_op(req).await,
        "disconnect_network" => disconnect_network_op(req).await,
        "list_volumes" => list_volumes().await,
        "create_volume" => create_volume_op(req).await,
        "remove_volume" => remove_volume_op(req).await,
        "get_settings" => Ok(dk_settings_json()),
        "set_settings" => set_dk_settings(req).await,
        "set_registry_lists" => set_registry_lists(req).await,
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

/// Reject operations on DN7 Panel-managed service containers/images (nginx /
/// mysql) on the generic Docker channel — they're managed by their own modules
/// so state/volumes stay consistent. Applies to every caller (web console AND
/// the mini-program relay).
async fn guard_managed_ops(req: &Req) -> Result<()> {
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
            if let Some(owner) = image_in_use_guard(r).await {
                return Err(anyhow!(
                    "镜像正在被容器「{}」引用，无法删除。请先删除相关容器后再试。",
                    owner
                ));
            }
        }
    }
    Ok(())
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
