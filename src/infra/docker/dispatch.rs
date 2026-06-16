//! Docker capability dispatch (authoritative per-op match) + managed-service
//! guards, ref/token validation, and the typed-error bridge.
use super::*;

/// Build the transitional `anyhow` error for a typed [`DockerError`]: prefixes
/// the semantic code with the `ERR_CODE:` transport marker the `op_err_body`
/// web boundary parses into the wire `code`. The marker lives here (infra), not
/// in the core enum, per §2/§4.
pub(crate) fn docker_err(e: DockerError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// op result `data` on success.
///
/// Execute one already-parsed docker request. The `app::docker` router owns
/// parsing + the in-memory op-registry ops; this holds the authoritative match
/// for the container/image/network/volume ops (each interleaved with bollard
/// daemon state, so it stays as one adapter cluster). Long ops (`pull_image`,
/// `install`) start a detached task and return an `op_id` immediately.
pub(crate) async fn run_op(req: &Req, is_super: bool) -> Result<Value> {
    guard_managed_ops(req).await?;
    match req.op.as_str() {
        "info" => docker_info().await,
        "list_images" => list_images().await,
        "pull_image" => start_pull(req),
        "create_container" => {
            // Guardrail: privileged / host-network are super-only (default deny).
            enforce_create_policy(req, is_super)?;
            check_port_conflicts(req).await?;
            start_create(req)
        }
        "install" => start_install(req),
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
        "restore_backup" => start_restore_backup(req, is_super),
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

/// In-memory detached-op-registry projections + dismiss, exposed for the
/// `app::docker` router (the registry fns are module-private). These ops touch
/// neither Docker nor any container — pure process-local state.
pub(crate) fn ops_snapshot_value() -> Value {
    ops_snapshot()
}
pub(crate) fn op_log_value(op_id: &str) -> Value {
    op_log(op_id)
}
pub(crate) fn op_dismiss_registry(op_id: &str) {
    op_dismiss(op_id);
}

/// Reject operations on DN7 Panel-managed service containers/images (nginx /
/// mysql) on the generic Docker channel — they're managed by their own modules
/// so state/volumes stay consistent. Applies to every caller (web console AND
/// the mini-program relay).
pub(crate) async fn guard_managed_ops(req: &Req) -> Result<()> {
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
                return Err(docker_err(DockerError::ImageInUseBuiltin));
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
pub(crate) async fn managed_container_guard(reference: &str) -> Option<String> {
    let dkr = dkr().ok()?;
    let c = dkr.inspect_container(reference, None).await.ok()?;
    let name = c.name.unwrap_or_default();
    let name = name.trim_start_matches('/');
    let labels = c
        .config
        .as_ref()
        .and_then(|cf| cf.labels.clone())
        .unwrap_or_default();
    let is_mysql = name == crate::infra::mysql::CONTAINER || labels.contains_key("dn7.mysql");
    if is_mysql {
        // The caller wraps this message in `anyhow!`, so it carries the full
        // ERR_CODE: marker — sourced from the typed code so it can't drift.
        Some(format!(
            "ERR_CODE:{}",
            DockerError::ContainerManagedMysql.code()
        ))
    } else {
        None
    }
}

/// True if `reference` is an image used by a DN7 Panel-managed service container
/// (nginx / mysql) — such images can't be removed from the Docker page.
pub(crate) async fn managed_image_guard(reference: &str) -> bool {
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

pub(crate) fn need_ref(req: &Req) -> Result<String> {
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
pub(crate) fn need_network(req: &Req) -> Result<String> {
    let n = req
        .network
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| docker_err(DockerError::MissingNetworkName))?;
    validate_token(n)?;
    Ok(n.to_string())
}

/// Reject values that don't look like a plausible docker id / name / ref so a
/// crafted value can't smuggle extra `docker` flags. Allows the characters that
/// appear in image refs (registry/name:tag@sha256:...), container names and ids.
pub(crate) fn validate_token(s: &str) -> Result<()> {
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
