//! In-house container-runtime backend for the docker API — the DEFAULT backend
//! on Linux (`DN7_RUNTIME=docker` opts back into the external Docker daemon).
//!
//! Maps the panel's docker ops to the `dn7-container` crate, returning the SAME
//! JSON shapes the UI consumes. It is **Linux-only** (the crate drives
//! namespaces / cgroup v2 / pivot_root directly), so on other platforms — and for
//! any op not yet implemented here — [`try_run_op`] returns `None` and the caller
//! falls back to the bollard backend. bollard therefore stays the default and the
//! cross-platform fallback; this backend is opt-in and migrates ops incrementally.

use super::*;

#[cfg(target_os = "linux")]
use dn7_container::container::state::{State as DnState, Status as DnStatus};

/// Whether the in-house runtime backend is selected. Delegates to the single
/// source of truth ([`dn7_container::selected`]) — the in-house runtime is the
/// DEFAULT on Linux; `DN7_RUNTIME=docker` opts back into the external daemon.
#[cfg(target_os = "linux")]
fn active() -> bool {
    dn7_container::selected()
}

/// Try to handle `req` with the dn7 backend. `None` means "not active, or this op
/// isn't implemented yet" — the caller then uses bollard.
#[cfg(target_os = "linux")]
pub(crate) async fn try_run_op(req: &Req, is_super: bool) -> Option<Result<Value>> {
    if !active() {
        return None;
    }
    match req.op.as_str() {
        // The runtime is synchronous → run its calls on the blocking pool.
        "info" => Some(run_blocking(info).await),
        "list_images" => Some(run_blocking(list_images).await),
        "list_networks" => Some(run_blocking(list_networks).await),
        "list_volumes" => Some(run_blocking(list_volumes).await),
        "pull_image" => Some(start_pull(req)),
        "remove_image" => Some(op_remove_image(req).await),
        "tag_image" => Some(op_tag_image(req).await),
        "create_volume" => Some(op_create_volume(req).await),
        "remove_volume" => Some(op_remove_volume(req).await),
        "create_container" => Some(op_create_container(req, is_super).await),
        "list_containers" => Some(run_blocking(list_containers).await),
        "inspect_container" => Some(op_inspect_container(req).await),
        "container_stats" => Some(op_container_stats(req).await),
        "get_container_config" => Some(op_get_container_config(req).await),
        "start_container" => Some(op_container_action(req, "start").await),
        "stop_container" => Some(op_container_action(req, "stop").await),
        "restart_container" => Some(op_container_action(req, "restart").await),
        "remove_container" => Some(op_container_action(req, "remove").await),
        "pause_container" => Some(op_container_action(req, "pause").await),
        "unpause_container" => Some(op_container_action(req, "unpause").await),
        "kill_container" => Some(op_container_action(req, "kill").await),
        "logs" => Some(op_logs(req).await),
        "rename_container" => Some(op_rename_container(req).await),
        "commit_container" => Some(op_commit_container(req).await),
        "network_ips" => Some(op_network_ips(req).await),
        "inspect_container_networks" => Some(op_inspect_container_networks(req).await),
        "create_network" => Some(op_create_network(req).await),
        "remove_network" => Some(op_remove_network(req).await),
        "rename_network" => Some(op_rename_network(req).await),
        "set_network_ip" => Some(op_set_network_ip(req).await),
        "connect_network" => Some(op_connect_network(req).await),
        "disconnect_network" => Some(op_disconnect_network(req).await),
        "retag_image" => Some(op_retag_image(req).await),
        "backup_container" => Some(op_backup_container(req)),
        "restore_backup" => Some(op_restore_backup(req, is_super)),
        // `list_backups` / `delete_backup` / `list_dirs` are pure filesystem ops
        // (no daemon) → they fall through to the shared handlers unchanged.
        // Anything absent falls through to the bollard path.
        _ => None,
    }
}

/// Run a synchronous dn7-container call off the async runtime's worker threads.
#[cfg(target_os = "linux")]
async fn run_blocking<F>(f: F) -> Result<Value>
where
    F: FnOnce() -> Result<Value> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| anyhow!("dn7 task panicked: {e}"))?
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn try_run_op(_req: &Req, _is_super: bool) -> Option<Result<Value>> {
    None // the dn7-container crate is Linux-only; always use bollard elsewhere
}

/// `info` in the panel's docker-info shape, reporting the in-house runtime.
#[cfg(target_os = "linux")]
fn info() -> Result<Value> {
    let cgroup_v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let ver = "dn7-container 0.1.0";
    Ok(json!({
        "installed": true,
        "daemon_running": true,
        "docker_present": false,
        "server_version": ver,
        "client_version": ver,
        "compose_version": Value::Null,
        "cgroup_v2": cgroup_v2,
        "host_cpus": cpus,
        "host_mem_bytes": mem_total_bytes(),
        "runtime": "dn7",
    }))
}

/// `list_images` in the panel's image-row shape, from the dn7 image store.
#[cfg(target_os = "linux")]
fn list_images() -> Result<Value> {
    use super::images::{human_since, human_size, split_repo_tag};

    let store = dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
    let summaries = dn7_container::image::list_summaries(&store)
        .map_err(|e| anyhow!("dn7 list images: {e}"))?;

    let items: Vec<Value> = summaries
        .into_iter()
        .map(|s| {
            let short_id = s
                .config_digest
                .strip_prefix("sha256:")
                .unwrap_or(&s.config_digest)
                .chars()
                .take(12)
                .collect::<String>();
            let (repo, tag) = split_repo_tag(&s.reference);
            let name = s.reference;
            json!({
                "id": short_id,
                "name": name.clone(),
                "tags": [name],
                "repo": repo,
                "tag": tag,
                "size": human_size(s.size),
                "created": human_since(s.created_ts),
                "created_ts": s.created_ts,
                // dn7 doesn't track panel-managed / in-use yet (no daemon image
                // refcount); reported false until the container ops are migrated.
                "managed": false,
                "in_use": false,
            })
        })
        .collect();
    Ok(json!({ "images": items }))
}

/// `list_networks` in the panel's network-row shape. dn7 has the managed bridge
/// network(s); ids are a stable hash of the name (dn7 has no random network ids).
#[cfg(target_os = "linux")]
fn list_networks() -> Result<Value> {
    use dn7_container::net::registry;
    let items: Vec<Value> = registry::all()
        .into_iter()
        .map(|n| {
            let builtin = registry::is_builtin(&n.name);
            json!({
                "id": short_hash(&n.name),
                "name": n.name,
                "driver": "bridge",
                "scope": "local",
                "subnet": n.subnet.to_string(),
                "gateway": n.gateway.to_string(),
                // The built-in default is protected; user networks are removable.
                "builtin": builtin,
            })
        })
        .collect();
    Ok(json!({ "networks": items }))
}

/// `list_volumes` in the panel's volume-row shape, from the dn7 volumes dir.
/// Size/refs are unknown for now (reported as Docker does without usage data).
#[cfg(target_os = "linux")]
fn list_volumes() -> Result<Value> {
    let vols = dn7_container::image::volume::list().map_err(|e| anyhow!("dn7 volumes: {e}"))?;
    let items: Vec<Value> = vols
        .into_iter()
        .map(|v| {
            json!({
                "name": v.name,
                "driver": "local",
                "mountpoint": v.path.to_string_lossy(),
                "created": "-",
                "size": "-",
                "refs": -1,
                "managed": v.name.starts_with("dn7-"),
            })
        })
        .collect();
    Ok(json!({ "volumes": items }))
}

/// `pull_image` (detached): pull into the dn7 store on a background task,
/// reporting coarse progress to the shared op-registry. Mirrors bollard's
/// `start_pull` (returns `{op_id, target}` immediately).
#[cfg(target_os = "linux")]
fn start_pull(req: &Req) -> Result<Value> {
    let image = req
        .image
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("missing image"))?
        .to_string();
    validate_token(&image)?;

    let op_id = new_op_id();
    op_create(&op_id, "pull", &image);
    let op_id_t = op_id.clone();
    let target = image.clone();

    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.pulling", &[image.as_str()]));
        let img = image.clone();
        let pulled = tokio::task::spawn_blocking(move || {
            let store = dn7_container::image::Store::open().map_err(|e| e.to_string())?;
            dn7_container::image::pull(&img, &store)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .await;
        match pulled {
            Ok(Ok(())) => {
                op_push(&op_id_t, &pmsg("dk.done", &[]));
                op_finish(&op_id_t, "done", "", &image);
            }
            Ok(Err(e)) => op_finish(&op_id_t, "error", &e, ""),
            Err(e) => op_finish(&op_id_t, "error", &format!("pull task: {e}"), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

/// `remove_image`: drop the image record from the dn7 store, after a dn7-native
/// in-use check (the shared `guard_managed_ops` guard consults the absent bollard
/// daemon and no-ops under `DN7_RUNTIME=dn7`).
#[cfg(target_os = "linux")]
async fn op_remove_image(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let store = dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        // Refuse to delete an image still referenced by any dn7 container, so its
        // overlay lower layer can't be pulled out from under a running/stopped one.
        if let Some(users) = dn7_image_users(&r) {
            return Err(anyhow!("镜像正被容器使用，无法删除（{users}）"));
        }
        dn7_container::image::remove_image(&store, &r).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "removed": r }))
    })
    .await
}

/// Comma-joined ids of dn7 containers whose source image resolves to the same
/// store key as `reference`, or `None` if the image is unused.
#[cfg(target_os = "linux")]
fn dn7_image_users(reference: &str) -> Option<String> {
    use dn7_container::image::Reference;
    let want = Reference::parse(reference).ok().map(|x| x.store_key());
    let ids: Vec<String> = dn7_container::container::list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| match s.meta.image.as_deref() {
            None => false,
            Some(img) if img == reference => true,
            Some(img) => match (&want, Reference::parse(img).ok()) {
                (Some(w), Some(got)) => &got.store_key() == w,
                _ => false,
            },
        })
        .map(|s| s.id)
        .collect();
    (!ids.is_empty()).then(|| ids.join(", "))
}

/// `tag_image`: add one or more tags pointing at `src`'s content. Same validation
/// as bollard's path (≤20 tags, each a valid token).
#[cfg(target_os = "linux")]
async fn op_tag_image(req: &Req) -> Result<Value> {
    let src = need_ref(req)?;
    let tags: Vec<String> = req
        .tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if tags.is_empty() {
        return Err(docker_err(DockerError::TagEmpty));
    }
    if tags.len() > 20 {
        return Err(docker_err(DockerError::TooManyTags));
    }
    for t in &tags {
        if validate_token(t).is_err() {
            return Err(docker_err(DockerError::BadTag));
        }
    }
    let n = tags.len();
    run_blocking(move || {
        let store = dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        for t in &tags {
            dn7_container::image::tag_image(&store, &src, t).map_err(|e| anyhow!("{e}"))?;
        }
        Ok(json!({ "tagged": src, "count": n }))
    })
    .await
}

/// `create_volume`: create a named managed volume. dn7 has no host-path-backed
/// named volumes yet — a `path` is rejected (use a bind mount instead).
#[cfg(target_os = "linux")]
async fn op_create_volume(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| docker_err(DockerError::MissingVolumeName))?
        .to_string();
    validate_name(&name)?;
    if req
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
    {
        return Err(anyhow!(
            "dn7: host-path named volumes are not supported yet; use a bind mount"
        ));
    }
    run_blocking(move || {
        dn7_container::image::volume::create(&name).map_err(|e| anyhow!("dn7 volume: {e}"))?;
        Ok(json!({ "created": name }))
    })
    .await
}

/// `remove_volume`: remove a named volume (managed `dn7-` volumes are protected).
#[cfg(target_os = "linux")]
async fn op_remove_volume(req: &Req) -> Result<Value> {
    let name = need_ref(req)?;
    if name.starts_with("dn7-") {
        return Err(docker_err(DockerError::VolumeManaged));
    }
    run_blocking(move || {
        dn7_container::image::volume::remove(&name).map_err(|e| anyhow!("dn7 volume: {e}"))?;
        Ok(json!({ "removed": name }))
    })
    .await
}

/// A fully-validated, translated dn7 create plan (the bridge between the panel's
/// `Req` and the runtime's `ImageRunSpec`/`StateMeta`).
#[cfg(target_os = "linux")]
struct Dn7CreatePlan {
    spec: dn7_container::container::ImageRunSpec,
    meta: dn7_container::container::state::StateMeta,
    /// What `op_create`/the return reports (display name, else image).
    target: String,
    start: bool,
    /// Edit/upgrade: an existing container to remove before creating.
    replace: Option<String>,
    image: String,
    /// Additional networks to attach after the container starts (the primary is
    /// wired at create; docker `network connect` for each of these).
    extra_nets: Vec<NetAttach>,
}

/// Validate `req` (reusing the panel's `build_create_spec`, so validation + error
/// codes match bollard exactly), reject the options dn7 cannot honor, and
/// translate the rest into a runtime create plan. Pure + synchronous → unit-testable.
#[cfg(target_os = "linux")]
fn build_dn7_create(req: &Req) -> Result<Dn7CreatePlan> {
    // Full panel-grade validation (token/name/restart/ports/env/binds/cpu·mem/
    // dns/hostname/networks). Discards the bollard config it builds; we re-derive
    // from the now-known-valid `req` to avoid a bollard round-trip.
    let (cspec, display_name) = build_create_spec(req)?;

    // Reject what dn7 cannot deliver — never silently degrade a security option.
    if req.privileged.unwrap_or(false) {
        return Err(anyhow!("ERR_CODE:dn7.create_privileged_unsupported"));
    }

    // Networking: the PRIMARY attachment (its network + optional static IP) is
    // wired at create; any additional networks the form requested are attached
    // after start via `net_connect`. The primary comes from the first `networks`
    // row if present, else the host_config network_mode. A network NAME (built-in
    // `bridge`/`dn7` or a user network) passes through as the mode so the runtime
    // resolves it; `host`/`none` are the special modes.
    let rows: Vec<NetAttach> = req.networks.clone().unwrap_or_default();
    let hc_mode = cspec
        .config
        .host_config
        .as_ref()
        .and_then(|h| h.network_mode.clone());
    let primary_name = rows
        .first()
        .map(|a| a.network.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(hc_mode);
    let primary_ip = rows
        .first()
        .and_then(|a| a.ipv4.clone())
        .filter(|s| !s.trim().is_empty());
    let extra_nets: Vec<NetAttach> = rows.iter().skip(1).cloned().collect();
    let (net_mode, net_name_requested) = match primary_name.as_deref() {
        None | Some("bridge") | Some("dn7") => ("bridge".to_string(), None),
        Some("host") => ("host".to_string(), None),
        Some("none") => ("none".to_string(), None),
        Some(other) => (other.to_string(), Some(other.to_string())),
    };

    // Container id = the (validated) name, or a generated one when anonymous.
    // dn7 ids are stricter than panel names (lowercase, ≤64, derive veth/netns
    // names) — reject a name that can't be one.
    let name = cspec.name.clone();
    let id = match &name {
        Some(n) if is_valid_dn7_id(n) => n.clone(),
        Some(_) => return Err(anyhow!("ERR_CODE:dn7.create_name_invalid")),
        None => gen_container_id(),
    };

    let target = if display_name.is_empty() {
        cspec.image.clone()
    } else {
        display_name
    };

    // Published ports → dn7 `-p` string (ipv6 wildcard dropped — nft DNAT is v4).
    let ports_spec = req
        .ports
        .iter()
        .flatten()
        .map(|p| {
            format!(
                "{}:{}/{}",
                p.host,
                p.container,
                p.proto.as_deref().unwrap_or("tcp")
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    // Volumes → resolved mounts (host paths already deny-listed by build_create_spec).
    let mut volumes = Vec::new();
    for v in req.volumes.iter().flatten() {
        let (host, container) = (v.host.trim(), v.container.trim());
        if host.is_empty() || container.is_empty() {
            continue;
        }
        let s = if v.readonly {
            format!("{host}:{container}:ro")
        } else {
            format!("{host}:{container}")
        };
        volumes
            .push(dn7_container::image::volume::resolve(&s).map_err(|e| anyhow!("dn7 卷: {e}"))?);
    }

    let env_extra: Vec<String> = req
        .env
        .iter()
        .flatten()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    let cmd = match trimmed(&req.command) {
        Some(c) => split_command(&c)?,
        None => Vec::new(),
    };
    let dns: Vec<String> = req
        .dns
        .iter()
        .flatten()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    let hostname = trimmed(&req.hostname);

    let mem_limit = trimmed(&req.memory).map(|m| mem_to_bytes(&m) as i64);
    let cpus_val = trimmed(&req.cpus).and_then(|c| c.parse::<f64>().ok());
    let cpu_quota = cpus_val.map(|v| ((v * 100_000.0) as i64, 100_000u64));
    let nano_cpus = cpus_val.map(|v| (v * 1_000_000_000.0) as i64);
    let cpu_shares_i = req.cpu_shares.filter(|v| *v > 0);

    let restart_str = trimmed(&req.restart).unwrap_or_else(|| "unless-stopped".to_string());

    let spec = dn7_container::container::ImageRunSpec {
        id,
        reference: cspec.image.clone(),
        cmd: cmd.clone(),
        net_mode,
        ports: ports_spec.clone(),
        volumes,
        env_extra: env_extra.clone(),
        dns: dns.clone(),
        hostname: hostname.clone(),
        mem_limit,
        cpu_quota,
        cpu_shares: cpu_shares_i.map(|v| v as u64),
        pids_limit: None,
        tty: req.tty.unwrap_or(false),
        static_ip: primary_ip.clone(),
    };
    let meta = dn7_container::container::state::StateMeta {
        image: Some(cspec.image.clone()),
        name,
        restart_policy: Some(restart_str),
        tty: req.tty.unwrap_or(false),
        open_stdin: req.interactive.unwrap_or(req.tty.unwrap_or(false)),
        hostname,
        domainname: trimmed(&req.domainname),
        dns,
        env: env_extra,
        cmd,
        mem_limit,
        nano_cpus,
        cpu_shares: cpu_shares_i,
        privileged: false,
        ports_spec,
        net_name_requested,
        create_spec: Some(create_body(req)),
        ..Default::default()
    };

    Ok(Dn7CreatePlan {
        spec,
        meta,
        target,
        start: cspec.start,
        replace: cspec.replace.clone(),
        image: cspec.image,
        extra_nets,
    })
}

/// dn7-native port-conflict check (the bollard `check_port_conflicts` we bypass
/// queries the absent daemon). Rejects a create/edit when a published host port
/// clashes with: (a) another port in the same form, (b) a port already published
/// by a different *running* dn7 container, or (c) a port held by some other host
/// process. The container being replaced (edit/upgrade) is excluded so it can
/// reuse its own ports. dn7 publishes via nft DNAT (no host-side bind), so a peer
/// container's port won't show up to `port_busy` — hence the container-list scan.
#[cfg(target_os = "linux")]
fn check_dn7_port_conflicts(req: &Req) -> Result<()> {
    let ports = match &req.ports {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()),
    };
    // (a) Duplicate host port (same protocol) within the form itself.
    reject_duplicate_ports(ports)?;

    // The container being edited/upgraded may reuse its own ports.
    let mut excluded: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(r) = trimmed(&req.replace) {
        excluded.insert(r);
    }
    if let Some(n) = trimmed(&req.name) {
        excluded.insert(n);
    }

    // Map every host port published by a *running* dn7 container -> owner id/name.
    let mut held: std::collections::HashMap<(i64, String), String> =
        std::collections::HashMap::new();
    for s in dn7_container::container::list().map_err(|e| anyhow!("dn7 list: {e}"))? {
        if !matches!(s.status, DnStatus::Running) {
            continue;
        }
        let owner = s.meta.name.clone().unwrap_or_else(|| s.id.clone());
        for (hp, proto) in parse_ports_spec(&s.meta.ports_spec) {
            held.entry((hp, proto)).or_insert_with(|| owner.clone());
        }
    }

    // (b) running-container conflict, then (c) host-process conflict.
    for p in ports {
        let proto = p.proto.as_deref().unwrap_or("tcp").to_string();
        match held.get(&(p.host, proto.clone())) {
            Some(owner) if !excluded.contains(owner) => {
                return Err(anyhow!(
                    "宿主机端口 {}/{} 已被容器「{}」占用，无法映射。",
                    p.host,
                    proto.to_uppercase(),
                    owner
                ));
            }
            Some(_) => {} // held by the container we're replacing — reuse is fine.
            None => {
                if port_busy(p.host, &proto) {
                    return Err(anyhow!(
                        "宿主机端口 {}/{} 已被其他进程占用，无法映射。",
                        p.host,
                        proto.to_uppercase()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Parse a dn7 `ports_spec` (`hp:cp[/proto],...`) into `(host_port, proto)` pairs.
#[cfg(target_os = "linux")]
fn parse_ports_spec(spec: &str) -> Vec<(i64, String)> {
    let mut out = Vec::new();
    for p in spec.split(',').filter(|s| !s.is_empty()) {
        let (hostpart, proto) = p.rsplit_once('/').unwrap_or((p, "tcp"));
        if let Some((hp, _cp)) = hostpart.split_once(':') {
            if let Ok(host) = hp.parse::<i64>() {
                out.push((host, proto.to_string()));
            }
        }
    }
    out
}

/// `create_container` (detached): validate + translate, then create (and start)
/// on the blocking pool, reporting to the op-registry. Mirrors bollard's
/// `start_create` and returns `{op_id, target}` immediately.
#[cfg(target_os = "linux")]
async fn op_create_container(req: &Req, is_super: bool) -> Result<Value> {
    // The super-admin gate for privileged / host-network lives in the bollard
    // arm we bypass — run it here too.
    enforce_create_policy(req, is_super)?;
    // Reject a host-port clash up front (the bollard check_port_conflicts is
    // daemon-backed; this is the dn7-native equivalent).
    check_dn7_port_conflicts(req)?;
    let plan = build_dn7_create(req)?;

    let op_id = new_op_id();
    op_create(&op_id, "create", &plan.target);
    let op_id_t = op_id.clone();
    let target = plan.target.clone();
    let target_t = target.clone();

    let Dn7CreatePlan {
        spec,
        meta,
        start,
        replace,
        image,
        extra_nets,
        ..
    } = plan;

    tokio::spawn(async move {
        op_push(&op_id_t, &pmsg("dk.creating_container", &[]));
        let created = tokio::task::spawn_blocking(move || -> Result<String> {
            // Edit/upgrade: confirm the new image is present locally BEFORE
            // removing the old container (else a bad tag leaves nothing).
            if let Some(old) = &replace {
                let store =
                    dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
                let r =
                    dn7_container::image::Reference::parse(&image).map_err(|e| anyhow!("{e}"))?;
                dn7_container::image::ImageRecord::load(&store, &r.store_key()).map_err(|_| {
                    anyhow!(
                        "镜像「{image}」在本地不存在，已保留原容器；请先拉取该镜像后再编辑/升级。"
                    )
                })?;
                let _ = dn7_container::container::delete(old, true); // best-effort
            }
            let id = dn7_container::container::create_from_image(&spec, meta)
                .map_err(|e| anyhow!("dn7 create: {e}"))?;
            if start {
                dn7_container::container::start(&id).map_err(|e| anyhow!("dn7 start: {e}"))?;
                // Attach any additional requested networks (the primary was wired
                // at create; these are hot-plugged now the container is running).
                for a in &extra_nets {
                    let ip = a.ipv4.as_deref().filter(|s| !s.trim().is_empty());
                    dn7_container::container::net_connect(&id, &a.network, ip)
                        .map_err(|e| anyhow!("dn7 connect {}: {e}", a.network))?;
                }
            }
            Ok(id)
        })
        .await;
        match created {
            Ok(Ok(id)) => {
                let short = id.chars().take(12).collect::<String>();
                op_push(
                    &op_id_t,
                    &pmsg(
                        "dk.container_created",
                        &[
                            if start {
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
            Ok(Err(e)) => op_finish(&op_id_t, "error", &e.to_string(), ""),
            Err(e) => op_finish(&op_id_t, "error", &format!("create task: {e}"), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

/// Trim an optional string to a non-empty owned value.
#[cfg(target_os = "linux")]
fn trimmed(o: &Option<String>) -> Option<String> {
    o.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whether `s` is a valid dn7 container id: lowercase `[a-z0-9][a-z0-9_.-]{0,63}`
/// (stricter than panel names — ids derive veth/netns/cgroup names).
#[cfg(target_os = "linux")]
fn is_valid_dn7_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let first = s.chars().next().unwrap();
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'))
}

/// A unique lowercase id for an anonymous container (no name given).
#[cfg(target_os = "linux")]
fn gen_container_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("dn7c{nanos:x}")
}

/// The panel "recreate body" (`container_create_body` shape) built from the
/// request, stored in State so backups + the edit form round-trip under dn7.
#[cfg(target_os = "linux")]
fn create_body(req: &Req) -> Value {
    let ports: Vec<Value> = req
        .ports
        .iter()
        .flatten()
        .map(|p| {
            json!({
                "host": p.host, "container": p.container,
                "proto": p.proto.as_deref().unwrap_or("tcp"), "ipv6": p.ipv6.unwrap_or(false)
            })
        })
        .collect();
    let volumes: Vec<Value> = req
        .volumes
        .iter()
        .flatten()
        .map(|v| json!({ "host": v.host, "container": v.container, "readonly": v.readonly }))
        .collect();
    let networks: Vec<Value> = req
        .networks
        .iter()
        .flatten()
        .map(|a| json!({ "network": a.network, "mac": a.mac, "ipv4": a.ipv4 }))
        .collect();
    json!({
        "op": "create_container",
        "image": req.image, "name": req.name, "restart": req.restart,
        "ports": ports, "env": req.env, "volumes": volumes, "command": req.command,
        "tty": req.tty.unwrap_or(false), "interactive": req.interactive.unwrap_or(false),
        "networks": networks, "hostname": req.hostname, "domainname": req.domainname,
        "dns": req.dns, "cpu_shares": req.cpu_shares, "cpus": req.cpus,
        "memory": req.memory, "privileged": req.privileged.unwrap_or(false)
    })
}

/// `list_containers`: one row per dn7 container, in the panel's list shape.
#[cfg(target_os = "linux")]
fn list_containers() -> Result<Value> {
    let states = dn7_container::container::list().map_err(|e| anyhow!("dn7 list: {e}"))?;
    let items: Vec<Value> = states.into_iter().map(container_row).collect();
    Ok(json!({ "containers": items }))
}

/// One container list row from a dn7 `State`.
#[cfg(target_os = "linux")]
fn container_row(s: DnState) -> Value {
    let short_id = s.id.chars().take(12).collect::<String>();
    let name = s.meta.name.clone().unwrap_or_else(|| s.id.clone());
    let running = matches!(s.status, DnStatus::Running);
    let ips = dn7_ips(&s.net);
    let ip = ips.first().cloned().unwrap_or_default();
    let description = s
        .meta
        .labels
        .get("org.opencontainers.image.description")
        .or_else(|| s.meta.labels.get("org.opencontainers.image.title"))
        .cloned()
        .unwrap_or_default();
    let status = dn7_status(&s);
    let uptime = if running {
        status.clone()
    } else {
        String::new()
    };
    let managed = false; // no built-in/managed service containers exist anymore
    json!({
        "id": short_id,
        "name": name,
        "image": s.meta.image.clone().unwrap_or_default(),
        "state": dn7_live_state(&s),
        "status": status,
        "ports": fmt_dn7_ports(&s.meta.ports_spec),
        "ip": ip,
        "ips": ips,
        "description": description,
        "uptime": uptime,
        // dn7 has no cheap per-container shell probe yet; assume a running
        // container has /bin/sh (true for nearly all images). Refined later.
        "has_shell": running,
        "managed": managed,
    })
}

/// `inspect_container`: the panel's inspect shape from a dn7 `State`.
#[cfg(target_os = "linux")]
async fn op_inspect_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s = dn7_container::container::state(&id).map_err(|e| anyhow!("dn7 inspect: {e}"))?;
        let running = matches!(s.status, DnStatus::Running);
        Ok(json!({
            "id": short_or(&r, &s.id),
            "name": s.meta.name.clone().unwrap_or_else(|| s.id.clone()),
            "image": s.meta.image.clone().unwrap_or_default(),
            "state": dn7_live_state(&s),
            "running": running,
            "restart_policy": s.meta.restart_policy.clone().unwrap_or_default(),
            "created": s.created_iso(),
            // dn7 doesn't track a separate start timestamp yet; reuse created.
            "started_at": s.created_iso(),
            "exit_code": s.meta.exit_code,
            "restart_count": s.meta.restart_count,
            "ports": fmt_dn7_ports(&s.meta.ports_spec),
            "has_shell": running,
        }))
    })
    .await
}

/// `container_stats`: cgroup-v2 counters. CPU% is derived from two `cpu.stat`
/// samples ~100ms apart; net/blk are not wired yet (reported 0).
#[cfg(target_os = "linux")]
async fn op_container_stats(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s1 = dn7_container::container::stats(&id).map_err(|e| anyhow!("dn7 stats: {e}"))?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let s2 = dn7_container::container::stats(&id).map_err(|e| anyhow!("dn7 stats: {e}"))?;
        let cpu_delta = s2.cpu_usage_usec.saturating_sub(s1.cpu_usage_usec) as f64;
        let cpu_pct = cpu_delta / 100_000.0 * 100.0; // delta-µs / interval-µs * 100
        let online = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1);
        Ok(json!({
            "cpu_pct": (cpu_pct * 100.0).round() / 100.0,
            "cpu_online": online,
            "mem_used": s2.memory_current,
            "mem_limit": s2.memory_max.unwrap_or(0),
            "net_rx": 0, "net_tx": 0, "blk_read": 0, "blk_write": 0,
        }))
    })
    .await
}

/// `get_container_config`: the stored recreate body (for the edit/upgrade form).
#[cfg(target_os = "linux")]
async fn op_get_container_config(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s = DnState::load(&id).map_err(|e| anyhow!("dn7 inspect: {e}"))?;
        let body = s.meta.create_spec.clone().unwrap_or_else(|| json!({}));
        Ok(json!({ "config": body }))
    })
    .await
}

/// Lifecycle actions (start/stop/restart/pause/unpause/kill/remove), mirroring
/// bollard's `container_action`: do the action, return `{<verb>: <ref>}`.
#[cfg(target_os = "linux")]
async fn op_container_action(req: &Req, action: &str) -> Result<Value> {
    let r = need_ref(req)?;
    let action = action.to_string();
    run_blocking(move || {
        use dn7_container::container as ctr;
        let id = resolve_dn7_id(&r)?;
        let verb = match action.as_str() {
            "start" => {
                ctr::start_or_rerun(&id).map_err(|e| anyhow!("dn7 start: {e}"))?;
                "started"
            }
            "stop" => {
                ctr::stop(&id, std::time::Duration::from_secs(10))
                    .map_err(|e| anyhow!("dn7 stop: {e}"))?;
                "stopped"
            }
            "restart" => {
                ctr::restart(&id).map_err(|e| anyhow!("dn7 restart: {e}"))?;
                "restarted"
            }
            "pause" => {
                ctr::pause(&id).map_err(|e| anyhow!("dn7 pause: {e}"))?;
                "paused"
            }
            "unpause" => {
                ctr::unpause(&id).map_err(|e| anyhow!("dn7 unpause: {e}"))?;
                "resumed"
            }
            "kill" => {
                ctr::kill_now(&id).map_err(|e| anyhow!("dn7 kill: {e}"))?;
                "killed"
            }
            "remove" => {
                ctr::delete(&id, true).map_err(|e| anyhow!("dn7 remove: {e}"))?;
                // A removed container may back a website proxy upstream; re-sync so
                // a now-dangling site fails closed instead of proxying a stale IP.
                crate::infra::website::resync_after_container_change();
                "removed"
            }
            other => return Err(anyhow!("unsupported container action: {other}")),
        };
        let mut m = serde_json::Map::new();
        m.insert(verb.to_string(), Value::String(r));
        Ok(Value::Object(m))
    })
    .await
}

/// `logs`: the captured stdout/stderr of a dn7 container, last `tail` lines.
#[cfg(target_os = "linux")]
async fn op_logs(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let tail = req.tail.unwrap_or(200).clamp(1, 2000) as usize;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let bytes = dn7_container::container::logs(&id).map_err(|e| anyhow!("dn7 logs: {e}"))?;
        let text = String::from_utf8_lossy(&bytes);
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(tail);
        Ok(json!({ "logs": lines[start..].join("\n") }))
    })
    .await
}

/// `rename_container`: dn7 ids are immutable (they derive cgroup/netns names), so
/// this updates the display name (`State.meta.name`) only.
#[cfg(target_os = "linux")]
async fn op_rename_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let name = req
        .new_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| docker_err(DockerError::MissingName))?
        .to_string();
    validate_name(&name)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let mut s = DnState::load(&id).map_err(|e| anyhow!("dn7 rename: {e}"))?;
        s.meta.name = Some(name.clone());
        s.save().map_err(|e| anyhow!("dn7 rename: {e}"))?;
        crate::infra::website::resync_after_container_change();
        Ok(json!({ "renamed": name }))
    })
    .await
}

/// `commit_container`: snapshot a container's overlay into a new image `repo:tag`.
#[cfg(target_os = "linux")]
async fn op_commit_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let repo = req
        .repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| docker_err(DockerError::MissingImageName))?
        .to_string();
    validate_token(&repo)?;
    let tag = req
        .tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("latest")
        .to_string();
    validate_token(&tag)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let new_ref = format!("{repo}:{tag}");
        let store = dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        let bundle = dn7_container::container::bundle_dir(&id);
        dn7_container::image::commit::commit(&store, &bundle, &new_ref)
            .map_err(|e| anyhow!("dn7 commit: {e}"))?;
        Ok(json!({ "image": new_ref }))
    })
    .await
}

/// `network_ips`: the subnet/gateway + the containers currently on `net`, read
/// from the dn7 network config + container states.
#[cfg(target_os = "linux")]
async fn op_network_ips(req: &Req) -> Result<Value> {
    let net = need_ref(req)?;
    run_blocking(move || {
        let cfgs = dn7_container::net::ipam::list_networks();
        let (subnet, gateway) = match cfgs.iter().find(|c| c.name == net) {
            Some(c) => (c.subnet.to_string(), c.gateway.to_string()),
            None => (String::new(), String::new()),
        };
        let mut cons = Vec::new();
        for s in dn7_container::container::list().map_err(|e| anyhow!("dn7 list: {e}"))? {
            let Some(n) = &s.net else { continue };
            if n.network != net {
                continue;
            }
            cons.push(json!({
                "id": s.id.chars().take(12).collect::<String>(),
                "full_id": s.id,
                "name": s.meta.name.clone().unwrap_or_else(|| s.id.clone()),
                "ipv4": n.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                "mac": n.mac.clone().unwrap_or_default(),
            }));
        }
        cons.sort_by_key(|c| c["name"].as_str().unwrap_or("").to_string());
        // User networks support per-endpoint static-IP edit + disconnect; the
        // built-in default network is view-only.
        let editable = !dn7_container::net::registry::is_builtin(&net);
        Ok(json!({ "name": net, "subnet": subnet, "gateway": gateway, "editable": editable, "containers": cons }))
    })
    .await
}

/// `inspect_container_networks`: which network a container is on. dn7 has a single
/// network, so there is never another one "available" to hot-attach.
#[cfg(target_os = "linux")]
async fn op_inspect_container_networks(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s = DnState::load(&id).map_err(|e| anyhow!("dn7 inspect: {e}"))?;
        let attached: Vec<String> = s
            .net
            .as_ref()
            .filter(|n| n.mode == "bridge")
            .map(|n| vec![n.network.clone()])
            .unwrap_or_default();
        Ok(json!({ "attached": attached, "available": [] }))
    })
    .await
}

// dn7 supports a built-in default network plus user-defined bridge networks
// (create/remove/rename), per-container static IPs, and runtime attach/detach.
#[cfg(target_os = "linux")]
async fn op_create_network(req: &Req) -> Result<Value> {
    let name = trimmed(&req.name).ok_or_else(|| anyhow!("network name is required"))?;
    let subnet = trimmed(&req.subnet).ok_or_else(|| anyhow!("subnet (CIDR) is required"))?;
    let gateway = req.gateway.clone().unwrap_or_default();
    run_blocking(move || {
        use dn7_container::net::registry;
        let (net, gw) = registry::parse_subnet(&subnet, &gateway).map_err(|e| anyhow!("{e}"))?;
        let cfg = registry::create(&name, net, gw).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({
            "created": cfg.name,
            "bridge": cfg.bridge,
            "subnet": cfg.subnet.to_string(),
            "gateway": cfg.gateway.to_string(),
        }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_remove_network(req: &Req) -> Result<Value> {
    let name = need_ref(req)?;
    run_blocking(move || {
        dn7_container::net::registry::remove(&name).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "removed": name }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_rename_network(req: &Req) -> Result<Value> {
    let old = need_ref(req)?;
    let new = trimmed(&req.new_name).ok_or_else(|| anyhow!("new network name is required"))?;
    run_blocking(move || {
        dn7_container::net::registry::rename(&old, &new).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "renamed": new }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_set_network_ip(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("network is required"))?;
    let ipv4 = trimmed(&req.ipv4).ok_or_else(|| anyhow!("ipv4 is required"))?;
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        dn7_container::container::net_set_ip(&id, &network, &ipv4).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "ok": true, "ip": ipv4 }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_connect_network(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("network is required"))?;
    let ipv4 = trimmed(&req.ipv4);
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        let (ip, ifname) = dn7_container::container::net_connect(&id, &network, ipv4.as_deref())
            .map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "connected": network, "ip": ip, "ifname": ifname }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_disconnect_network(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("network is required"))?;
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        dn7_container::container::net_disconnect(&id, &network).map_err(|e| anyhow!("{e}"))?;
        Ok(json!({ "disconnected": network }))
    })
    .await
}

/// `retag_image`: reconcile an image's tags. Current tags = every stored
/// reference sharing this image's config digest; add the missing desired ones,
/// remove the no-longer-desired ones. Mirrors bollard's `retag_image`.
#[cfg(target_os = "linux")]
async fn op_retag_image(req: &Req) -> Result<Value> {
    let reference = need_ref(req)?;
    let mut desired: Vec<String> = req
        .tags
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    desired.dedup();
    if desired.is_empty() {
        return Err(docker_err(DockerError::TagEmpty));
    }
    if desired.len() > 20 {
        return Err(docker_err(DockerError::TooManyTags));
    }
    for t in &desired {
        if validate_token(t).is_err() {
            return Err(docker_err(DockerError::BadTag));
        }
    }
    run_blocking(move || {
        use dn7_container::image;
        let store = image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        let r = image::Reference::parse(&reference).map_err(|e| anyhow!("{e}"))?;
        let rec = image::ImageRecord::load(&store, &r.store_key())
            .map_err(|_| anyhow!("no such image: {reference}"))?;
        let cd = rec.config_digest;
        let desired_canon: Vec<String> = desired
            .iter()
            .filter_map(|t| image::Reference::parse(t).ok().map(|x| x.canonical()))
            .collect();
        let current: Vec<String> = image::list_summaries(&store)
            .map_err(|e| anyhow!("{e}"))?
            .into_iter()
            .filter(|s| s.config_digest == cd)
            .map(|s| s.reference)
            .collect();
        let add: Vec<&String> = desired_canon
            .iter()
            .filter(|t| !current.contains(t))
            .collect();
        let remove: Vec<&String> = current
            .iter()
            .filter(|c| !desired_canon.contains(c))
            .collect();
        for t in &add {
            image::tag_image(&store, &reference, t).map_err(|e| anyhow!("dn7 tag: {e}"))?;
        }
        for c in &remove {
            image::remove_image(&store, c).map_err(|e| anyhow!("dn7 untag: {e}"))?;
        }
        Ok(json!({ "added": add.len(), "removed": remove.len() }))
    })
    .await
}

/// `backup_container` (detached): snapshot a container — write the recreate-body
/// sidecar + commit its overlay to a temp image, save that as a gzipped OCI tar
/// under `<backups>/<name>/<ts>.tar.gz`. Mirrors bollard's start_backup_container.
#[cfg(target_os = "linux")]
fn op_backup_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .map(str::to_string)
        .unwrap_or_else(|| r.chars().take(12).collect());
    if !safe_dir_component(&name) {
        return Err(docker_err(DockerError::BadName));
    }
    let op_id = new_op_id();
    op_create(&op_id, "backup", &name);
    let op_id_t = op_id.clone();
    let target = name.clone();
    tokio::spawn(async move {
        let res = tokio::task::spawn_blocking(move || dn7_backup(&r, &name)).await;
        match res {
            Ok(Ok(file)) => op_finish(&op_id_t, "done", "", &file),
            Ok(Err(e)) => op_finish(&op_id_t, "error", &e.to_string(), ""),
            Err(e) => op_finish(&op_id_t, "error", &format!("backup task: {e}"), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

#[cfg(target_os = "linux")]
fn dn7_backup(reference: &str, name: &str) -> Result<String> {
    use dn7_container::{container, image};
    let id = resolve_dn7_id(reference)?;
    let ts = now_stamp();
    let dir = backups_root().join(name);
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("无法创建备份目录：{e}"))?;

    // Recreate-body sidecar (the stored create spec).
    let s = DnState::load(&id).map_err(|e| anyhow!("dn7 backup: {e}"))?;
    let body = s.meta.create_spec.clone().unwrap_or_else(|| json!({}));
    let json_path = dir.join(format!("{ts}.json"));
    std::fs::write(
        &json_path,
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
    .map_err(|e| anyhow!("无法写入配置快照：{e}"))?;

    // Commit overlay → temp image → OCI tar → gzip.
    let store = image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
    let tmp_ref = format!("dn7-backup:{name}-{ts}");
    let bundle = container::bundle_dir(&id);
    image::commit::commit(&store, &bundle, &tmp_ref).map_err(|e| anyhow!("dn7 commit: {e}"))?;
    let tmp_tar = dir.join(format!("{ts}.tar"));
    let tar_gz = dir.join(format!("{ts}.tar.gz"));
    let result = (|| -> Result<()> {
        image::archive::save(&store, &tmp_ref, &tmp_tar).map_err(|e| anyhow!("dn7 save: {e}"))?;
        gzip_file(&tmp_tar, &tar_gz)
    })();
    let _ = std::fs::remove_file(&tmp_tar);
    let _ = image::remove_image(&store, &tmp_ref); // the tar is self-contained
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tar_gz);
        let _ = std::fs::remove_file(&json_path);
        return Err(e);
    }
    Ok(format!("{ts}.tar.gz"))
}

/// `restore_backup` (detached): load the saved image and recreate the container
/// from its sidecar config (replacing any current one with the name). Mirrors
/// bollard's start_restore_backup.
#[cfg(target_os = "linux")]
fn op_restore_backup(req: &Req, is_super: bool) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .ok_or_else(|| docker_err(DockerError::BadName))?
        .to_string();
    let file = req
        .backup
        .as_deref()
        .map(str::trim)
        .filter(|s| valid_backup_name(s))
        .ok_or_else(|| docker_err(DockerError::BadBackup))?
        .to_string();
    let op_id = new_op_id();
    op_create(&op_id, "restore", &name);
    let op_id_t = op_id.clone();
    let target = name.clone();
    tokio::spawn(async move {
        let done = name.clone();
        let res = tokio::task::spawn_blocking(move || dn7_restore(&name, &file, is_super)).await;
        match res {
            Ok(Ok(())) => op_finish(&op_id_t, "done", "", &done),
            Ok(Err(e)) => op_finish(&op_id_t, "error", &e.to_string(), ""),
            Err(e) => op_finish(&op_id_t, "error", &format!("restore task: {e}"), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

#[cfg(target_os = "linux")]
fn dn7_restore(name: &str, file: &str, is_super: bool) -> Result<()> {
    use dn7_container::{container, image};
    let dir = backups_root().join(name);
    let tar_gz = dir.join(file);
    if !tar_gz.exists() {
        return Err(docker_err(DockerError::BackupMissing));
    }
    // Gunzip → temp tar → load into the store under a fresh ref.
    let tmp_tar = dir.join(format!("{file}.restore.tar"));
    gunzip_file(&tar_gz, &tmp_tar)?;
    let store = image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
    let restore_ref = format!("dn7-backup:{name}-{}", now_stamp());
    let loaded =
        image::archive::load(&store, &tmp_tar, &restore_ref).map_err(|e| anyhow!("dn7 load: {e}"));
    let _ = std::fs::remove_file(&tmp_tar);
    loaded?;

    // Recreate from the sidecar config, pointed at the loaded image.
    let json_path = dir.join(file.replace(".tar.gz", ".json"));
    let mut body: Value = std::fs::read(&json_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({}));
    let obj = body
        .as_object_mut()
        .ok_or_else(|| docker_err(DockerError::BackupBadConfig))?;
    obj.insert("image".to_string(), json!(restore_ref));
    obj.insert("name".to_string(), json!(name));
    obj.insert("replace".to_string(), json!(name));
    obj.insert("start".to_string(), json!(true));
    let restore_req: Req =
        serde_json::from_value(body).map_err(|_| docker_err(DockerError::BackupBadConfig))?;
    // Same host-escape gate as create — a snapshot saved by a super must not
    // materialize privileged/host-net for a non-super restorer.
    enforce_create_policy(&restore_req, is_super)?;
    let plan = build_dn7_create(&restore_req)?;
    if let Some(old) = &plan.replace {
        let _ = container::delete(old, true);
    }
    let id = container::create_from_image(&plan.spec, plan.meta)
        .map_err(|e| anyhow!("dn7 create: {e}"))?;
    if plan.start {
        container::start(&id).map_err(|e| anyhow!("dn7 start: {e}"))?;
    }
    Ok(())
}

/// gzip `src` → `dst`.
#[cfg(target_os = "linux")]
fn gzip_file(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let mut input = std::fs::File::open(src).map_err(|e| anyhow!("打开归档失败：{e}"))?;
    let out = std::fs::File::create(dst).map_err(|e| anyhow!("创建备份失败：{e}"))?;
    let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    std::io::copy(&mut input, &mut enc).map_err(|e| anyhow!("压缩备份失败：{e}"))?;
    enc.finish().map_err(|e| anyhow!("压缩备份失败：{e}"))?;
    Ok(())
}

/// gunzip `src` → `dst`.
#[cfg(target_os = "linux")]
fn gunzip_file(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    let input = std::fs::File::open(src).map_err(|e| anyhow!("打开备份失败：{e}"))?;
    let mut dec = flate2::read::GzDecoder::new(input);
    let mut out = std::fs::File::create(dst).map_err(|e| anyhow!("解压备份失败：{e}"))?;
    std::io::copy(&mut dec, &mut out).map_err(|e| anyhow!("解压备份失败：{e}"))?;
    Ok(())
}

/// Resolve a panel-supplied ref (full id/name, or a 12-char short id) to the full
/// dn7 container id — mirrors Docker's id-prefix resolution.
#[cfg(target_os = "linux")]
fn resolve_dn7_id(r: &str) -> Result<String> {
    if DnState::exists(r) {
        return Ok(r.to_string());
    }
    let states = dn7_container::container::list().map_err(|e| anyhow!("dn7 list: {e}"))?;
    states
        .into_iter()
        .find(|s| s.id.starts_with(r))
        .map(|s| s.id)
        .ok_or_else(|| anyhow!("no such container: {r}"))
}

/// Keep the panel's id form (it passes a short id) when it's a prefix of the
/// resolved full id; otherwise report the full id.
#[cfg(target_os = "linux")]
fn short_or(requested: &str, full: &str) -> String {
    if full.starts_with(requested) {
        requested.to_string()
    } else {
        full.to_string()
    }
}

/// Map a dn7 status to the docker-style state string the UI expects.
#[cfg(target_os = "linux")]
fn dn7_state_str(status: DnStatus) -> &'static str {
    match status {
        DnStatus::Created => "created",
        DnStatus::Running => "running",
        DnStatus::Stopped => "exited",
    }
}

/// The live state string the UI's status chip consumes. A frozen (`pause`d)
/// container is Running at the pid/cgroup level, so its `status` is `Running`;
/// `meta.paused` overlays that with the docker-parity `paused` state — otherwise
/// a paused container would keep showing "running" and the pause/resume controls
/// would desync.
#[cfg(target_os = "linux")]
fn dn7_live_state(s: &DnState) -> &'static str {
    if s.meta.paused && matches!(s.status, DnStatus::Running) {
        "paused"
    } else {
        dn7_state_str(s.status)
    }
}

/// A human status line (`Up 3 minutes` / `Up 3 minutes (Paused)` / `Created` /
/// `Exited (0)`).
#[cfg(target_os = "linux")]
fn dn7_status(s: &DnState) -> String {
    match s.status {
        DnStatus::Created => "Created".to_string(),
        DnStatus::Running => {
            let up = format!("Up {}", dur_human(unix_now().saturating_sub(s.created)));
            if s.meta.paused {
                format!("{up} (Paused)")
            } else {
                up
            }
        }
        DnStatus::Stopped => format!("Exited ({})", s.meta.exit_code),
    }
}

/// The container's IPv4(s) as `"<ip> (<network>)"` (dn7 has one NIC for now).
#[cfg(target_os = "linux")]
fn dn7_ips(net: &Option<dn7_container::net::NetState>) -> Vec<String> {
    net.as_ref()
        .and_then(|n| n.ip.map(|ip| format!("{ip} ({})", n.network)))
        .into_iter()
        .collect()
}

/// Format a dn7 `ports_spec` (`hp:cp/proto,...`) like `docker ps`
/// (`0.0.0.0:hp->cp/proto`).
#[cfg(target_os = "linux")]
fn fmt_dn7_ports(spec: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for p in spec.split(',').filter(|s| !s.is_empty()) {
        let (hostpart, proto) = p.rsplit_once('/').unwrap_or((p, "tcp"));
        if let Some((hp, cp)) = hostpart.split_once(':') {
            out.push(format!("0.0.0.0:{hp}->{cp}/{proto}"));
        }
    }
    out.sort();
    out.dedup();
    out.join(", ")
}

/// A coarse duration label (`45 seconds` / `3 minutes` / `2 hours` / `5 days`).
#[cfg(target_os = "linux")]
fn dur_human(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} seconds")
    } else if secs < 3600 {
        format!("{} minutes", secs / 60)
    } else if secs < 86_400 {
        format!("{} hours", secs / 3600)
    } else {
        format!("{} days", secs / 86_400)
    }
}

/// Seconds since the Unix epoch.
#[cfg(target_os = "linux")]
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A stable 12-char hex id derived from a name (for entities dn7 doesn't assign
/// random ids to, e.g. networks).
#[cfg(target_os = "linux")]
fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Total RAM in bytes from `/proc/meminfo` (0 if unreadable).
#[cfg(target_os = "linux")]
fn mem_total_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("MemTotal:")
                    .and_then(|v| v.trim().trim_end_matches(" kB").trim().parse::<u64>().ok())
            })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn info_reports_dn7_runtime_in_docker_info_shape() {
        let v = info().unwrap();
        assert_eq!(v["runtime"], "dn7");
        assert_eq!(v["daemon_running"], true);
        assert_eq!(v["docker_present"], false);
        assert!(v["server_version"]
            .as_str()
            .unwrap()
            .contains("dn7-container"));
        assert!(v["host_cpus"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn list_networks_reports_dn7_bridge_in_shape() {
        let v = list_networks().unwrap();
        let nets = v["networks"].as_array().unwrap();
        assert!(!nets.is_empty());
        assert_eq!(nets[0]["driver"], "bridge");
        assert_eq!(nets[0]["scope"], "local");
        assert!(nets[0]["subnet"].as_str().unwrap().contains("172.18"));
        assert_eq!(nets[0]["id"].as_str().unwrap().len(), 12);
    }

    fn req_from(v: Value) -> Req {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn build_dn7_create_translates_a_basic_request() {
        let req = req_from(json!({
            "op": "create_container", "image": "alpine", "name": "web",
            "ports": [{"host": 8080, "container": 80}],
            "env": ["FOO=bar"], "memory": "64m", "cpus": "0.5", "start": true,
            "restart": "always"
        }));
        let plan = build_dn7_create(&req).unwrap();
        assert_eq!(plan.spec.id, "web");
        assert_eq!(plan.spec.reference, "alpine");
        assert_eq!(plan.spec.ports, "8080:80/tcp");
        assert_eq!(plan.spec.env_extra, vec!["FOO=bar".to_string()]);
        assert_eq!(plan.spec.cpu_quota, Some((50_000, 100_000)));
        assert!(plan.spec.mem_limit.is_some());
        assert_eq!(plan.target, "web");
        assert!(plan.start);
        assert_eq!(plan.meta.image.as_deref(), Some("alpine"));
        assert_eq!(plan.meta.restart_policy.as_deref(), Some("always"));
        assert!(plan.meta.create_spec.is_some());
    }

    #[test]
    fn build_dn7_create_rejects_privileged() {
        let req =
            req_from(json!({"op": "create_container", "image": "alpine", "privileged": true}));
        assert!(build_dn7_create(&req).is_err());
    }

    #[test]
    fn build_dn7_create_threads_network_and_static_ipv4() {
        // A user-selected network + static IP now flow into the spec (the primary
        // network becomes the mode; the IP becomes `spec.static_ip`), instead of
        // being rejected.
        let req = req_from(json!({
            "op": "create_container", "image": "alpine",
            "networks": [{"network": "mynet", "ipv4": "172.20.0.9"}]
        }));
        let plan = build_dn7_create(&req).unwrap();
        assert_eq!(plan.spec.net_mode, "mynet");
        assert_eq!(plan.spec.static_ip.as_deref(), Some("172.20.0.9"));
        assert!(plan.extra_nets.is_empty());
    }

    #[test]
    fn build_dn7_create_extra_networks_become_attachments() {
        let req = req_from(json!({
            "op": "create_container", "image": "alpine",
            "networks": [{"network": "dn7"}, {"network": "second"}]
        }));
        let plan = build_dn7_create(&req).unwrap();
        assert_eq!(plan.spec.net_mode, "bridge"); // "dn7" primary → built-in bridge
        assert_eq!(plan.extra_nets.len(), 1);
        assert_eq!(plan.extra_nets[0].network, "second");
    }

    #[test]
    fn build_dn7_create_rejects_uppercase_name() {
        let req = req_from(json!({"op": "create_container", "image": "alpine", "name": "WebApp"}));
        assert!(build_dn7_create(&req).is_err());
    }

    #[test]
    fn dn7_id_validation() {
        assert!(is_valid_dn7_id("web"));
        assert!(is_valid_dn7_id("my-app_1.2"));
        assert!(!is_valid_dn7_id("WebApp"));
        assert!(!is_valid_dn7_id("-leading"));
        assert!(!is_valid_dn7_id(""));
        assert!(gen_container_id()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-')));
    }

    #[test]
    fn container_row_has_the_panel_shape() {
        let mut s = DnState::new(
            "webapp",
            1234,
            std::path::Path::new("/b"),
            "dn7/webapp",
            1_609_459_200,
        );
        s.status = DnStatus::Running;
        s.meta.image = Some("alpine:latest".into());
        s.meta.name = Some("webapp".into());
        s.meta.ports_spec = "8080:80/tcp".into();
        let row = container_row(s);
        assert_eq!(row["id"], "webapp");
        assert_eq!(row["name"], "webapp");
        assert_eq!(row["image"], "alpine:latest");
        assert_eq!(row["state"], "running");
        assert_eq!(row["ports"], "0.0.0.0:8080->80/tcp");
        assert_eq!(row["has_shell"], true);
        assert_eq!(row["managed"], false);
        assert!(row["status"].as_str().unwrap().starts_with("Up"));
        assert!(row["ips"].is_array());
    }

    #[test]
    fn parse_ports_spec_extracts_host_port_and_proto() {
        assert_eq!(
            parse_ports_spec("8080:80/tcp,53:53/udp"),
            vec![(8080, "tcp".to_string()), (53, "udp".to_string())]
        );
        // Missing proto defaults to tcp; empty spec yields nothing.
        assert_eq!(parse_ports_spec("9000:90"), vec![(9000, "tcp".to_string())]);
        assert_eq!(parse_ports_spec(""), Vec::<(i64, String)>::new());
    }

    #[test]
    fn check_dn7_port_conflicts_rejects_duplicate_form_ports() {
        // Two mappings of the same host port + proto in one request is a conflict,
        // caught before any container-list scan (pure, hermetic).
        let req = req_from(json!({
            "op": "create_container", "image": "alpine",
            "ports": [{"host": 8080, "container": 80}, {"host": 8080, "container": 81}]
        }));
        assert!(check_dn7_port_conflicts(&req).is_err());

        // No ports → always OK.
        let req0 = req_from(json!({"op": "create_container", "image": "alpine"}));
        assert!(check_dn7_port_conflicts(&req0).is_ok());
    }

    #[test]
    fn port_and_state_formatting() {
        assert_eq!(
            fmt_dn7_ports("8080:80/tcp,53:53/udp"),
            "0.0.0.0:53->53/udp, 0.0.0.0:8080->80/tcp"
        );
        assert_eq!(fmt_dn7_ports(""), "");
        assert_eq!(dn7_state_str(DnStatus::Stopped), "exited");
        assert_eq!(dn7_state_str(DnStatus::Created), "created");
        assert_eq!(dn7_state_str(DnStatus::Running), "running");
        assert_eq!(dur_human(45), "45 seconds");
        assert_eq!(dur_human(120), "2 minutes");
    }
}
