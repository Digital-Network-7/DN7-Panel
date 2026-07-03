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
        "prune_images" => Some(op_prune_images().await),
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
    tokio::task::spawn_blocking(f).await.map_err(dn7_err)?
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

    let store = dn7_container::image::Store::open().map_err(dn7_err)?;
    let summaries = dn7_container::image::list_summaries(&store).map_err(dn7_err)?;

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
    let vols = dn7_container::image::volume::list().map_err(dn7_err)?;
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
/// `prune_images`: reclaim orphaned image blobs + rootfs-caches (docker image prune).
#[cfg(target_os = "linux")]
async fn op_prune_images() -> Result<Value> {
    run_blocking(|| {
        let store = dn7_container::image::Store::open().map_err(dn7_err)?;
        let (pruned, reclaimed) = dn7_container::image::prune(&store).map_err(dn7_err)?;
        Ok(json!({ "pruned": pruned, "reclaimed": reclaimed }))
    })
    .await
}

async fn op_remove_image(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let store = dn7_container::image::Store::open().map_err(dn7_err)?;
        // Refuse to delete an image still referenced by any dn7 container, so its
        // overlay lower layer can't be pulled out from under a running/stopped one.
        if let Some(users) = dn7_image_users(&r) {
            return Err(anyhow!("ERR_CODE:docker.image_in_use\u{1f}{users}"));
        }
        dn7_container::image::remove_image(&store, &r).map_err(dn7_err)?;
        Ok(json!({ "removed": r }))
    })
    .await
}

/// Whether the container's rootfs has a usable shell — so the web-terminal button
/// is only offered when a session will actually open (a distroless/scratch/static
/// image has none, and clicking would just fail).
#[cfg(target_os = "linux")]
fn dn7_has_shell(bundle: &std::path::Path) -> bool {
    let rootfs = bundle.join("rootfs");
    [
        "bin/sh",
        "bin/bash",
        "bin/ash",
        "usr/bin/sh",
        "usr/bin/bash",
        "bin/busybox",
    ]
    .iter()
    .any(|p| rootfs.join(p).exists())
}

/// The image's default `STOPSIGNAL` (best-effort local lookup); `None` if the
/// image isn't present locally or declares none.
#[cfg(target_os = "linux")]
fn dn7_image_stop_signal(image: &str) -> Option<String> {
    use dn7_container::image::{ImageRecord, Reference, Store};
    let store = Store::open().ok()?;
    let r = Reference::parse(image).ok()?;
    let cfg = ImageRecord::load(&store, &r.store_key())
        .ok()?
        .config(&store)
        .ok()?;
    let s = cfg.config.stop_signal.trim();
    (!s.is_empty()).then(|| s.to_string())
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
        let store = dn7_container::image::Store::open().map_err(dn7_err)?;
        for t in &tags {
            dn7_container::image::tag_image(&store, &src, t).map_err(dn7_err)?;
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
    // Optional host path (docker `local`-driver bind). Vet it against the same
    // absolute-path + host-bind deny-list as a `-v` bind before backing the volume.
    let path = match req.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => {
            validate_path(p)?;
            validate_bind_source(p)?;
            Some(p.to_string())
        }
        None => None,
    };
    run_blocking(move || {
        let mp = path.as_deref().map(std::path::Path::new);
        dn7_container::image::volume::create_with_mount(&name, mp).map_err(dn7_err)?;
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
        dn7_container::image::volume::remove(&name).map_err(dn7_err)?;
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
    let primary_mac = rows
        .first()
        .and_then(|a| a.mac.clone())
        .filter(|s| !s.trim().is_empty());
    let extra_nets: Vec<NetAttach> = rows.iter().skip(1).cloned().collect();
    let (net_mode, net_name_requested) = match primary_name.as_deref() {
        None | Some("bridge") | Some("dn7") => ("bridge".to_string(), None),
        Some("host") => ("host".to_string(), None),
        Some("none") => ("none".to_string(), None),
        Some(other) => (other.to_string(), Some(other.to_string())),
    };

    // Docker model: the id is a random, immutable 64-hex — NEVER the name. The
    // (validated, possibly mixed-case) name is a separate mutable label kept in
    // meta.name. Decoupling them is what lets rename touch only the name, lets
    // ids stay stable, and lets names use Docker's charset (incl. uppercase). An
    // unnamed container gets a friendly random name (Docker's adjective_surname),
    // not an opaque token.
    let id = gen_container_id();
    let name = cspec.name.clone().or_else(|| Some(gen_container_name()));

    let target = if display_name.is_empty() {
        cspec.image.clone()
    } else {
        display_name
    };

    // dn7's DNAT is IPv4-only, so an explicit IPv6 publish can't be honored —
    // reject it clearly rather than silently dropping it (Docker parity).
    if req.ports.iter().flatten().any(|p| p.ipv6.unwrap_or(false)) {
        return Err(anyhow!("ERR_CODE:docker.ipv6_publish_unsupported"));
    }
    // Published ports → dn7 `-p` string, honoring an optional host-IP so a
    // `127.0.0.1:8080:80` publish is scoped to loopback (not all interfaces).
    let ports_spec = req
        .ports
        .iter()
        .flatten()
        .map(|p| {
            let proto = p.proto.as_deref().unwrap_or("tcp");
            match p
                .host_ip
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(ip) => format!("{ip}:{}:{}/{proto}", p.host, p.container),
                None => format!("{}:{}/{proto}", p.host, p.container),
            }
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
        let vm = dn7_container::image::volume::resolve(&s).map_err(dn7_err)?;
        // Docker auto-creates a missing host bind source (as a directory) so
        // `-v ./data:/data` just works instead of failing ENOENT at mount time.
        // (Named volumes are already materialized by resolve; the deny-list has
        // vetted this host path.) Runs in the root serving loop, so the mkdir works.
        if !vm.source.exists() {
            let _ = std::fs::create_dir_all(&vm.source);
        }
        volumes.push(vm);
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
    // Docker defaults an unset hostname to the container's short (12-hex) id.
    let hostname = trimmed(&req.hostname).or_else(|| Some(id.chars().take(12).collect()));

    let mem_limit = trimmed(&req.memory).map(|m| mem_to_bytes(&m) as i64);
    let cpus_val = trimmed(&req.cpus).and_then(|c| c.parse::<f64>().ok());
    let cpu_quota = cpus_val.map(|v| ((v * 100_000.0) as i64, 100_000u64));
    let nano_cpus = cpus_val.map(|v| (v * 1_000_000_000.0) as i64);
    let cpu_shares_i = req.cpu_shares.filter(|v| *v > 0);

    let restart_str = trimmed(&req.restart).unwrap_or_else(|| "unless-stopped".to_string());
    let pids_limit = req.pids_limit.filter(|v| *v > 0);
    // Stop signal: explicit --stop-signal, else the image's STOPSIGNAL (best-effort
    // local lookup), else None (SIGTERM). Stop timeout: --stop-timeout, else None (10s).
    let stop_signal = trimmed(&req.stop_signal).or_else(|| dn7_image_stop_signal(&cspec.image));
    let stop_timeout = req.stop_timeout.filter(|v| *v > 0);
    let auto_remove = req.auto_remove.unwrap_or(false);

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
        pids_limit,
        tty: req.tty.unwrap_or(false),
        static_ip: primary_ip.clone(),
        static_mac: primary_mac.clone(),
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
        stop_signal,
        stop_timeout,
        auto_remove,
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
    for s in dn7_container::container::list().map_err(dn7_err)? {
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
                    "ERR_CODE:docker.port_in_use_container\u{1f}{}\u{1f}{}\u{1f}{}",
                    p.host,
                    proto.to_uppercase(),
                    owner
                ));
            }
            Some(_) => {} // held by the container we're replacing — reuse is fine.
            None => {
                if port_busy(p.host, &proto) {
                    return Err(anyhow!(
                        "ERR_CODE:docker.port_in_use_process\u{1f}{}\u{1f}{}",
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
            // Serialize concurrent same-name creates + enforce unique names
            // (Docker returns 409 Conflict). The name-scoped lock is held across
            // the whole delete→check→create so a replace can reuse its own name.
            let _name_guard = match meta.name.as_deref() {
                Some(nm) => Some(DnState::lock(&format!("namelock-{nm}")).map_err(dn7_err)?),
                None => None,
            };
            // Edit/upgrade: confirm the new image is present locally BEFORE
            // removing the old container (else a bad tag leaves nothing).
            if let Some(old) = &replace {
                let store = dn7_container::image::Store::open().map_err(dn7_err)?;
                let r = dn7_container::image::Reference::parse(&image).map_err(dn7_err)?;
                dn7_container::image::ImageRecord::load(&store, &r.store_key())
                    .map_err(|_| anyhow!("ERR_CODE:docker.edit_image_missing"))?;
                // `old` is a user ref (usually the name); ids are now random hex,
                // so resolve it to the real id before deleting — otherwise the old
                // container leaks and its name blocks the replacement.
                if let Ok(old_id) = resolve_dn7_id(old) {
                    let _ = dn7_container::container::delete(&old_id, true); // best-effort
                }
            }
            // Reject a duplicate name now that any replaced container is gone.
            if let Some(nm) = meta.name.as_deref() {
                if dn7_name_in_use(nm) {
                    return Err(anyhow!("ERR_CODE:docker.name_conflict"));
                }
            }
            let id = dn7_container::container::create_from_image(&spec, meta)
                .map_err(|e| anyhow!("dn7 create: {e}"))?;
            if start {
                dn7_container::container::start(&id).map_err(dn7_err)?;
                // Attach any additional requested networks (the primary was wired
                // at create; these are hot-plugged now the container is running).
                for a in &extra_nets {
                    let ip = a.ipv4.as_deref().filter(|s| !s.trim().is_empty());
                    dn7_container::container::net_connect(&id, &a.network, ip).map_err(dn7_err)?;
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

/// A fresh, random, immutable container id (see the callers for the Docker model).
#[cfg(target_os = "linux")]
/// A fresh container id: Docker-style 256-bit random, lowercase hex (64 chars),
/// independent of the name. The short form (first 12) is what the UI shows and
/// what `docker`-parity clients expect. Immutable for the container's lifetime —
/// rename changes only the display name, never this.
fn gen_container_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    // Fallback (no /dev/urandom): 128 bits of nanos ⊕ pid, still collision-safe.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    format!(
        "{nanos:032x}{:032x}",
        pid.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    )
}

/// A friendly random `adjective_surname` name (Docker's names-generator style)
/// for an unnamed container, retried until free so it doesn't collide with an
/// existing name; falls back to appending a short hex if the space is exhausted.
#[cfg(target_os = "linux")]
fn gen_container_name() -> String {
    const ADJ: &[&str] = &[
        "admiring", "bold", "brave", "calm", "clever", "cool", "dreamy", "eager", "elegant",
        "fervent", "gentle", "gifted", "happy", "jolly", "keen", "kind", "lucid", "mystic",
        "nifty", "peaceful", "quirky", "serene", "sharp", "silly", "stoic", "tender", "upbeat",
        "vibrant", "wizardly", "zen",
    ];
    const SUR: &[&str] = &[
        "babbage", "bardeen", "bohr", "curie", "darwin", "dijkstra", "euler", "fermi", "franklin",
        "galileo", "gauss", "goldberg", "hamilton", "hawking", "hopper", "kepler", "knuth",
        "liskov", "lovelace", "mendel", "newton", "noether", "pasteur", "perlman", "planck",
        "ritchie", "shannon", "tesla", "torvalds", "turing",
    ];
    let pick = || -> String {
        let mut buf = [0u8; 2];
        let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        });
        format!(
            "{}_{}",
            ADJ[buf[0] as usize % ADJ.len()],
            SUR[buf[1] as usize % SUR.len()]
        )
    };
    for _ in 0..24 {
        let n = pick();
        if !dn7_name_in_use(&n) {
            return n;
        }
    }
    format!("{}_{}", pick(), &gen_container_id()[..6])
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
                "proto": p.proto.as_deref().unwrap_or("tcp"), "ipv6": p.ipv6.unwrap_or(false),
                "host_ip": p.host_ip
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
        "memory": req.memory, "privileged": req.privileged.unwrap_or(false),
        "pids_limit": req.pids_limit, "stop_signal": req.stop_signal,
        "stop_timeout": req.stop_timeout, "auto_remove": req.auto_remove.unwrap_or(false)
    })
}

/// `list_containers`: one row per dn7 container, in the panel's list shape.
#[cfg(target_os = "linux")]
fn list_containers() -> Result<Value> {
    let states = dn7_container::container::list().map_err(dn7_err)?;
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
        "has_shell": running && dn7_has_shell(&s.bundle),
        "managed": managed,
    })
}

/// `inspect_container`: the panel's inspect shape from a dn7 `State`.
#[cfg(target_os = "linux")]
async fn op_inspect_container(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s = dn7_container::container::state(&id).map_err(dn7_err)?;
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
            "has_shell": running && dn7_has_shell(&s.bundle),
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
        let pid = DnState::load(&id).map_err(dn7_err)?.pid;
        let t0 = std::time::Instant::now();
        let s1 = dn7_container::container::stats(&id).map_err(dn7_err)?;
        std::thread::sleep(std::time::Duration::from_millis(100));
        let s2 = dn7_container::container::stats(&id).map_err(dn7_err)?;
        // CPU% over the ACTUAL measured interval (not an assumed 100ms), like docker.
        let elapsed_us = t0.elapsed().as_micros().max(1) as f64;
        let cpu_delta = s2.cpu_usage_usec.saturating_sub(s1.cpu_usage_usec) as f64;
        let cpu_pct = cpu_delta / elapsed_us * 100.0;
        let online = std::thread::available_parallelism()
            .map(|n| n.get() as u64)
            .unwrap_or(1);
        // Network: sum non-lo ifaces from /proc/<pid>/net/dev (the container's netns).
        let (net_rx, net_tx) = read_proc_net_dev(pid);
        // Memory like `docker stats`: current minus reclaimable page cache; an
        // unlimited container reports host RAM as its limit (so the % is meaningful).
        let mem_used = s2.memory_current.saturating_sub(s2.inactive_file);
        let mem_limit = s2.memory_max.unwrap_or_else(mem_total_bytes);
        Ok(json!({
            "cpu_pct": (cpu_pct * 100.0).round() / 100.0,
            "cpu_online": online,
            "mem_used": mem_used,
            "mem_limit": mem_limit,
            "net_rx": net_rx, "net_tx": net_tx,
            "blk_read": s2.io_rbytes, "blk_write": s2.io_wbytes,
        }))
    })
    .await
}

/// Sum non-loopback RX/TX bytes from `/proc/<pid>/net/dev`. That file reflects
/// the network namespace of `pid`, so the container's init pid gives the
/// container's own traffic totals (`docker stats` NET I/O).
#[cfg(target_os = "linux")]
fn read_proc_net_dev(pid: i32) -> (u64, u64) {
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Ok(txt) = std::fs::read_to_string(format!("/proc/{pid}/net/dev")) {
        for line in txt.lines() {
            let Some((iface, rest)) = line.split_once(':') else {
                continue; // header rows carry no data colon
            };
            if iface.trim() == "lo" {
                continue;
            }
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() >= 9 {
                rx += f[0].parse::<u64>().unwrap_or(0); // receive bytes
                tx += f[8].parse::<u64>().unwrap_or(0); // transmit bytes
            }
        }
    }
    (rx, tx)
}

/// `get_container_config`: the stored recreate body (for the edit/upgrade form).
#[cfg(target_os = "linux")]
async fn op_get_container_config(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    run_blocking(move || {
        let id = resolve_dn7_id(&r)?;
        let s = DnState::load(&id).map_err(dn7_err)?;
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
    let req_stop_timeout = req.stop_timeout;
    run_blocking(move || {
        use dn7_container::container as ctr;
        let id = resolve_dn7_id(&r)?;
        let verb = match action.as_str() {
            "start" => {
                ctr::start_or_rerun(&id).map_err(dn7_err)?;
                "started"
            }
            "stop" => {
                // docker stop -t / the container's stored StopTimeout, else 10s.
                let secs = req_stop_timeout
                    .or_else(|| DnState::load(&id).ok().and_then(|s| s.meta.stop_timeout))
                    .filter(|v| *v > 0)
                    .unwrap_or(10) as u64;
                ctr::stop(&id, std::time::Duration::from_secs(secs)).map_err(dn7_err)?;
                "stopped"
            }
            "restart" => {
                ctr::restart(&id).map_err(dn7_err)?;
                "restarted"
            }
            "pause" => {
                ctr::pause(&id).map_err(dn7_err)?;
                "paused"
            }
            "unpause" => {
                ctr::unpause(&id).map_err(dn7_err)?;
                "resumed"
            }
            "kill" => {
                ctr::kill_now(&id).map_err(dn7_err)?;
                "killed"
            }
            "remove" => {
                ctr::delete(&id, true).map_err(dn7_err)?;
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
        let bytes = dn7_container::container::logs(&id).map_err(dn7_err)?;
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
        let _guard = DnState::lock(&format!("namelock-{name}")).map_err(dn7_err)?;
        let id = resolve_dn7_id(&r)?;
        let mut s = DnState::load(&id).map_err(dn7_err)?;
        // Renaming to the same name is a no-op; otherwise the target must be free
        // (Docker rejects a rename onto an existing name).
        if s.meta.name.as_deref() != Some(name.as_str()) && dn7_name_in_use(&name) {
            return Err(anyhow!("ERR_CODE:docker.name_conflict"));
        }
        s.meta.name = Some(name.clone());
        s.save().map_err(dn7_err)?;
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
        let store = dn7_container::image::Store::open().map_err(dn7_err)?;
        let bundle = dn7_container::container::bundle_dir(&id);
        dn7_container::image::commit::commit(&store, &bundle, &new_ref).map_err(dn7_err)?;
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
        for s in dn7_container::container::list().map_err(dn7_err)? {
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
        let s = DnState::load(&id).map_err(dn7_err)?;
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
/// Map a dn7 failure (an op-layer guard, or a fixed string forwarded from the
/// `registry`/`container` crate) to a stable `ERR_CODE` the web console localizes
/// via `err.<code>`. The crate messages are constants we own, so substring
/// matching stays stable; anything unmatched falls back to a generic localized
/// "operation failed" rather than leaking raw English into a translated console.
#[cfg(target_os = "linux")]
fn dn7_err_code(msg: &str) -> &'static str {
    let has = |n: &str| msg.contains(n);
    if has("is in state") && has("cannot") {
        "docker.bad_container_state"
    } else if has("overlaps existing") {
        "docker.subnet_overlap"
    } else if has("invalid subnet CIDR") {
        "docker.bad_subnet_cidr"
    } else if has("invalid gateway IP") {
        "docker.bad_gateway_ip"
    } else if has("is not inside subnet") {
        "docker.gateway_outside_subnet"
    } else if has("prefix must be between") {
        "docker.subnet_prefix_range"
    } else if has("is reserved") {
        "docker.net_name_reserved"
    } else if has("invalid network name") {
        "docker.bad_net_name"
    } else if has("no usable host") {
        "docker.subnet_no_host"
    } else if has("no free private subnet") {
        "docker.subnet_pool_exhausted"
    } else if has("container") && has("already exists") {
        "docker.name_conflict"
    } else if has("already exists") {
        "docker.net_exists"
    } else if has("no such network") {
        "docker.no_such_network"
    } else if has("still has") && has("attached") {
        "docker.net_still_attached"
    } else if has("can't be removed") || has("can't be renamed") {
        "docker.net_builtin_immutable"
    } else if has("already in use on network") {
        "docker.ip_in_use"
    } else if has("invalid ipv4") {
        "docker.bad_ipv4"
    } else if has("is not connected to network") {
        "docker.not_connected"
    } else if has("is already connected to network") {
        "docker.already_connected"
    } else if has("is exhausted") {
        "docker.net_exhausted"
    } else if has("not on a bridge network") {
        "docker.not_bridge_net"
    } else if has("primary network") {
        "docker.cant_disconnect_primary"
    } else if has("has no managed network") {
        "docker.no_managed_network"
    } else if has("no such container") || has("not found") {
        "docker.no_such_container"
    } else {
        "docker.op_failed"
    }
}

/// Wrap a crate network error as a localized `ERR_CODE:` anyhow error.
#[cfg(target_os = "linux")]
fn dn7_err(e: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", dn7_err_code(&e.to_string()))
}

async fn op_create_network(req: &Req) -> Result<Value> {
    let name = trimmed(&req.name).ok_or_else(|| anyhow!("ERR_CODE:docker.need_network_name"))?;
    // The subnet is optional (the modal labels it so): auto-assign a free private
    // range when it's omitted, matching Docker instead of hard-failing.
    let subnet = trimmed(&req.subnet);
    let gateway = req.gateway.clone().unwrap_or_default();
    run_blocking(move || {
        use dn7_container::net::registry;
        let (net, gw) = match subnet {
            Some(s) => registry::parse_subnet(&s, &gateway).map_err(dn7_err)?,
            None => (registry::allocate_free_subnet().map_err(dn7_err)?, None),
        };
        let cfg = registry::create(&name, net, gw).map_err(dn7_err)?;
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
        dn7_container::net::registry::remove(&name).map_err(dn7_err)?;
        Ok(json!({ "removed": name }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_rename_network(req: &Req) -> Result<Value> {
    let old = need_ref(req)?;
    let new = trimmed(&req.new_name).ok_or_else(|| anyhow!("ERR_CODE:docker.need_network_name"))?;
    run_blocking(move || {
        dn7_container::net::registry::rename(&old, &new).map_err(dn7_err)?;
        Ok(json!({ "renamed": new }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_set_network_ip(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("ERR_CODE:docker.need_network"))?;
    let ipv4 = trimmed(&req.ipv4).ok_or_else(|| anyhow!("ERR_CODE:docker.need_ipv4"))?;
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        dn7_container::container::net_set_ip(&id, &network, &ipv4).map_err(dn7_err)?;
        Ok(json!({ "ok": true, "ip": ipv4 }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_connect_network(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("ERR_CODE:docker.need_network"))?;
    let ipv4 = trimmed(&req.ipv4);
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        let (ip, ifname) = dn7_container::container::net_connect(&id, &network, ipv4.as_deref())
            .map_err(dn7_err)?;
        Ok(json!({ "connected": network, "ip": ip, "ifname": ifname }))
    })
    .await
}
#[cfg(target_os = "linux")]
async fn op_disconnect_network(req: &Req) -> Result<Value> {
    let cref = need_ref(req)?;
    let network = trimmed(&req.network).ok_or_else(|| anyhow!("ERR_CODE:docker.need_network"))?;
    run_blocking(move || {
        let id = resolve_dn7_id(&cref)?;
        dn7_container::container::net_disconnect(&id, &network).map_err(dn7_err)?;
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
        let store = image::Store::open().map_err(dn7_err)?;
        let r = image::Reference::parse(&reference).map_err(dn7_err)?;
        let rec = image::ImageRecord::load(&store, &r.store_key())
            .map_err(|_| anyhow!("no such image: {reference}"))?;
        let cd = rec.config_digest;
        let desired_canon: Vec<String> = desired
            .iter()
            .filter_map(|t| image::Reference::parse(t).ok().map(|x| x.canonical()))
            .collect();
        let current: Vec<String> = image::list_summaries(&store)
            .map_err(dn7_err)?
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
            image::tag_image(&store, &reference, t).map_err(dn7_err)?;
        }
        for c in &remove {
            image::remove_image(&store, c).map_err(dn7_err)?;
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
    let s = DnState::load(&id).map_err(dn7_err)?;
    let body = s.meta.create_spec.clone().unwrap_or_else(|| json!({}));
    let json_path = dir.join(format!("{ts}.json"));
    std::fs::write(
        &json_path,
        serde_json::to_vec_pretty(&body).unwrap_or_default(),
    )
    .map_err(|e| anyhow!("无法写入配置快照：{e}"))?;

    // Commit overlay → temp image → OCI tar → gzip.
    let store = image::Store::open().map_err(dn7_err)?;
    let tmp_ref = format!("dn7-backup:{name}-{ts}");
    let bundle = container::bundle_dir(&id);
    image::commit::commit(&store, &bundle, &tmp_ref).map_err(dn7_err)?;
    let tmp_tar = dir.join(format!("{ts}.tar"));
    let tar_gz = dir.join(format!("{ts}.tar.gz"));
    let result = (|| -> Result<()> {
        image::archive::save(&store, &tmp_ref, &tmp_tar).map_err(dn7_err)?;
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
    let store = image::Store::open().map_err(dn7_err)?;
    let restore_ref = format!("dn7-backup:{name}-{}", now_stamp());
    let loaded = image::archive::load(&store, &tmp_tar, &restore_ref).map_err(dn7_err);
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
        container::start(&id).map_err(dn7_err)?;
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
/// Resolve a user-supplied container ref to its immutable id, Docker-style:
/// exact id → exact name → unambiguous id-prefix. An ambiguous prefix errors
/// instead of silently picking one.
fn resolve_dn7_id(r: &str) -> Result<String> {
    if DnState::exists(r) {
        return Ok(r.to_string()); // exact id — the state dir is keyed by id
    }
    let states = dn7_container::container::list().map_err(dn7_err)?;
    if let Some(s) = states.iter().find(|s| s.meta.name.as_deref() == Some(r)) {
        return Ok(s.id.clone()); // exact name (names are unique)
    }
    let mut prefix = states.iter().filter(|s| s.id.starts_with(r));
    match (prefix.next(), prefix.next()) {
        (Some(s), None) => Ok(s.id.clone()),
        (Some(_), Some(_)) => Err(anyhow!("ERR_CODE:docker.ambiguous_ref")),
        _ => Err(anyhow!("ERR_CODE:docker.no_such_container")),
    }
}

/// Whether a container already carries display name `name` (Docker names are
/// unique). Best-effort: a list failure reports "not in use".
fn dn7_name_in_use(name: &str) -> bool {
    dn7_container::container::list()
        .map(|v| v.iter().any(|s| s.meta.name.as_deref() == Some(name)))
        .unwrap_or(false)
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
        // `[host_ip:]host_port:container_port` — show the real bind IP (Docker
        // shows the scoped IP, not always 0.0.0.0).
        let parts: Vec<&str> = hostpart.split(':').collect();
        let (ip, hp, cp) = match parts.as_slice() {
            [hp, cp] => ("0.0.0.0", *hp, *cp),
            [ip, hp, cp] => (*ip, *hp, *cp),
            _ => continue,
        };
        out.push(format!("{ip}:{hp}->{cp}/{proto}"));
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
        assert_eq!(plan.spec.id.len(), 64); // random hex id, decoupled from the name
        assert_ne!(plan.spec.id, "web");
        assert_eq!(plan.meta.name.as_deref(), Some("web"));
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
    fn build_dn7_create_accepts_uppercase_name_with_a_hex_id() {
        // Docker allows [a-zA-Z0-9][a-zA-Z0-9_.-]; the id is random hex, not the name.
        let req = req_from(json!({"op": "create_container", "image": "alpine", "name": "WebApp"}));
        let plan = build_dn7_create(&req).expect("uppercase names are allowed");
        assert_eq!(plan.meta.name.as_deref(), Some("WebApp"));
        assert_eq!(plan.spec.id.len(), 64);
        assert_ne!(plan.spec.id, "WebApp");
        assert!(plan.spec.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn gen_container_id_is_random_lowercase_64_hex() {
        let a = gen_container_id();
        let b = gen_container_id();
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_ne!(a, b, "ids must be random");
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
        // has_shell now depends on a real rootfs probe (false for this synthetic /b).
        assert!(row["has_shell"].is_boolean());
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
