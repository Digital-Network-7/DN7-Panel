//! Volume listing + create/remove (split from docker.rs).
use super::*;

pub(crate) async fn list_volumes() -> Result<Value> {
    let dkr = dkr()?;
    let resp = dkr
        .list_volumes(None::<bollard::volume::ListVolumesOptions<String>>)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    let mut out = Vec::new();
    for v in resp.volumes.unwrap_or_default() {
        let managed = v.name.starts_with("dn7-") || v.labels.contains_key("dn7.managed");
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
    out.sort_by_key(|a| a["name"].as_str().unwrap_or("").to_string());
    Ok(json!({ "volumes": out }))
}

pub(crate) async fn create_volume_op(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| docker_err(DockerError::MissingVolumeName))?;
    validate_name(name)?;
    let mut opts = bollard::volume::CreateVolumeOptions {
        name: name.to_string(),
        driver: "local".to_string(),
        ..Default::default()
    };
    // Optional host path: back the volume with a bind mount to an absolute host
    // directory (local driver: type=none, o=bind, device=<path>). This volume is
    // a bind mount the moment it's attached by name, and a named volume hides its
    // host path from `spec_binds` — so the host-compromise deny-list MUST run HERE
    // too (same shared gate as container-create binds), or it's a full bypass.
    if let Some(dev) = req.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        validate_bind_source(dev)?;
        let mut o = HashMap::new();
        o.insert("type".to_string(), "none".to_string());
        o.insert("o".to_string(), "bind".to_string());
        o.insert("device".to_string(), dev.to_string());
        opts.driver_opts = o;
    }
    dkr()?
        .create_volume(opts)
        .await
        .map_err(|e| anyhow!(friendly_docker_err(&e)))?;
    Ok(json!({ "created": name }))
}

pub(crate) async fn remove_volume_op(req: &Req) -> Result<Value> {
    let name = need_ref(req)?;
    if name.starts_with("dn7-") {
        return Err(docker_err(DockerError::VolumeManaged));
    }
    let opts = bollard::volume::RemoveVolumeOptions { force: false };
    dkr()?.remove_volume(&name, Some(opts)).await.map_err(|e| {
        let raw = e.to_string().to_lowercase();
        if raw.contains("in use") {
            docker_err(DockerError::VolumeInUse)
        } else {
            anyhow!(friendly_docker_err(&e))
        }
    })?;
    Ok(json!({ "removed": name }))
}
