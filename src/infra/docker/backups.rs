//! Container backups + image import/export streams (split from docker.rs).
use super::*;

// ---------------------------------------------------------------------------
// Container backups (commit -> docker save -> gzip; restore = load + recreate)
// ---------------------------------------------------------------------------

/// Root directory holding all container backups (`<data>/docker-backups`).
pub(crate) fn backups_root() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("docker-backups")
}

/// Validate a container name used as a backups subdirectory (defensive — the
/// name comes from the daemon, but we still keep it to a safe charset).
pub(crate) fn safe_dir_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Validate a backup file name (timestamp.tar.gz). No path separators.
pub(crate) fn valid_backup_name(s: &str) -> bool {
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
pub(crate) fn start_backup_container(req: &Req) -> Result<Value> {
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

pub(crate) async fn backup_container(op_id: &str, reference: &str, name: &str) -> Result<String> {
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
    let tmp_image = commit_backup_image(&dkr, reference, name, &ts).await?;

    // Stream `docker save` -> gzip -> file.
    op_push(op_id, &pmsg("dk.bk_saving", &[]));
    let tar_gz = dir.join(format!("{ts}.tar.gz"));
    let result = stream_image_to_gz(&dkr, &tmp_image, &tar_gz).await;

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

/// Commit `reference` to a temporary `dn7-backup:<name>-<ts>` image so the
/// exported tar carries the full config + layers. Returns the temp image name.
async fn commit_backup_image(
    dkr: &Docker,
    reference: &str,
    name: &str,
    ts: &str,
) -> Result<String> {
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
    Ok(format!("{tmp_repo}:{tmp_tag}"))
}

/// Stream `docker save <image>` through gzip into `path`. The caller handles
/// cleanup of the temp image and the partial file on error.
async fn stream_image_to_gz(dkr: &Docker, image: &str, path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let file = std::fs::File::create(path).map_err(|e| anyhow!("无法创建备份文件：{e}"))?;
    let mut enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut stream = dkr.export_image(image);
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| anyhow!(friendly_docker_err(&e)))?;
        enc.write_all(&chunk)
            .map_err(|e| anyhow!("写入备份失败：{e}"))?;
    }
    enc.finish().map_err(|e| anyhow!("写入备份失败：{e}"))?;
    Ok(())
}

/// List backups for a container name: file, size, created (mtime, secs).
pub(crate) async fn list_backups(req: &Req) -> Result<Value> {
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
    items.sort_by_key(|a| std::cmp::Reverse(a.get("created").and_then(Value::as_u64)));
    Ok(json!({ "backups": items }))
}

/// Delete one backup file (and its sidecar config snapshot).
pub(crate) fn delete_backup(req: &Req) -> Result<Value> {
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
pub(crate) fn start_restore_backup(req: &Req) -> Result<Value> {
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

pub(crate) async fn restore_backup(op_id: &str, name: &str, file: &str) -> Result<()> {
    let dkr = dkr()?;
    let dir = backups_root().join(name);
    let tar_gz = dir.join(file);
    if !tar_gz.exists() {
        return Err(anyhow!("ERR_CODE:docker.backup_missing"));
    }

    // Load the saved image (`docker load`); it records its own repo:tag.
    op_push(op_id, &pmsg("dk.bk_loading", &[]));
    let loaded_image = load_backup_image(&dkr, &tar_gz).await?;

    // Read the config snapshot and recreate the container from the loaded image.
    op_push(op_id, &pmsg("dk.bk_recreating", &[]));
    recreate_from_snapshot(&dir, file, name, &loaded_image).await
}

/// `docker load` a backup tarball and return the repo:tag it recorded
/// (dn7-backup:<name>-<ts>), parsed from the load progress stream.
async fn load_backup_image(dkr: &Docker, tar_gz: &std::path::Path) -> Result<String> {
    use tokio_util::codec::{BytesCodec, FramedRead};
    let f = tokio::fs::File::open(tar_gz)
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
    Ok(loaded_image)
}

/// Read the JSON create-snapshot beside the tarball, point it at the freshly
/// loaded image, and recreate the container under `name` (replacing any
/// existing one with that name).
async fn recreate_from_snapshot(
    dir: &std::path::Path,
    file: &str,
    name: &str,
    loaded_image: &str,
) -> Result<()> {
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
pub(crate) fn now_stamp() -> String {
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
) -> Result<(String, crate::infra::file::ByteStream)> {
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
pub async fn image_export_stream(image: &str) -> Result<(String, crate::infra::file::ByteStream)> {
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
