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
        return Err(docker_err(DockerError::BadName));
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
    // Read the docker export asynchronously, but do the CPU-bound gzip + blocking
    // file writes on the blocking pool (a dedicated writer task) so the runtime
    // worker isn't pinned for the whole (potentially multi-GB) backup.
    let path = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
    let writer = tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::Write;
        let file = std::fs::File::create(&path).map_err(|e| anyhow!("无法创建备份文件：{e}"))?;
        let mut enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        while let Ok(chunk) = rx.recv() {
            enc.write_all(&chunk)
                .map_err(|e| anyhow!("写入备份失败：{e}"))?;
        }
        enc.finish().map_err(|e| anyhow!("写入备份失败：{e}"))?;
        Ok(())
    });

    let mut stream = dkr.export_image(image);
    let mut stream_err: Option<anyhow::Error> = None;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => {
                if tx.send(chunk.to_vec()).is_err() {
                    break; // writer task ended (it will surface the error below)
                }
            }
            Err(e) => {
                stream_err = Some(anyhow!(friendly_docker_err(&e)));
                break;
            }
        }
    }
    drop(tx); // signal EOF to the writer
    writer.await.map_err(|e| anyhow!("备份任务失败：{e}"))??;
    match stream_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// List backups for a container name: file, size, created (mtime, secs).
pub(crate) async fn list_backups(req: &Req) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| safe_dir_component(s))
        .ok_or_else(|| docker_err(DockerError::BadName))?;
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
        .ok_or_else(|| docker_err(DockerError::BadName))?;
    let file = req
        .backup
        .as_deref()
        .map(str::trim)
        .filter(|s| valid_backup_name(s))
        .ok_or_else(|| docker_err(DockerError::BadBackup))?;
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
pub(crate) fn start_restore_backup(req: &Req, is_super: bool) -> Result<Value> {
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
        match restore_backup(&op_id_t, &name, &file, is_super).await {
            Ok(()) => op_finish(&op_id_t, "done", "", &name),
            Err(e) => op_finish(&op_id_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "target": target }))
}

pub(crate) async fn restore_backup(
    op_id: &str,
    name: &str,
    file: &str,
    is_super: bool,
) -> Result<()> {
    let dkr = dkr()?;
    let dir = backups_root().join(name);
    let tar_gz = dir.join(file);
    if !tar_gz.exists() {
        return Err(docker_err(DockerError::BackupMissing));
    }

    // Load the saved image (`docker load`); it records its own repo:tag.
    op_push(op_id, &pmsg("dk.bk_loading", &[]));
    let loaded_image = load_backup_image(&dkr, &tar_gz).await?;

    // Read the config snapshot and recreate the container from the loaded image.
    op_push(op_id, &pmsg("dk.bk_recreating", &[]));
    recreate_from_snapshot(file, name, &loaded_image, is_super).await
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
    file: &str,
    name: &str,
    loaded_image: &str,
    is_super: bool,
) -> Result<()> {
    // `dir` is derivable from `name` (one fewer param to thread).
    let dir = backups_root().join(name);
    let json_path = dir.join(file.replace(".tar.gz", ".json"));
    let mut body: Value = match std::fs::read(&json_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({})),
        Err(_) => json!({}),
    };
    let obj = body
        .as_object_mut()
        .ok_or_else(|| docker_err(DockerError::BackupBadConfig))?;
    if !loaded_image.is_empty() {
        obj.insert("image".to_string(), json!(loaded_image));
    }
    obj.insert("name".to_string(), json!(name));
    obj.insert("replace".to_string(), json!(name));
    obj.insert("start".to_string(), json!(true));
    let restore_req: Req =
        serde_json::from_value(body).map_err(|_| docker_err(DockerError::BackupBadConfig))?;
    // A restore must not materialize a privileged / host-network container for a
    // non-super caller, even from a snapshot saved by one (same gate as create).
    enforce_create_policy(&restore_req, is_super)?;
    let (spec, _) = build_create_spec(&restore_req)?;
    create_container(spec).await?;
    Ok(())
}

/// A compact timestamp for backup file names. Uses MILLIS-since-epoch (no
/// chrono/time dependency): monotonic + sortable, and collision-resistant so two
/// backups of the same container within the same second don't clobber each other
/// (whole-second stems used to silently overwrite).
pub(crate) fn now_stamp() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{millis}")
}

// ---------------------------------------------------------------------------
// Staged, verified exports (audit P3)
//
// A docker image export / container backup download used to stream straight to
// the client with the 200 already committed, so a mid-stream daemon/IO failure
// yielded a *truncated* attachment the user mistook for a good backup. For these
// high-value paths we instead stage the whole export to a verified temp file
// under `<data>/tmp` first: if the export fails mid-write we can still return an
// error (no 200), and on success we serve the complete file with an accurate
// Content-Length + a SHA-256 the client can verify. The temp is always cleaned
// up (on failure here, on success after the response body drains).
// ---------------------------------------------------------------------------

/// Staging directory for in-flight exports (`<data>/tmp`). Created on demand.
fn export_staging_dir() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("tmp")
}

/// A fully-staged export: the on-disk temp file, its exact byte length, and the
/// hex SHA-256 of its contents (for the `X-DN7-SHA256` header / sidecar).
pub struct StagedExport {
    pub path: std::path::PathBuf,
    pub len: u64,
    pub sha256_hex: String,
}

impl StagedExport {
    /// Best-effort removal of the staged temp file (on success after the
    /// response drains, or on any error path).
    pub fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Sane fraction of currently-available disk we're willing to spend staging one
/// export, so a huge (or runaway) export can't fill the data volume. Checked
/// against `fs2::available_space` up front and again as the running total grows.
const STAGE_DISK_FRACTION: u64 = 4; // ≤ 1/4 of free space

/// Drain a docker export/backup byte stream into a freshly-created temp file
/// under `<data>/tmp`, hashing as we go. Returns the staged file + its length +
/// SHA-256 on success. On **any** failure (stream error, IO error, cap/disk
/// guard) the partial temp is removed and an error is returned — so the caller
/// can respond with an error status instead of a truncated 200.
///
/// `stream` yields `std::io::Result<Bytes>` (the shape of
/// [`crate::infra::file::ByteStream`]); a per-chunk error aborts the stage.
pub async fn stage_export<S>(mut stream: S) -> Result<StagedExport>
where
    S: futures::Stream<Item = std::io::Result<bytes::Bytes>> + Unpin,
{
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    let dir = export_staging_dir();
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("无法创建暂存目录：{e}"))?;
    // Bound the stage to a fraction of free space (guard against filling the
    // volume). If we can't stat the fs, fall back to no explicit cap.
    let cap = fs2::available_space(&dir)
        .ok()
        .map(|avail| avail / STAGE_DISK_FRACTION);

    // Fresh, unpredictable temp name in the staging dir (O_EXCL, 0600) — a local
    // low-priv user can't pre-plant a symlink to hijack the write.
    let (f, tmp) = create_staging_file(&dir)?;
    let mut f = tokio::fs::File::from_std(f);
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;

    // Any early return past this point must remove the partial temp; do it via a
    // small helper so we never leak a half-written file.
    let fail = |tmp: &std::path::Path, e: anyhow::Error| -> anyhow::Error {
        StagedExport::cleanup(tmp);
        e
    };

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => return Err(fail(&tmp, anyhow!("导出流失败：{e}"))),
        };
        total += chunk.len() as u64;
        if let Some(cap) = cap {
            if total > cap {
                return Err(fail(&tmp, anyhow!("导出体积超出可用磁盘限制")));
            }
        }
        if let Err(e) = f.write_all(&chunk).await {
            return Err(fail(&tmp, anyhow!("写入暂存文件失败：{e}")));
        }
        hasher.update(&chunk);
    }
    if let Err(e) = f.flush().await {
        return Err(fail(&tmp, anyhow!("写入暂存文件失败：{e}")));
    }
    drop(f);

    Ok(StagedExport {
        path: tmp,
        len: total,
        sha256_hex: hex_lower(&hasher.finalize()),
    })
}

/// Create a fresh staging file (O_EXCL + 0600) in `dir` with an unpredictable
/// random name. Mirrors [`crate::infra::file::create_temp_upload`] but lets us
/// place the temp under `<data>/tmp` (on the data volume) rather than the system
/// temp dir, so a multi-GB export doesn't land on a small `/tmp` tmpfs.
fn create_staging_file(dir: &std::path::Path) -> Result<(std::fs::File, std::path::PathBuf)> {
    let mut last_err = None;
    for _ in 0..16 {
        let path = dir.join(format!(
            "dn7-export-{:016x}{:016x}.part",
            rand::random::<u64>(),
            rand::random::<u64>()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true); // O_CREAT | O_EXCL
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(anyhow!("无法创建暂存文件：{e}")),
        }
    }
    Err(anyhow!(
        "无法创建暂存文件：{}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// An unpredictable staging *path* under `dir` (128-bit random name) that is
/// **not** yet created. Used when a downstream helper wants to open the file
/// itself with `O_EXCL` (e.g. `archive::save`), so we hand it a fresh name it
/// can exclusively create rather than a pre-existing empty file.
#[cfg(target_os = "linux")]
fn staging_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!(
        "dn7-export-{:016x}{:016x}.tar",
        rand::random::<u64>(),
        rand::random::<u64>()
    ))
}

/// Lowercase-hex encode a digest (no extra dep; matches the hex idiom used
/// elsewhere in this module, e.g. `runtime_dn7::short_hash`).
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    S: futures::Stream<Item = bytes::Bytes> + Send + 'static,
{
    if dn7_container::selected() {
        return dn7_import_image(body).await;
    }
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
        return Err(docker_err(DockerError::ImportNoImage));
    }
    Ok(json!({ "loaded": loaded }))
}

/// Open a docker image export (`docker save`) for streaming download as a tar.
pub async fn image_export_stream(image: &str) -> Result<(String, crate::infra::file::ByteStream)> {
    use futures::StreamExt;
    validate_token(image)?;
    if dn7_container::selected() {
        return dn7_export_image(image).await;
    }
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

/// dn7: export an image to an OCI tar, then stream it. The tar is staged under
/// `<data>/tmp` with an unpredictable name (not `/tmp/dn7-export-<millis>`, which
/// a local user could predict + pre-plant a symlink for); `archive::save` opens
/// it O_EXCL/0600 so it can't follow a planted symlink either. The temp is
/// unlinked immediately after opening so the fd auto-cleans on EOF/error.
#[cfg(target_os = "linux")]
async fn dn7_export_image(image: &str) -> Result<(String, crate::infra::file::ByteStream)> {
    use futures::StreamExt;
    let image_owned = image.to_string();
    let dir = export_staging_dir();
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("无法创建暂存目录：{e}"))?;
    let tmp = staging_path(&dir);
    let tmp2 = tmp.clone();
    let saved = tokio::task::spawn_blocking(move || {
        let store = dn7_container::image::Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        dn7_container::image::archive::save(&store, &image_owned, &tmp2)
            .map_err(|e| anyhow!("dn7 save: {e}"))
    })
    .await
    .map_err(|e| anyhow!("export task: {e}"));
    // A save failure (or join error) must not leave the staged tar behind.
    if let Err(e) | Ok(Err(e)) = saved {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let f = match tokio::fs::File::open(&tmp).await {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!("无法打开导出文件：{e}"));
        }
    };
    let _ = std::fs::remove_file(&tmp); // unlink; the open fd keeps the data
    let safe = image.replace([':', '/'], "_");
    let stream = tokio_util::codec::FramedRead::new(f, tokio_util::codec::BytesCodec::new())
        .map(|r| r.map(|b| b.freeze()));
    Ok((format!("{safe}.tar"), Box::pin(stream)))
}
#[cfg(not(target_os = "linux"))]
async fn dn7_export_image(_image: &str) -> Result<(String, crate::infra::file::ByteStream)> {
    Err(anyhow!("dn7 runtime is Linux-only"))
}

/// dn7: load an uploaded OCI tar into the store under a generated reference. The
/// upload is staged to an O_EXCL/0600 temp under `<data>/tmp` (not a predictable
/// `/tmp/dn7-import-<millis>` a local user could pre-plant), capped to a fraction
/// of free disk so a proxied upload can't fill the volume. The temp is removed on
/// every exit path.
#[cfg(target_os = "linux")]
async fn dn7_import_image<S>(body: S) -> Result<Value>
where
    S: futures::Stream<Item = bytes::Bytes> + Send + 'static,
{
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let ts = now_stamp();
    let dir = export_staging_dir();
    std::fs::create_dir_all(&dir).map_err(|e| anyhow!("无法创建暂存目录：{e}"))?;
    // Cap the drained upload to a fraction of free space (guard against filling
    // the data volume). Falls back to no explicit cap if the fs can't be stat'd.
    let cap = fs2::available_space(&dir)
        .ok()
        .map(|avail| avail / STAGE_DISK_FRACTION);
    let (f, tmp) = create_staging_file(&dir)?;

    let drained = async {
        let mut f = tokio::fs::File::from_std(f);
        let mut body = std::pin::pin!(body);
        let mut total: u64 = 0;
        while let Some(chunk) = body.next().await {
            total += chunk.len() as u64;
            if let Some(cap) = cap {
                if total > cap {
                    return Err(anyhow!("上传体积超出可用磁盘限制"));
                }
            }
            f.write_all(&chunk)
                .await
                .map_err(|e| anyhow!("写入上传失败：{e}"))?;
        }
        f.flush().await.map_err(|e| anyhow!("写入上传失败：{e}"))?;
        Ok(())
    }
    .await;
    if let Err(e) = drained {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    let tmp2 = tmp.clone();
    let out = tokio::task::spawn_blocking(move || -> Result<Value> {
        use dn7_container::image::{archive, list_summaries, ImageRecord, Reference, Store};
        let store = Store::open().map_err(|e| anyhow!("dn7 store: {e}"))?;
        // Restore the image's real name from the archive itself (a dn7 export's
        // OCI ref-name annotation, or a docker-save's RepoTags); fall back to a
        // synthetic `imported:<ts>` only for a genuinely-unnamed archive.
        let reference =
            archive::embedded_reference(&tmp2).unwrap_or_else(|| format!("imported:{ts}"));
        let key = Reference::parse(&reference)
            .map_err(|e| anyhow!("dn7 load: {e}"))?
            .store_key();
        // Snapshot any image already under this tag BEFORE load moves the tag, so
        // we can tell the user "identical" vs "replaced" (Docker `load` semantics:
        // an identical image is a no-op; a different one takes over the tag).
        let size_of = |d: &str| -> Option<u64> {
            list_summaries(&store)
                .ok()?
                .into_iter()
                .find(|s| s.config_digest == d)
                .map(|s| s.size)
        };
        let prev = ImageRecord::load(&store, &key).ok();
        let prev_size = prev.as_ref().and_then(|p| size_of(&p.config_digest));
        let rec = archive::load(&store, &tmp2, &reference).map_err(|e| anyhow!("dn7 load: {e}"))?;
        let status = match &prev {
            Some(p) if p.config_digest == rec.config_digest => "identical",
            Some(_) => "replaced",
            None => "loaded",
        };
        Ok(json!({
            "loaded": [rec.reference.clone()],
            "reference": rec.reference,
            "status": status,
            "digest": rec.config_digest,
            "size": size_of(&rec.config_digest),
            "prev_digest": prev.as_ref().map(|p| p.config_digest.clone()),
            "prev_size": prev_size,
        }))
    })
    .await
    .map_err(|e| anyhow!("import task: {e}"));
    let _ = std::fs::remove_file(&tmp);
    out?
}
#[cfg(not(target_os = "linux"))]
async fn dn7_import_image<S>(_body: S) -> Result<Value>
where
    S: futures::Stream<Item = bytes::Bytes> + Send + 'static,
{
    Err(anyhow!("dn7 runtime is Linux-only"))
}

#[cfg(test)]
mod stage_tests {
    use super::*;
    use crate::test_support::ENV_LOCK;

    // `stage_export` resolves the staging dir through `data_dir()`, which honors
    // the process-global `DN7_RUNTIME_DIR`. The tests set/read it, so serialize
    // them (and restore the previous value) against every other env-mutating test
    // via the one crate-wide `test_support::ENV_LOCK` — held across `.await`.

    // Point `data_dir()` (hence the staging dir) at a private temp dir; returns
    // the base so the caller can assert paths / clean up.
    fn redirect_data_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dn7-stage-test-{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        ));
        std::env::set_var("DN7_RUNTIME_DIR", &dir);
        dir
    }

    fn ok_chunk(b: &[u8]) -> std::io::Result<bytes::Bytes> {
        Ok(bytes::Bytes::copy_from_slice(b))
    }

    #[tokio::test]
    async fn stage_export_success_stages_and_checksums() {
        let _g = ENV_LOCK.lock().await;
        let base = redirect_data_dir();
        let stream = futures::stream::iter(vec![ok_chunk(b"hel"), ok_chunk(b"lo")]);
        let staged = stage_export(stream).await.expect("stage should succeed");

        // Length + checksum are computed over the full "hello".
        assert_eq!(staged.len, 5);
        // SHA-256("hello"), lowercase hex.
        assert_eq!(
            staged.sha256_hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        // The temp landed under `<data>/tmp` and its bytes match.
        assert!(staged.path.starts_with(base.join("data").join("tmp")));
        assert_eq!(std::fs::read(&staged.path).unwrap(), b"hello");

        // Caller-driven cleanup removes the staged temp.
        StagedExport::cleanup(&staged.path);
        assert!(!staged.path.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn stage_export_mid_stream_error_cleans_up() {
        let _g = ENV_LOCK.lock().await;
        let base = redirect_data_dir();
        let boom = || -> std::io::Result<bytes::Bytes> { Err(std::io::Error::other("boom")) };
        let stream = futures::stream::iter(vec![ok_chunk(b"hel"), boom()]);
        let res = stage_export(stream).await;

        // A mid-stream failure must surface as an error (never a truncated file).
        assert!(res.is_err(), "mid-stream error must fail the stage");
        // …and the partial temp must be gone (no leaked `.part` under staging).
        let staging = base.join("data").join("tmp");
        let leaked = std::fs::read_dir(&staging)
            .map(|rd| rd.flatten().count())
            .unwrap_or(0);
        assert_eq!(leaked, 0, "the partial temp must be cleaned up");
        let _ = std::fs::remove_dir_all(&base);
    }
}
