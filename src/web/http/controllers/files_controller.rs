//! File transfer (host + container) HTTP handlers (split from web/server.rs).
use super::super::*;

/// Map an `app::files` error to the file handlers' response shape: a 403 for a
/// permission failure, else a 200 `{ ok:false, error }` for an op error.
pub(crate) fn fs_err_response(e: crate::app::files::FsError) -> Response {
    match e {
        crate::app::files::FsError::Forbidden => api_err(StatusCode::FORBIDDEN, "auth.forbidden"),
        // Split an `ERR_CODE:<code>` op error into a localizable `code` field (as
        // the capability ops do) — e.g. `files.cross_device` / `files.read_failed`
        // — while plain messages pass through unchanged as `{ ok:false, error }`.
        crate::app::files::FsError::Op(e) => Json(op_err_body(e)).into_response(),
    }
}

// ---------------------------------------------------------------------------
// File transfer (host + container) — plain HTTP request/response.
// ---------------------------------------------------------------------------

/// Body for list/mkdir/delete: a path, optionally scoped to a container.
#[derive(serde::Deserialize)]
pub(crate) struct FileOpReq {
    #[serde(default)]
    path: String,
    /// When set, the operation targets this container's filesystem.
    #[serde(default)]
    container: Option<String>,
}

pub(crate) fn ctn_ref(req: &FileOpReq) -> Option<&str> {
    req.container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Audit target for a file op: `container:path` when container-scoped, else the
/// bare host path. Keeps the log line self-describing.
fn audit_target(path: &str, container: Option<&str>) -> String {
    match container {
        Some(c) => format!("{c}:{path}"),
        None => path.to_string(),
    }
}

/// Short audit detail string for a failed file op.
fn fs_err_detail(e: &crate::app::files::FsError) -> String {
    match e {
        crate::app::files::FsError::Forbidden => "forbidden".to_string(),
        crate::app::files::FsError::Op(e) => e.to_string(),
    }
}

/// Default per-file upload cap (lowered from 512 MiB). Streaming keeps memory
/// bounded regardless, but a smaller cap limits temp-disk blowups too.
pub(crate) const UPLOAD_CAP: u64 = 256 * 1024 * 1024;

/// Global cap on concurrent file transfers (uploads + downloads), so a few
/// parallel transfers can't exhaust resources. A transfer holds a permit for
/// its whole duration (downloads carry it inside the response stream).
pub(crate) fn transfer_sem() -> std::sync::Arc<tokio::sync::Semaphore> {
    static S: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(6)))
        .clone()
}

/// Wraps a download/export byte stream so a *closed* audit entry is written when
/// the transfer terminates. A 200 + `Body::from_stream` is already committed
/// before the first byte, so a mid-stream failure would otherwise send a
/// truncated attachment with no record of the outcome. This adapter records:
///   - `ok=true`  on a clean EOF (the whole file was streamed);
///   - `ok=false` if any chunk yields an error (a truncated download); or
///   - `ok=false` ("aborted") if the response body is dropped before EOF
///     (client disconnect / cancelled download).
///
/// Exactly one record is emitted (the first terminal event wins). The transfer
/// permit is carried inside so it stays held for the whole stream lifetime.
struct AuditedStream<S> {
    inner: S,
    actor: String,
    action: &'static str,
    target: String,
    /// Set once a terminal outcome has been recorded, so `Drop` doesn't double-log.
    recorded: bool,
    /// Kept alive for the whole stream (the concurrent-transfer permit).
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<S> AuditedStream<S> {
    fn new(
        inner: S,
        actor: String,
        action: &'static str,
        target: String,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            inner,
            actor,
            action,
            target,
            recorded: false,
            _permit: permit,
        }
    }

    /// Emit the single terminal audit record (idempotent).
    fn record(&mut self, ok: bool, detail: &str) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        audit::record(&self.actor, self.action, &self.target, ok, detail);
    }
}

impl<S> futures::Stream for AuditedStream<S>
where
    S: futures::Stream<Item = std::io::Result<bytes::Bytes>> + Unpin,
{
    type Item = std::io::Result<bytes::Bytes>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;
        // `Self: Unpin` (all fields are), so we can take a plain `&mut Self`.
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
            Poll::Ready(Some(Err(e))) => {
                let detail = e.to_string();
                this.record(false, &detail);
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.record(true, "");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for AuditedStream<S> {
    fn drop(&mut self) {
        // Terminal state never reached (clean EOF / error) => the client aborted
        // before the transfer completed. Close the trail as a failed download.
        self.record(false, "aborted");
    }
}

/// Serves an already-staged temp file (a verified docker export/backup) as a
/// byte stream, then removes the temp when the response terminates — on clean
/// EOF, a read error, or a client abort (the `Drop` fires in every case). The
/// transfer permit is carried inside so it stays held for the whole response,
/// mirroring [`AuditedStream`]. The export outcome is already known before the
/// 200 here (the stage either fully succeeded or returned an error), so no
/// completion audit is needed on this path.
struct TempFileStream {
    inner: tokio_util::io::ReaderStream<tokio::fs::File>,
    /// The staged temp file to unlink once the response is done (best-effort).
    temp: std::path::PathBuf,
    /// Kept alive for the whole stream (the concurrent-transfer permit).
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl TempFileStream {
    fn new(
        file: tokio::fs::File,
        temp: std::path::PathBuf,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            inner: tokio_util::io::ReaderStream::new(file),
            temp,
            _permit: permit,
        }
    }
}

impl futures::Stream for TempFileStream {
    type Item = std::io::Result<bytes::Bytes>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // `Self: Unpin` (ReaderStream over a File is Unpin), so a plain `&mut`.
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_next(cx)
    }
}

impl Drop for TempFileStream {
    fn drop(&mut self) {
        // Best-effort cleanup once the response drains / is dropped. The open fd
        // in `inner` is closed as this struct drops; unlink the path so a partial
        // (aborted) or completed download leaves nothing behind on the data volume.
        let temp = std::mem::take(&mut self.temp);
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&temp).await;
        });
    }
}

/// Stream a request body to a host temp file, enforcing `cap` (bounded memory).
/// Returns the temp path, or an error response (and removes the partial temp).
pub(crate) async fn stream_body_to_temp(
    body: axum::body::Body,
    cap: u64,
) -> Result<std::path::PathBuf, Response> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let (f, tmp) = match crate::infra::file::create_temp_upload() {
        Ok(v) => v,
        Err(e) => {
            return Err(api_err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "common.save_failed",
                e,
            ))
        }
    };
    let mut f = tokio::fs::File::from_std(f);
    let mut total: u64 = 0;
    let mut stream = body.into_data_stream();
    let fail = |tmp: &std::path::PathBuf, resp: Response| {
        let t = tmp.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_file(&t).await;
        });
        resp
    };
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => {
                return Err(fail(
                    &tmp,
                    api_err(StatusCode::BAD_REQUEST, "common.save_failed"),
                ))
            }
        };
        total += chunk.len() as u64;
        if total > cap {
            return Err(fail(
                &tmp,
                api_err(StatusCode::PAYLOAD_TOO_LARGE, "files.too_large"),
            ));
        }
        if f.write_all(&chunk).await.is_err() {
            return Err(fail(
                &tmp,
                api_err(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed"),
            ));
        }
    }
    if f.flush().await.is_err() {
        return Err(fail(
            &tmp,
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "common.save_failed"),
        ));
    }
    Ok(tmp)
}

pub(crate) async fn files_list(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    match crate::app::files::list(&caller, &req.path, ctn_ref(&req)).await {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

pub(crate) async fn files_mkdir(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let res = crate::app::files::mkdir(&caller, &req.path, ctn_ref(&req)).await;
    audit::record(
        &acct.username,
        "files.mkdir",
        &audit_target(&req.path, ctn_ref(&req)),
        res.is_ok(),
        &res.as_ref().err().map(fs_err_detail).unwrap_or_default(),
    );
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

pub(crate) async fn files_delete(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let res = crate::app::files::delete(&caller, &req.path, ctn_ref(&req)).await;
    audit::record(
        &acct.username,
        "files.delete",
        &audit_target(&req.path, ctn_ref(&req)),
        res.is_ok(),
        &res.as_ref().err().map(fs_err_detail).unwrap_or_default(),
    );
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

/// Body for rename/move: the source path and the FULL new path (`to`), with
/// the same optional container scope as the other file ops.
#[derive(serde::Deserialize)]
pub(crate) struct FileRenameReq {
    #[serde(default)]
    path: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    container: Option<String>,
}

/// POST /api/files/rename — rename or move (one endpoint; `to` is the full
/// destination path). The infra layer refuses protected system trees on both
/// ends and an existing destination (no silent clobber).
pub(crate) async fn files_rename(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileRenameReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let ctn = req
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let res = crate::app::files::rename(&caller, &req.path, &req.to, ctn).await;
    audit::record(
        &acct.username,
        "files.rename",
        &format!("{} -> {}", audit_target(&req.path, ctn), req.to),
        res.is_ok(),
        &res.as_ref().err().map(fs_err_detail).unwrap_or_default(),
    );
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

/// Cap for the inline editor's read/write payloads (1 MiB). The viewer is for
/// configs / small logs — bulk transfer stays on download/upload.
pub(crate) const EDIT_CAP: usize = 1024 * 1024;

/// Drain up to `EDIT_CAP` (+1 probe byte) from a file stream → (bytes ≤ CAP,
/// truncated). Dropping the stream early aborts the underlying source.
async fn read_capped(
    mut stream: crate::infra::file::ByteStream,
) -> std::io::Result<(Vec<u8>, bool)> {
    use futures::StreamExt;
    let cap = EDIT_CAP + 1;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let c = chunk?;
        let room = cap - buf.len();
        buf.extend_from_slice(&c[..c.len().min(room)]);
        if buf.len() >= cap {
            break;
        }
    }
    let truncated = buf.len() > EDIT_CAP;
    if truncated {
        buf.truncate(EDIT_CAP);
    }
    Ok((buf, truncated))
}

/// Decode capped file bytes for the editor → `(content, binary)`. A multi-byte
/// char split by the cap cut is trimmed (still text); any other invalid UTF-8
/// marks the file binary.
fn edit_decode(buf: Vec<u8>, truncated: bool) -> (String, bool) {
    match String::from_utf8(buf) {
        Ok(s) => (s, false),
        Err(e) => {
            let err = e.utf8_error();
            // error_len() == None ⇔ an incomplete sequence at the very end —
            // forgivable only when we cut the read ourselves.
            if !(truncated && err.error_len().is_none()) {
                return (String::new(), true);
            }
            let valid = err.valid_up_to();
            let mut bytes = e.into_bytes();
            bytes.truncate(valid);
            (String::from_utf8(bytes).unwrap_or_default(), false)
        }
    }
}

/// POST /api/files/read — fetch a text file's content for the inline viewer/
/// editor. Reads at most `EDIT_CAP` bytes → `{ content, size, truncated }`, or
/// `{ binary:true, size, truncated }` when the bytes aren't valid UTF-8
/// (`size` = bytes actually returned). Scope/permission checks ride the same
/// `app::files` read path as downloads.
pub(crate) async fn files_read(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileOpReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let target = audit_target(&req.path, ctn_ref(&req));
    let res = match crate::app::files::read_stream(&caller, &req.path, ctn_ref(&req)).await {
        Ok((_, s)) => read_capped(s)
            .await
            .map_err(|e| crate::app::files::FsError::Op(anyhow::anyhow!(e))),
        Err(e) => Err(e),
    };
    match res {
        Ok((buf, truncated)) => {
            audit::record(&acct.username, "files.read", &target, true, "");
            let size = buf.len() as u64;
            let (content, binary) = edit_decode(buf, truncated);
            let data = if binary {
                json!({ "binary": true, "size": size, "truncated": truncated })
            } else {
                json!({ "content": content, "size": size, "truncated": truncated })
            };
            Json(json!({ "ok": true, "data": data })).into_response()
        }
        Err(e) => {
            audit::record(
                &acct.username,
                "files.read",
                &target,
                false,
                &fs_err_detail(&e),
            );
            fs_err_response(e)
        }
    }
}

/// Body for the inline editor's save: full text content (capped at `EDIT_CAP`).
#[derive(serde::Deserialize)]
pub(crate) struct FileWriteReq {
    #[serde(default)]
    path: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    container: Option<String>,
}

/// Stage in-memory editor content to a temp file (the shared write path takes
/// a staged temp, mirroring upload). Returns the temp path.
async fn stage_content_to_temp(content: &[u8]) -> Result<std::path::PathBuf, Response> {
    use tokio::io::AsyncWriteExt;
    let (f, tmp) = match crate::infra::file::create_temp_upload() {
        Ok(v) => v,
        Err(e) => {
            return Err(api_err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "common.save_failed",
                e,
            ))
        }
    };
    let mut f = tokio::fs::File::from_std(f);
    if f.write_all(content).await.is_err() || f.flush().await.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "common.save_failed",
        ));
    }
    Ok(tmp)
}

/// POST /api/files/write — create-or-overwrite a text file from the inline
/// editor. Content capped at `EDIT_CAP` (1 MiB); the write reuses the upload
/// path's staging + scope/jail checks.
pub(crate) async fn files_write(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Json(req): Json<FileWriteReq>,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if req.content.len() > EDIT_CAP {
        return api_err(StatusCode::PAYLOAD_TOO_LARGE, "files.edit_too_large");
    }
    let ctn = req
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let tmp = match stage_content_to_temp(req.content.as_bytes()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let res = crate::app::files::write_file(&caller, &req.path, ctn, &tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    audit::record(
        &acct.username,
        "files.write",
        &audit_target(&req.path, ctn),
        res.is_ok(),
        &res.as_ref().err().map(fs_err_detail).unwrap_or_default(),
    );
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

/// Download query: a one-time ticket (browser can't set Authorization on a
/// direct link), path, optional container.
#[derive(serde::Deserialize)]
pub(crate) struct DownloadQuery {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
}

pub(crate) async fn files_download(
    State(state): State<Shared>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let user = match state.auth.consume_ticket(&q.ticket, "download") {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    let acct = match resolve_account(&state, &user) {
        Some(a) => a,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Hold a transfer permit for the whole download (moved into the stream).
    let permit = transfer_sem().acquire_owned().await.ok();
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    let res = crate::app::files::read_stream(&caller, &q.path, ctn).await;
    match res {
        Ok((name, stream)) => {
            // Wrap the stream so a completed/failed/aborted audit entry is written
            // when the download terminates (the 200 is already committed here, so
            // this closes the trail even on a mid-stream failure). The permit is
            // carried inside, staying held for the stream's lifetime.
            let audited = AuditedStream::new(
                stream,
                acct.username.clone(),
                "files.download",
                audit_target(&q.path, ctn),
                permit,
            );
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                axum::body::Body::from_stream(audited),
            )
                .into_response()
        }
        Err(e) => {
            // The op never started streaming — record the failure now (no 200 sent).
            audit::record(
                &acct.username,
                "files.download",
                &audit_target(&q.path, ctn),
                false,
                &fs_err_detail(&e),
            );
            match e {
                crate::app::files::FsError::Forbidden => {
                    api_err(StatusCode::FORBIDDEN, "auth.forbidden")
                }
                crate::app::files::FsError::Op(e) => {
                    (StatusCode::BAD_REQUEST, e.to_string()).into_response()
                }
            }
        }
    }
}

/// Docker download query: a one-time ticket plus what to fetch — a container
/// backup (kind=backup, name + backup file) or an image export (kind=image,
/// ref). Admin-only; mirrors files_download's ticket model.
#[derive(serde::Deserialize)]
pub(crate) struct DockerDownloadQuery {
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    backup: String,
    #[serde(default, rename = "ref")]
    reference: String,
}

pub(crate) async fn docker_download(
    State(state): State<Shared>,
    Query(q): Query<DockerDownloadQuery>,
) -> Response {
    let user = match state.auth.consume_ticket(&q.ticket, "download") {
        Some(u) => u,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    let acct = match resolve_account(&state, &user) {
        Some(a) => a,
        None => return api_err(StatusCode::UNAUTHORIZED, "auth.unauthorized"),
    };
    // Docker management is admin-only.
    if !acct.is_admin {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    let permit = transfer_sem().acquire_owned().await.ok();
    // Self-describing audit target: `backup:<name>/<file>` or `image:<ref>`.
    let target = match q.kind.as_str() {
        "backup" => format!("backup:{}/{}", q.name, q.backup),
        "image" => format!("image:{}", q.reference),
        other => format!("{other}:?"),
    };
    let res = match q.kind.as_str() {
        "backup" => crate::infra::docker::backup_read_stream(&q.name, &q.backup).await,
        "image" => crate::infra::docker::image_export_stream(&q.reference).await,
        _ => Err(anyhow::anyhow!("invalid download kind")),
    };
    let (name, stream) = match res {
        Ok(v) => v,
        Err(e) => {
            // Never started exporting — record the failure now (no 200 sent).
            audit::record(
                &acct.username,
                "docker.export",
                &target,
                false,
                &e.to_string(),
            );
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };

    // High-value export/backup paths: stage the FULL export to a verified temp
    // file first, so a mid-stream daemon/IO failure yields an *error* (not a
    // truncated 200 the user mistakes for a good backup). See
    // `infra::docker::stage_export`.
    let staged = match crate::infra::docker::stage_export(stream).await {
        Ok(s) => s,
        Err(e) => {
            // The stage cleaned up its own temp; record the failure (no 200 sent)
            // and return a plain error — the caller never sees a truncated file.
            audit::record(
                &acct.username,
                "docker.export",
                &target,
                false,
                &e.to_string(),
            );
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    // The staged file is complete + checksummed. Open it and serve it with an
    // accurate Content-Length and an X-DN7-SHA256 the client can verify. Record
    // the (successful) export now — the outcome is already known, unlike the old
    // streaming path that had to close the trail from inside the body.
    let file = match tokio::fs::File::open(&staged.path).await {
        Ok(f) => f,
        Err(e) => {
            crate::infra::docker::StagedExport::cleanup(&staged.path);
            audit::record(
                &acct.username,
                "docker.export",
                &target,
                false,
                &e.to_string(),
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    audit::record(
        &acct.username,
        "docker.export",
        &target,
        true,
        &staged.sha256_hex,
    );

    // Body reads the staged file; the wrapper unlinks the temp (best-effort) and
    // releases the transfer permit once the response drains or the client aborts.
    let body = TempFileStream::new(file, staged.path.clone(), permit);
    let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
    let sha_header = header::HeaderName::from_static("x-dn7-sha256");
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, staged.len.to_string()),
            (header::CONTENT_DISPOSITION, disp),
            (sha_header, staged.sha256_hex),
        ],
        axum::body::Body::from_stream(body),
    )
        .into_response()
}

/// POST /api/docker/image-upload — load a local image archive (docker load).
/// Streams the request body (a `docker save` tar, optionally gzipped) into the
/// daemon's image-load API. Admin only.
pub(crate) async fn docker_image_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    body: axum::body::Body,
) -> Response {
    use futures::StreamExt;
    let acct = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _permit = transfer_sem().acquire_owned().await.ok();
    let stream = body.into_data_stream().map(|r| r.unwrap_or_default());
    let res = crate::infra::docker::import_image_upload(stream).await;
    audit::record(
        &acct.username,
        "docker.image_upload",
        "",
        res.is_ok(),
        &res.as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default(),
    );
    match res {
        Ok(v) => Json(json!({ "ok": true, "data": v })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}

/// Strip characters that could break the Content-Disposition header / path.
pub(crate) fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '"' || c == '\\' || c == '\n' || c == '\r' {
                '_'
            } else {
                c
            }
        })
        .take(255)
        .collect()
}

/// Upload: multipart-free — the path/container come as query params and the raw
/// file bytes are the request body (kept simple; the UI sends one file at a
/// time). Caps the body at `UPLOAD_CAP` (256 MiB) to bound memory. Without
/// `overwrite=1`, an existing target is refused with a stable 409
/// (`files.exists`) so the client can prompt before clobbering.
#[derive(serde::Deserialize)]
pub(crate) struct UploadQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
    #[serde(default)]
    overwrite: Option<String>,
}

pub(crate) async fn files_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<UploadQuery>,
    body: axum::body::Body,
) -> Response {
    let acct = match current_account(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let ctn = q
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if ctn.is_some() && !acct.is_admin {
        return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    // Stream the body to a temp file (bounded memory), then write it into place.
    let tmp = match stream_body_to_temp(body, UPLOAD_CAP).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let caller = crate::app::files::Caller {
        is_admin: acct.is_admin,
        system_user: acct.system_user.as_deref(),
    };
    // Conflict guard: without overwrite=1 an existing target is a 409 (stable
    // code `files.exists`) so the client can prompt. Checked after the body is
    // staged so the response always lands cleanly (no mid-upload reset); an
    // inconclusive probe falls through — the write itself still enforces perms.
    let overwrite = q.overwrite.as_deref() == Some("1");
    if !overwrite
        && matches!(
            crate::app::files::exists(&caller, &q.path, ctn).await,
            Ok(true)
        )
    {
        let _ = tokio::fs::remove_file(&tmp).await;
        return api_err(StatusCode::CONFLICT, "files.exists");
    }
    let res = crate::app::files::write_file(&caller, &q.path, ctn, &tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    audit::record(
        &acct.username,
        "files.upload",
        &audit_target(&q.path, ctn),
        res.is_ok(),
        &res.as_ref().err().map(fs_err_detail).unwrap_or_default(),
    );
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => fs_err_response(e),
    }
}

/// Static-site upload: extract an uploaded ZIP, or write a single file, into a
/// managed static webroot. Query params:
///   root  — the static site's webroot subdirectory name (validated panel-side)
///   mode  — "zip" (body is a .zip to extract) | "file" (body is one file)
///   rel   — for mode=file: the file's relative path within the webroot
///   clear — "1" to wipe the webroot first (fresh upload)
/// Body is the raw bytes (capped at `UPLOAD_CAP` = 256 MiB), mirroring files_upload.
#[derive(serde::Deserialize)]
pub(crate) struct StaticUploadQuery {
    root: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    rel: Option<String>,
    #[serde(default)]
    clear: Option<String>,
}

pub(crate) async fn website_static_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<StaticUploadQuery>,
    body: axum::body::Body,
) -> Response {
    let acct = match require_admin(&state, &headers) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _permit = transfer_sem().acquire_owned().await.ok();
    let tmp = match stream_body_to_temp(body, UPLOAD_CAP).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let mode = q.mode.as_deref().unwrap_or("zip");
    let clear = q.clear.as_deref() == Some("1");
    let res = crate::infra::website::web_static_upload(crate::infra::website::StaticUpload {
        root: &q.root,
        mode,
        rel: q.rel.as_deref(),
        clear,
        temp: &tmp,
    })
    .await;
    let _ = tokio::fs::remove_file(&tmp).await;
    audit::record(
        &acct.username,
        "website.static_upload",
        &q.root,
        res.is_ok(),
        &res.as_ref()
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default(),
    );
    match res {
        Ok(n) => Json(json!({ "ok": true, "files": n })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Stream;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // Both tests mutate the process-global `DN7_RUNTIME_DIR` (to redirect the audit
    // log to a private dir) and then read it back, so they must not run
    // concurrently — serialize them on this lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // A no-op waker so we can drive a synchronous (always-Ready) stream by hand,
    // without spinning up an async runtime.
    fn noop_waker() -> Waker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        // SAFETY: the vtable's fns are all no-ops / return a fresh RawWaker, so the
        // waker is trivially valid and never dereferences its (null) data pointer.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    // Point the audit log (and every other path helper) at a private temp dir so
    // the test's audit writes stay hermetic. Returns the dir (kept for cleanup).
    fn temp_data_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dn7-audit-test-{:016x}-{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        ));
        std::env::set_var("DN7_RUNTIME_DIR", &dir);
        let _ = std::fs::create_dir_all(dir.join("data"));
        dir
    }

    fn chunk(b: &str) -> std::io::Result<bytes::Bytes> {
        Ok(bytes::Bytes::from(b.to_string()))
    }

    // Drain an AuditedStream to its terminal state via manual polling.
    fn drain<S>(mut s: AuditedStream<S>) -> Vec<u8>
    where
        S: Stream<Item = std::io::Result<bytes::Bytes>> + Unpin,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut s).poll_next(&mut cx) {
                Poll::Ready(Some(Ok(b))) => out.extend_from_slice(&b),
                Poll::Ready(Some(Err(_))) => { /* keep draining */ }
                Poll::Ready(None) => break,
                Poll::Pending => unreachable!("stream::iter is always Ready"),
            }
        }
        out
    }

    #[test]
    fn audited_stream_records_ok_on_clean_eof() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_data_dir();
        let inner = futures::stream::iter(vec![chunk("hel"), chunk("lo")]);
        let s = AuditedStream::new(inner, "owner".into(), "files.download", "/x".into(), None);
        // Bytes are forwarded transparently…
        assert_eq!(drain(s).as_slice(), b"hello");
        // …and a single ok=true record is written for the completed download.
        let entries = crate::infra::support::audit::read(50);
        let rec = entries
            .iter()
            .find(|e| e.action == "files.download" && e.target == "/x")
            .expect("audit record for completed download");
        assert!(rec.ok, "clean EOF must record ok=true");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audited_stream_records_failure_on_mid_stream_error() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_data_dir();
        let err = || -> std::io::Result<bytes::Bytes> { Err(std::io::Error::other("boom")) };
        let inner = futures::stream::iter(vec![chunk("hel"), err()]);
        let s = AuditedStream::new(inner, "owner".into(), "files.download", "/y".into(), None);
        let _ = drain(s);
        let entries = crate::infra::support::audit::read(50);
        let rec = entries
            .iter()
            .find(|e| e.action == "files.download" && e.target == "/y")
            .expect("audit record for failed download");
        assert!(!rec.ok, "a mid-stream error must record ok=false");
        assert_eq!(rec.detail, "boom");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
