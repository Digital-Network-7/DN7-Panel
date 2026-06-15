//! File transfer (host + container) HTTP handlers (split from web/server.rs).
use super::*;

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
    match files_service::list(&acct, &req.path, ctn_ref(&req)).await {
        Ok(data) => Json(json!({ "ok": true, "data": data })).into_response(),
        Err(e) => files_service::fs_err_response(e),
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
    match files_service::mkdir(&acct, &req.path, ctn_ref(&req)).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => files_service::fs_err_response(e),
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
    match files_service::delete(&acct, &req.path, ctn_ref(&req)).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => files_service::fs_err_response(e),
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
    use futures::StreamExt;
    let user = match state.auth.consume_ticket(&q.ticket) {
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
    let res = match ctn {
        Some(c) => {
            if !acct.is_admin {
                return api_err(StatusCode::FORBIDDEN, "auth.forbidden");
            }
            crate::infra::file::web_ctn_read_stream(c, &q.path).await
        }
        None => {
            crate::infra::file::web_host_read_stream(&q.path, acct.system_user.as_deref()).await
        }
    };
    match res {
        Ok((name, stream)) => {
            // Keep the permit alive for the lifetime of the response stream.
            let guarded = stream.map(move |item| {
                let _hold = &permit;
                item
            });
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                axum::body::Body::from_stream(guarded),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
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
    use futures::StreamExt;
    let user = match state.auth.consume_ticket(&q.ticket) {
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
    let res = match q.kind.as_str() {
        "backup" => crate::infra::docker::backup_read_stream(&q.name, &q.backup).await,
        "image" => crate::infra::docker::image_export_stream(&q.reference).await,
        _ => Err(anyhow::anyhow!("invalid download kind")),
    };
    match res {
        Ok((name, stream)) => {
            let guarded = stream.map(move |item| {
                let _hold = &permit;
                item
            });
            let disp = format!("attachment; filename=\"{}\"", sanitize_filename(&name));
            (
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, disp),
                ],
                axum::body::Body::from_stream(guarded),
            )
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
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
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    let stream = body.into_data_stream().map(|r| r.unwrap_or_default());
    match crate::infra::docker::import_image_upload(stream).await {
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
/// time). Caps the body at 512 MiB to bound memory.
#[derive(serde::Deserialize)]
pub(crate) struct UploadQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    container: Option<String>,
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
    let res = files_service::write_file(&acct, &q.path, ctn, &tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match res {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => files_service::fs_err_response(e),
    }
}

/// Static-site upload: extract an uploaded ZIP, or write a single file, into a
/// managed static webroot. Query params:
///   root  — the static site's webroot subdirectory name (validated panel-side)
///   mode  — "zip" (body is a .zip to extract) | "file" (body is one file)
///   rel   — for mode=file: the file's relative path within the webroot
///   clear — "1" to wipe the webroot first (fresh upload)
/// Body is the raw bytes (capped at 512 MiB), mirroring files_upload.
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

pub(crate) async fn nginx_static_upload(
    State(state): State<Shared>,
    headers: header::HeaderMap,
    Query(q): Query<StaticUploadQuery>,
    body: axum::body::Body,
) -> Response {
    if let Err(r) = require_admin(&state, &headers) {
        return r;
    }
    let _permit = transfer_sem().acquire_owned().await.ok();
    let tmp = match stream_body_to_temp(body, UPLOAD_CAP).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let mode = q.mode.as_deref().unwrap_or("zip");
    let clear = q.clear.as_deref() == Some("1");
    let res =
        crate::infra::nginx::web_static_upload(&q.root, mode, q.rel.as_deref(), clear, &tmp).await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match res {
        Ok(n) => Json(json!({ "ok": true, "files": n })).into_response(),
        Err(e) => Json(op_err_body(e)).into_response(),
    }
}
