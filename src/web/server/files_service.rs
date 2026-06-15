//! File-manager use-case layer (pilot of the handler → service → infra split).
//!
//! The HTTP handlers in `files_api` only parse the request, resolve the caller,
//! and map the result to a response. This module owns the **business rule**
//! shared by every file operation: a container-scoped op is admin-only, while a
//! host op runs as the caller's own system user (OS perms then enforce access).
//! The actual filesystem/Docker work lives in the `crate::file` infra module.
use super::*;

/// A file-service failure: either the caller lacks permission, or the
/// underlying operation errored. Handlers map these to the right HTTP shape.
pub(crate) enum FsError {
    Forbidden,
    Op(anyhow::Error),
}

/// Container ops are admin-only.
fn guard_container(acct: &Account) -> Result<(), FsError> {
    if acct.is_admin {
        Ok(())
    } else {
        Err(FsError::Forbidden)
    }
}

/// Map a file-service error to the response shape the file handlers use: a 403
/// for a permission failure, else a 200 `{ ok:false, error }` for an op error.
pub(crate) fn fs_err_response(e: FsError) -> Response {
    match e {
        FsError::Forbidden => api_err(StatusCode::FORBIDDEN, "auth.forbidden"),
        FsError::Op(e) => Json(json!({ "ok": false, "error": e.to_string() })).into_response(),
    }
}

/// List a directory (host as the caller's user, or a container — admin only).
pub(crate) async fn list(
    acct: &Account,
    path: &str,
    container: Option<&str>,
) -> Result<Value, FsError> {
    match container {
        Some(c) => {
            guard_container(acct)?;
            crate::file::web_ctn_list(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::file::web_host_list(path, acct.system_user.as_deref())
            .await
            .map_err(FsError::Op),
    }
}

/// Create a directory.
pub(crate) async fn mkdir(
    acct: &Account,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(acct)?;
            crate::file::web_ctn_mkdir(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::file::web_host_mkdir(path, acct.system_user.as_deref())
            .await
            .map_err(FsError::Op),
    }
}

/// Delete a path.
pub(crate) async fn delete(
    acct: &Account,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(acct)?;
            crate::file::web_ctn_delete(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::file::web_host_delete(path, acct.system_user.as_deref())
            .await
            .map_err(FsError::Op),
    }
}

/// Write an already-streamed temp file into place (host or container).
pub(crate) async fn write_file(
    acct: &Account,
    path: &str,
    container: Option<&str>,
    tmp: &std::path::Path,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(acct)?;
            crate::file::web_ctn_write_file(c, path, tmp)
                .await
                .map_err(FsError::Op)
        }
        None => crate::file::web_host_write_file(path, tmp, acct.system_user.as_deref())
            .await
            .map_err(FsError::Op),
    }
}
