//! File-manager use-cases (host + container).
//!
//! The web handlers only parse the request, resolve the caller, map the result
//! to a response, and (for downloads) wrap the returned stream in an HTTP body.
//! The shared **business rule** lives here: a container-scoped op is admin-only,
//! while a host op runs as the caller's own system user (OS perms then enforce
//! access). The actual filesystem/Docker work is delegated to `infra::file`.
//!
//! The caller is passed as primitives (`is_admin`, `system_user`) rather than a
//! web/delivery type, so this layer has no dependency on the web boundary.

use serde_json::Value;

/// A file-service failure: either the caller lacks permission, or the
/// underlying operation errored. The web boundary maps these to HTTP.
pub(crate) enum FsError {
    Forbidden,
    Op(anyhow::Error),
}

/// Container ops are admin-only.
fn guard_container(is_admin: bool) -> Result<(), FsError> {
    if is_admin {
        Ok(())
    } else {
        Err(FsError::Forbidden)
    }
}

/// List a directory (host as the caller's user, or a container — admin only).
pub(crate) async fn list(
    is_admin: bool,
    system_user: Option<&str>,
    path: &str,
    container: Option<&str>,
) -> Result<Value, FsError> {
    match container {
        Some(c) => {
            guard_container(is_admin)?;
            crate::infra::file::web_ctn_list(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::infra::file::web_host_list(path, system_user)
            .await
            .map_err(FsError::Op),
    }
}

/// Create a directory.
pub(crate) async fn mkdir(
    is_admin: bool,
    system_user: Option<&str>,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(is_admin)?;
            crate::infra::file::web_ctn_mkdir(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::infra::file::web_host_mkdir(path, system_user)
            .await
            .map_err(FsError::Op),
    }
}

/// Delete a path.
pub(crate) async fn delete(
    is_admin: bool,
    system_user: Option<&str>,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(is_admin)?;
            crate::infra::file::web_ctn_delete(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::infra::file::web_host_delete(path, system_user)
            .await
            .map_err(FsError::Op),
    }
}

/// Write an already-streamed temp file into place (host or container).
pub(crate) async fn write_file(
    is_admin: bool,
    system_user: Option<&str>,
    path: &str,
    container: Option<&str>,
    tmp: &std::path::Path,
) -> Result<(), FsError> {
    match container {
        Some(c) => {
            guard_container(is_admin)?;
            crate::infra::file::web_ctn_write_file(c, path, tmp)
                .await
                .map_err(FsError::Op)
        }
        None => crate::infra::file::web_host_write_file(path, tmp, system_user)
            .await
            .map_err(FsError::Op),
    }
}

/// Open a download stream + suggested filename (host as the caller's user, or a
/// container — admin only). The web boundary wraps the stream in an HTTP body.
pub(crate) async fn read_stream(
    is_admin: bool,
    system_user: Option<&str>,
    path: &str,
    container: Option<&str>,
) -> Result<(String, crate::infra::file::ByteStream), FsError> {
    match container {
        Some(c) => {
            guard_container(is_admin)?;
            crate::infra::file::web_ctn_read_stream(c, path)
                .await
                .map_err(FsError::Op)
        }
        None => crate::infra::file::web_host_read_stream(path, system_user)
            .await
            .map_err(FsError::Op),
    }
}
