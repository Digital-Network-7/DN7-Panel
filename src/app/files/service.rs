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

/// The caller's file-access identity: whether they're an admin (container ops
/// are admin-only) and the system user host ops run as (None = the panel's own
/// uid, i.e. the super-admin). Bundled so it threads through every entry as one
/// argument instead of a repeated `(is_admin, system_user)` pair.
pub(crate) struct Caller<'a> {
    pub(crate) is_admin: bool,
    pub(crate) system_user: Option<&'a str>,
}

impl Caller<'_> {
    /// Container ops are admin-only.
    fn guard_container(&self) -> Result<(), FsError> {
        if self.is_admin {
            Ok(())
        } else {
            Err(FsError::Forbidden)
        }
    }
}

/// Route a file op to its container arm (admin-gated) or host arm (run as the
/// caller's system user), mapping the infra error uniformly. Every entry below
/// is this same shape — the only per-op difference is which infra fn each arm
/// calls — so they share this macro instead of repeating the match + guard +
/// `map_err`. A macro (not a generic fn) because each arm's future borrows the
/// `&str` args, which a closure-returning-future signature can't express; the
/// macro expands inline so the borrows stay in one scope.
///
/// `$c` binds the container name in the container arm; `$u` binds the caller's
/// system user (`Option<&str>`) in the host arm.
macro_rules! fs_dispatch {
    ($caller:expr, $container:expr, |$c:ident| $ctn:expr, |$u:ident| $host:expr $(,)?) => {
        match $container {
            Some($c) => {
                $caller.guard_container()?;
                $ctn.await.map_err(FsError::Op)
            }
            None => {
                let $u = $caller.system_user;
                $host.await.map_err(FsError::Op)
            }
        }
    };
}

/// List a directory (host as the caller's user, or a container — admin only).
pub(crate) async fn list(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
) -> Result<Value, FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_list(c, path),
        |u| crate::infra::file::web_host_list(path, u),
    )
}

/// Create a directory.
pub(crate) async fn mkdir(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_mkdir(c, path),
        |u| crate::infra::file::web_host_mkdir(path, u),
    )
}

/// Delete a path.
pub(crate) async fn delete(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_delete(c, path),
        |u| crate::infra::file::web_host_delete(path, u),
    )
}

/// Rename/move a path (`to` is the full new path, same scope as `path`).
pub(crate) async fn rename(
    caller: &Caller<'_>,
    path: &str,
    to: &str,
    container: Option<&str>,
) -> Result<(), FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_rename(c, path, to),
        |u| crate::infra::file::web_host_rename(path, to, u),
    )
}

/// Whether a path already exists (upload-conflict detection; no-follow).
pub(crate) async fn exists(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
) -> Result<bool, FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_exists(c, path),
        |u| crate::infra::file::web_host_exists(path, u),
    )
}

/// Write an already-streamed temp file into place (host or container).
pub(crate) async fn write_file(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
    tmp: &std::path::Path,
) -> Result<(), FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_write_file(c, path, tmp),
        |u| crate::infra::file::web_host_write_file(path, tmp, u),
    )
}

/// Open a download stream + suggested filename (host as the caller's user, or a
/// container — admin only). The web boundary wraps the stream in an HTTP body.
pub(crate) async fn read_stream(
    caller: &Caller<'_>,
    path: &str,
    container: Option<&str>,
) -> Result<(String, crate::infra::file::ByteStream), FsError> {
    fs_dispatch!(
        caller,
        container,
        |c| crate::infra::file::web_ctn_read_stream(c, path),
        |u| crate::infra::file::web_host_read_stream(path, u),
    )
}
