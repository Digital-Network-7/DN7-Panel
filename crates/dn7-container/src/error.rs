//! Error type for the runtime. One enum, `thiserror`-derived, so every failure
//! path carries context (which syscall / which path) rather than a bare errno.

use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("syscall {call} failed: {source}")]
    Syscall {
        call: &'static str,
        #[source]
        source: nix::Error,
    },

    #[error("invalid OCI bundle: {0}")]
    Bundle(String),

    #[error("invalid config.json: {0}")]
    Config(String),

    #[error("container {0} already exists")]
    Exists(String),

    #[error("container {0} not found")]
    NotFound(String),

    #[error("container {id} is in state {state}, cannot {action}")]
    BadState {
        id: String,
        state: &'static str,
        action: &'static str,
    },

    #[error("cgroup v2 unavailable: {0}")]
    NoCgroupV2(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Wrap a `nix::Error` with the name of the syscall that produced it.
    pub(crate) fn sys(call: &'static str) -> impl FnOnce(nix::Error) -> Error {
        move |source| Error::Syscall { call, source }
    }

    /// Wrap a `std::io::Error` with the path it concerns.
    pub(crate) fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
        let path = path.into();
        move |source| Error::Io { path, source }
    }
}
