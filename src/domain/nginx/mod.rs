//! Nginx domain: persisted entities (Site/Location/AccessList/…), the typed
//! capability error, pure input validators, and the tuning / default-site
//! rules — each in a cohesive submodule. The public surface is re-exported so
//! callers keep using `crate::domain::nginx::*`.

mod error;
mod model;
mod tuning;
mod validate;

pub(crate) use error::*;
pub(crate) use model::*;
pub(crate) use tuning::*;
pub(crate) use validate::*;
