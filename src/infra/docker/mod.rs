//! On-box Docker management for the web console.
//!
//! A request/response JSON protocol backed by the local Docker daemon (bollard,
//! no `docker` CLI). Reached from the web boundary via `app::docker::dispatch`
//! (web → app → infra). Pure assembly: the request DTOs + daemon client live in
//! `model`, the authoritative per-op match + guards in `dispatch`, and each op
//! area is a submodule (containers/images/networks/volumes/create/…). Shared
//! structs are re-exported so descendant submodules reference them via
//! `use super::*` unchanged.
//!
//! Operations are a fixed whitelist (no arbitrary command pass-through);
//! user-supplied values are passed as separate argv entries, never interpolated
//! into a shell, so there's no injection surface. Long-running ops (image
//! pulls, Docker install) run detached in a process-global registry.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bollard::Docker;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::core::docker::{net_driver_allowed, restart_allowed, DockerError};

mod backups;
mod containers;
mod create;
mod dispatch;
mod images;
mod info;
mod install;
mod lifecycle;
mod model;
mod networks;
mod opreg;
mod pull;
mod settings;
mod validate;
mod volumes;

pub use backups::*;
pub(crate) use containers::container_is_privileged;
use containers::*;
use create::*;
use images::*;
use info::*;
use install::*;
use lifecycle::*;
use networks::*;
use opreg::*;
use pull::*;
use settings::*;
use validate::*;
use volumes::*;

pub(crate) use dispatch::*;
pub(crate) use model::*;

#[cfg(test)]
mod tests;
