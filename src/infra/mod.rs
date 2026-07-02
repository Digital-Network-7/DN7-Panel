//! Infrastructure layer: side-effecting adapters + technical support.
//!
//! Per `.kiro/steering/architecture.md`: infra 实现规则,不决定规则。Two kinds
//! live here — **adapters** (external systems: docker/website/system, plus
//! persistence) and **support** (technical helpers). Nothing here may `use`
//! axum or the `web` layer.

pub(crate) mod auth;
pub(crate) mod docker;
pub(crate) mod file;
pub(crate) mod metrics;
pub(crate) mod store;
pub(crate) mod support;
pub(crate) mod system;
pub(crate) mod website;
