//! Infrastructure layer: side-effecting adapters + technical support.
//!
//! Per `.kiro/steering/architecture.md`: infra 实现规则,不决定规则。Two kinds
//! live here — **adapters** (external systems: docker/nginx/mysql/system, plus
//! persistence) and **support** (technical helpers). Nothing here may `use`
//! axum or the `web` layer.

pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod crypto;
pub(crate) mod json_store;
pub(crate) mod op_registry;
pub(crate) mod store;
pub(crate) mod system;
