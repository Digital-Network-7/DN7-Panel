//! Infra **support**: technical helpers (not external-system adapters).
//!
//! Per `.kiro/steering/architecture.md`: infra has two kinds of module —
//! *adapters* (docker/nginx/mysql/system/file/store/metrics, which talk to an
//! external system) and *support* (crypto/json_store/op_registry/audit/totp/
//! totp/fetch). Support modules are pure technical machinery used by the
//! adapters; they build no ports. Grouping them here keeps the `infra/` root a
//! clean list of directories.

pub(crate) mod audit;
pub(crate) mod crypto;
pub(crate) mod fetch;
pub(crate) mod json_store;
pub(crate) mod op_registry;
pub(crate) mod totp;
