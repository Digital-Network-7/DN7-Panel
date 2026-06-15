//! Domain layer: pure business rules and value objects.
//!
//! Per `.kiro/steering/architecture.md`: domain 不懂传输。Nothing here may touch
//! transport (axum), external systems (bollard/reqwest), processes or I/O, and
//! it must not emit front-facing protocol strings. Everything is unit-testable
//! without any runtime.

pub(crate) mod authz;
pub(crate) mod docker;
pub(crate) mod error;
pub(crate) mod identity;
pub(crate) mod mysql;
pub(crate) mod nginx;
pub(crate) mod settings;

pub(crate) use error::Error;
