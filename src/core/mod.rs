//! Core layer: pure business rules and value objects (the problem domain,
//! independent of any technology). Named `core` (vs `domain`) as the most
//! stable, innermost layer — see `.kiro/steering/architecture.md`.
//!
//! `core` 不懂传输。Nothing here may touch transport (axum), external systems
//! (bollard/reqwest), processes or I/O, and it must not emit front-facing
//! protocol strings. Everything is unit-testable without any runtime.

pub(crate) mod authz;
pub(crate) mod docker;
pub(crate) mod error;
pub(crate) mod identity;
pub(crate) mod path;
pub(crate) mod settings;
pub(crate) mod website;

pub(crate) use error::Error;
