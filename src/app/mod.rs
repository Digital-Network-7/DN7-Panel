//! Application layer: use-cases (one explicit entry point each) + the ports
//! they depend on.
//!
//! Per `.kiro/steering/architecture.md`: app orchestrates domain + ports; it
//! must not depend on the web/delivery layer or on external systems directly
//! (those are reached through ports, implemented by adapters in `web`/`infra`).
//! Ports are introduced only where a use-case needs an external side effect
//! that we also want to mock in tests (see §5).

pub(crate) mod account;
pub(crate) mod docker;
pub(crate) mod mysql;
pub(crate) mod nginx;
pub(crate) mod ports;
pub(crate) mod users;
