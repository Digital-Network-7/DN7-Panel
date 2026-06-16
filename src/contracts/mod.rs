//! Contracts layer: the single source of truth for the **external** protocol —
//! the request/response DTOs and command models the web boundary parses and the
//! `app` use-cases consume.
//!
//! Per `.kiro/steering/architecture.md` §2: contracts may reference `domain`
//! base types, but must NOT depend on `app` / `infra` / `web`, and must not
//! carry derived business rules (that's `domain`). This keeps the wire protocol
//! out of both the handlers and the infra adapters, so it can evolve in one
//! place. Capabilities are migrated here incrementally (nginx first).

pub(crate) mod nginx;
