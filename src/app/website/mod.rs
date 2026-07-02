//! Website capability — application use-case entry.
//!
//! The web layer dispatches here (never straight into `infra::website`), so the
//! application service layer is the single seam for the website capability:
//! authn/audit live in the web boundary, op routing lives in `dispatch`, per-op
//! command construction in `commands`, and the settings/tuning use-cases in
//! `tuning`. Side-effecting work is delegated to the `infra::website` adapters.

mod commands;
mod dispatch;
mod tuning;

pub(crate) use dispatch::dispatch;
