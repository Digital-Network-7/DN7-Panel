//! Ports: traits the application layer depends on, implemented by adapters in
//! `web`/`infra`. Grouped by capability submodule (not one big bus file) per
//! steering §5.

pub(crate) mod account;
pub(crate) mod users;
