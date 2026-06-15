//! Persistence adapters: pure JSON load/save of domain entities. No business
//! rules, no transport — see `.kiro/steering/architecture.md`.

pub(crate) mod settings;
pub(crate) mod users;
