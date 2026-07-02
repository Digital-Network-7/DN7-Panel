//! HTTP controllers (≈ Laravel `app/Http/Controllers`): the request handlers.
//! Each controller owns one capability's endpoints; the shared state, identity
//! and error helpers live in the parent `http` kernel (reached via
//! `use super::super::*`). Handlers are re-exported here so the `routes` table
//! can bind them.

mod account_controller;
mod assets_controller;
mod audit_controller;
mod branding_controller;
mod capability_controller;
mod files_controller;
mod login_controller;
mod monitor_controller;
mod settings_controller;
mod terminal_controller;
mod update_controller;
mod users_controller;

pub(crate) use account_controller::*;
pub(crate) use assets_controller::*;
pub(crate) use audit_controller::*;
pub(crate) use branding_controller::*;
pub(crate) use capability_controller::*;
pub(crate) use files_controller::*;
pub(crate) use login_controller::*;
pub(crate) use monitor_controller::*;
pub(crate) use settings_controller::*;
pub(crate) use terminal_controller::*;
pub(crate) use update_controller::*;
pub(crate) use users_controller::*;
