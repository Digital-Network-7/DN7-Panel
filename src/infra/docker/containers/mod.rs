//! Container operations: listing, inspect, log tailing, lifecycle actions, and
//! shell-availability probing. Split from the former single containers.rs into
//! cohesive submodules; the docker parent items are reached via `use super::*`.
use super::*;

mod actions;
mod inspect;
mod list;
mod logs;
mod shell;

pub(crate) use actions::*;
pub(crate) use inspect::*;
pub(crate) use list::*;
pub(crate) use logs::*;
pub(crate) use shell::*;
