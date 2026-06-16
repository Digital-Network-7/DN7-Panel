//! MySQL instance lifecycle: install / remove / change_port / switch_version.
//! Pure assembly — install + shared specs/helpers in `install`; `databases` and
//! `lifecycle` are the sibling areas.
use super::*;

mod databases;
mod install;
mod lifecycle;

pub(crate) use databases::*;
pub(crate) use install::*;
pub(crate) use lifecycle::*;
