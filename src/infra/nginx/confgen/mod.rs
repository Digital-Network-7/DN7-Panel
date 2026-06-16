//! nginx config generation (all values pre-validated). Split into cohesive
//! submodules: `files` (server-block assembly + conf writing), `directives`
//! (security/auth directives), `locations` (location-block rendering) and
//! `tuning` (http/server tuning). Parent nginx items are reached via
//! `use super::*`.
use super::*;

mod directives;
mod files;
mod locations;
mod tuning;

pub(crate) use directives::*;
pub(crate) use files::*;
pub(crate) use locations::*;
pub(crate) use tuning::*;
