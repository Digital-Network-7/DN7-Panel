//! Self-update: fastest-line download, atomic binary replacement, and the
//! persisted update preferences that drive it.
//!
//! There is a single binary that runs as either role, so one self-update covers
//! both: fetch the latest binary (see `fetch`), atomically replace the running
//! executable at the stable install path, and exit so the supervisor relaunches
//! it on the new version.
//!
//! There is no user-visible source choice: every request races the mirror lines
//! (github direct + proxies) and uses whichever responds fastest, and a download
//! failure fails over to the next-fastest line (see `fetch`).

use crate::infra::support::fetch;
use crate::platform::config::PanelConfig;
use serde::Serialize;

mod changelog;
mod engine;
mod skiplist;

pub(crate) use changelog::*;
pub(crate) use engine::*;
pub(crate) use skiplist::*;
