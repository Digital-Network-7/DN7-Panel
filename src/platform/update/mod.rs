//! Self-update: dual-source download, atomic binary replacement, and the
//! persisted update preferences that drive it.
//!
//! There is a single binary that runs as either role, so one self-update covers
//! both: fetch the latest binary (see `fetch`), atomically replace the running
//! executable at the stable install path, and exit so the supervisor relaunches
//! it on the new version.
//!
//! Source selection (GitHub vs dn7.cn) is sticky: an explicit preference is
//! honoured; otherwise a remembered probe winner is reused for a week, and a
//! download failure fails over to the other source (forcing a re-probe).

use crate::infra::support::fetch::{self, SourceKind};
use crate::platform::config::PanelConfig;
use serde::Serialize;

mod changelog;
mod engine;

pub(crate) use changelog::*;
pub(crate) use engine::*;
