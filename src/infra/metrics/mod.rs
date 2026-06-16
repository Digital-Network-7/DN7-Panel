use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, System};

mod collect;
mod disks;
mod history;
mod host;

use disks::*;
use host::*;

pub(crate) use collect::*;
pub(crate) use history::{series as history_series, start as history_start};
