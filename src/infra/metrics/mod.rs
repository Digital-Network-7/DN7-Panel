use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, System};

mod collect;
mod disks;
mod host;

use disks::*;
use host::*;

pub(crate) use collect::*;
