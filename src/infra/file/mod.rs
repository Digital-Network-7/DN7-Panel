//! On-box file transfer for the web console.
//!
//! Plain request/response operations (list / mkdir / delete / download /
//! upload) against the host filesystem and inside Docker containers (via the
//! daemon archive + exec APIs — no `docker` CLI). Used directly by
//! `web::server`; there is no backend relay.

use std::path::Path;
use std::pin::Pin;

use anyhow::{anyhow, Result};
use bytes::Bytes;

// The sensitive-path guards normalize first via the shared core rule (a raw
// prefix match is bypassable by `//etc`, `/./etc`, `/srv/../etc`).
use crate::core::path::normalize_lexical;

mod ctn;
mod ctnfs;
mod hostfs;
mod ops;

use ctn::*;
pub(crate) use ctnfs::*;
pub(crate) use hostfs::*;
pub(crate) use ops::*;
