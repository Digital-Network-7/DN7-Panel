//! logrotate (platform host-runtime). Pure assembly; content in `rotate`.

mod rotate;

pub(crate) use rotate::*;
