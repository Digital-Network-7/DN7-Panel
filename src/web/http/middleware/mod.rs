//! HTTP middleware (≈ Laravel `app/Http/Middleware`): the safe-entry gate and
//! the defensive security-header layer. The entry-gate also binds the
//! per-request audit context (client IP + redacted headers).

mod gate;
mod headers;

pub(crate) use gate::*;
pub(crate) use headers::*;
