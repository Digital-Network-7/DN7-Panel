//! The atomic config store — the in-process `nginx -s reload` mechanism.
//!
//! A single process-wide [`ArcSwap`] holds the current [`RuntimeConfig`].
//! Serving a request loads the current `Arc` (cheap, lock-free); a reload builds
//! a fresh config, validates it, and `store`s it. In-flight requests keep their
//! loaded `Arc` until they finish, so a reload never drops a connection — the
//! swap is a single pointer store. A failed build/validate never reaches here,
//! so the previously-serving config stays live (the rollback is "do nothing").

use std::sync::Arc;

use arc_swap::ArcSwap;

use super::config::RuntimeConfig;

/// Process-wide current config. Initialised empty (serves the default-site 404
/// for everything) until the first successful reload publishes a real table.
fn cell() -> &'static ArcSwap<RuntimeConfig> {
    static STORE: std::sync::OnceLock<ArcSwap<RuntimeConfig>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| ArcSwap::from_pointee(RuntimeConfig::default()))
}

/// Load the config a request should serve from. Lock-free; the returned `Arc`
/// stays valid for the whole request even if a reload swaps a new one in.
pub(crate) fn current() -> Arc<RuntimeConfig> {
    cell().load_full()
}

/// Publish a new config atomically. The next request loads it; in-flight ones
/// finish on their old snapshot. This is the zero-downtime reload primitive.
pub(crate) fn publish(cfg: Arc<RuntimeConfig>) {
    cell().store(cfg);
}
