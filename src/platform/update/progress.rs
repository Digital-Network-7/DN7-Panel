//! Global self-update progress state + the single-runner mutual-exclusion guard.
//!
//! The phase/progress/byte counters are process-global atomics read by the UI via
//! `/api/update/status` and written by the engine as an update runs. The
//! `InProgressGuard` is the one gate that keeps two concurrent updates from both
//! starting (see the apply handler + [`try_begin_guard`]).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

pub const PHASE_IDLE: u8 = 0;
pub const PHASE_CHECKING: u8 = 1;
pub const PHASE_DOWNLOADING: u8 = 2;
pub const PHASE_INSTALLING: u8 = 3;
pub const PHASE_ERROR: u8 = 4;

/// Exit code the panel uses after a successful self-update, signalling the
/// supervisor to re-exec itself immediately (single combined restart) instead
/// of respawning the panel and re-exec'ing a version_check interval later.
pub const EXIT_UPDATED: i32 = 77;

static PHASE: AtomicU8 = AtomicU8::new(PHASE_IDLE);
static PROGRESS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
static DONE_BYTES: AtomicU64 = AtomicU64::new(0);
static IN_PROGRESS: AtomicBool = AtomicBool::new(false);

pub fn phase() -> u8 {
    PHASE.load(Ordering::Relaxed)
}
pub fn progress() -> u64 {
    PROGRESS.load(Ordering::Relaxed)
}
pub fn total_bytes() -> u64 {
    TOTAL_BYTES.load(Ordering::Relaxed)
}
pub fn done_bytes() -> u64 {
    DONE_BYTES.load(Ordering::Relaxed)
}
pub fn phase_str() -> &'static str {
    match phase() {
        PHASE_CHECKING => "checking",
        PHASE_DOWNLOADING => "downloading",
        PHASE_INSTALLING => "installing",
        PHASE_ERROR => "error",
        _ => "idle",
    }
}
pub(crate) fn set_phase(p: u8) {
    PHASE.store(p, Ordering::Relaxed);
}
pub(crate) fn set_progress(pct: u64) {
    PROGRESS.store(pct.min(100), Ordering::Relaxed);
}
pub fn set_bytes(done: u64, total: u64) {
    DONE_BYTES.store(done, Ordering::Relaxed);
    TOTAL_BYTES.store(total, Ordering::Relaxed);
}
fn end() {
    IN_PROGRESS.store(false, Ordering::SeqCst);
}
pub fn in_progress() -> bool {
    IN_PROGRESS.load(Ordering::SeqCst)
}

/// RAII guard proving this task holds the single in-progress slot. Obtained via
/// [`try_begin_guard`]; its `Drop` releases the slot on **every** exit path
/// (success, error, panic), so an owned runner can never leak the flag. The
/// success path `std::process::exit`s before Drop runs, which is fine — the
/// process is going away, so the slot doesn't need releasing.
pub struct InProgressGuard {
    _private: (),
}

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        end();
    }
}

/// Atomically claim the in-progress slot, returning an RAII guard on success or
/// `None` if an update is already running. This is the single point of mutual
/// exclusion: callers must hold the returned guard for the whole update and let
/// it drop to release the slot.
pub fn try_begin_guard() -> Option<InProgressGuard> {
    IN_PROGRESS
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
        .then_some(InProgressGuard { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The apply handler relies on `try_begin_guard` being the single point of
    // mutual exclusion: exactly one caller may hold the slot, and dropping the
    // guard must release it (RAII) so a later attempt can succeed. This is the
    // invariant that stops two concurrent /api/update/apply requests from both
    // reporting `started: true`.
    #[test]
    fn guard_is_exclusive_and_released_on_drop() {
        // NOTE: touches the process-global IN_PROGRESS flag; keep this the only
        // test that does so to avoid cross-test interference.
        let g = try_begin_guard().expect("first claim succeeds");
        assert!(in_progress(), "slot is held while the guard is alive");
        assert!(
            try_begin_guard().is_none(),
            "a second claim is rejected while the guard is held"
        );
        drop(g);
        assert!(!in_progress(), "dropping the guard releases the slot");

        // A fresh claim works again now that the slot is free.
        let g2 = try_begin_guard().expect("re-claim after release succeeds");
        drop(g2);
        assert!(!in_progress());
    }
}
