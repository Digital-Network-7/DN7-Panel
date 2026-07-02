//! Failed-version isolation for the self-updater.
//!
//! After a self-update whose new build fails to boot, the supervisor rolls the
//! binary back to the previous version. But the anti-rollback gate in the update
//! engine compares a downloaded binary against the *running* (now old) version,
//! so the SAME bad version still passes `is_newer` on the next auto-check —
//! producing a download → swap → fail → rollback → re-download loop that repeats
//! forever until upstream happens to ship a different version.
//!
//! This module persists a small skiplist (`update.json`) that breaks the loop:
//!   * before a swap, the engine records the target as the pending
//!     [`attempted_version`](super::UpdateState::attempted_version) (so a rollback,
//!     which re-execs the supervisor and loses all in-memory state, can still
//!     learn which version failed);
//!   * on rollback the supervisor moves that pending version onto the
//!     [`failed_versions`](super::UpdateState::failed_versions) list;
//!   * the auto-checker and install path then REFUSE any version on that list.
//!
//! Once a new build boots healthy the pending marker is cleared, so a later,
//! unrelated event can never move a good version onto the skiplist.

use super::{is_newer, parse_semver, UpdateState};

/// Pure skip decision (unit-testable without touching the filesystem): a version
/// is refused if it is in the failed-boot skiplist. Comparison is on the parsed
/// semver so a `v`-prefix or trailing-zero difference (`1.2` vs `1.2.0`) between
/// the recorded and offered strings still matches; unparseable entries fall back
/// to an exact string match so a weird tag can still be skiplisted.
pub(crate) fn is_version_skipped(failed: &[String], version: &str) -> bool {
    let target = parse_semver(version);
    failed.iter().any(|f| match (parse_semver(f), target) {
        (Some(a), Some(b)) => a == b,
        _ => f.trim() == version.trim(),
    })
}

/// Record the version we're about to swap in as the pending attempt, persisting
/// it *before* the rename so a rollback (which re-execs the supervisor) can still
/// learn which version failed even though nothing in memory survives the re-exec.
/// The caller (`install_verified`) has already refused any skiplisted version, so
/// this never records a known-bad one. Best-effort: a save failure only loses the
/// skiplist net, never blocks the update.
pub(crate) fn record_attempted_version(version: &str) {
    let mut st = UpdateState::load();
    st.attempted_version = Some(version.to_string());
    if let Err(e) = st.save() {
        tracing::warn!("could not persist attempted update version {version}: {e}");
    }
}

/// Move the pending [`attempted_version`](super::UpdateState::attempted_version)
/// onto the failed-boot [`failed_versions`](super::UpdateState::failed_versions)
/// skiplist. Called by the supervisor after it rolls a failed update back, so the
/// auto-checker won't re-offer the same broken build. Idempotent and
/// de-duplicating. Returns the version that was skiplisted, if any.
pub fn skiplist_failed_update() -> Option<String> {
    let mut st = UpdateState::load();
    let v = st.attempted_version.take()?;
    if !is_version_skipped(&st.failed_versions, &v) {
        st.failed_versions.push(v.clone());
    }
    if let Err(e) = st.save() {
        tracing::warn!("could not persist failed-update skiplist for {v}: {e}");
        return None;
    }
    Some(v)
}

/// Clear a confirmed-good update's pending attempt marker. Called once the new
/// build boots healthy so a *later*, unrelated event can never move it onto the
/// skiplist. No-op (skips the write) when there's nothing pending.
pub fn clear_attempted_version() {
    let mut st = UpdateState::load();
    if st.attempted_version.is_none() {
        return;
    }
    st.attempted_version = None;
    if let Err(e) = st.save() {
        tracing::warn!("could not clear attempted-update marker: {e}");
    }
}

// ---------------------------------------------------------------------------
// Rollback-state accessors (read by /api/update/status)
// ---------------------------------------------------------------------------

/// The version the last update attempt was rolled back FROM, if the panel is
/// currently running a rolled-back (older) build: the most recently skiplisted
/// version that is still newer than us. `None` once a later build installs
/// healthily (nothing on the list is newer than the running version any more),
/// so the UI banner clears itself without extra state.
pub fn rolled_back_from() -> Option<String> {
    let current = env!("CARGO_PKG_VERSION");
    UpdateState::load()
        .failed_versions
        .iter()
        .rev()
        .find(|v| is_newer(current, v.as_str()))
        .cloned()
}

/// Whether a just-installed update is still awaiting its boot confirmation:
/// the `.prev` rollback backup exists and the boot-ok marker hasn't
/// (re)appeared — the same on-disk state the supervisor keys its one-shot
/// rollback on (`supervise.rs`).
pub fn update_pending_verify() -> bool {
    crate::platform::paths::prev_bin().exists() && !crate::platform::paths::boot_marker().exists()
}

/// The persisted failed-boot skiplist, surfaced so operators can see WHY the
/// checker refuses a version instead of silently never offering it.
pub fn failed_versions() -> Vec<String> {
    UpdateState::load().failed_versions
}

#[cfg(test)]
mod tests {
    use super::is_version_skipped;

    // The failed-version skiplist is the loop-breaker: after a rollback the same
    // bad build still passes `is_newer` against the running old version on every
    // check, so it MUST be refused by version, not by the exact tag string.
    #[test]
    fn skiplist_matches_by_semver_not_exact_string() {
        let failed = vec!["1.2.3".to_string()];
        // Exact match is skipped.
        assert!(is_version_skipped(&failed, "1.2.3"));
        // A `v` prefix or trailing-zero spelling of the same version is skipped
        // too (both parse to the same semver), so a cosmetic tag difference in
        // the offered version can't sneak the broken build back in.
        assert!(is_version_skipped(&failed, "v1.2.3"));
        assert!(is_version_skipped(&["1.2".to_string()], "1.2.0"));
        // A different version is NOT skipped — a genuine upstream fix installs.
        assert!(!is_version_skipped(&failed, "1.2.4"));
        assert!(!is_version_skipped(&failed, "1.3.0"));
        // An empty skiplist skips nothing.
        assert!(!is_version_skipped(&[], "1.2.3"));
    }

    // A weird/unparseable tag must still be skiplistable by exact string, so a
    // non-semver release that failed to boot doesn't loop either.
    #[test]
    fn skiplist_falls_back_to_exact_match_for_unparseable_tags() {
        let failed = vec!["nightly-broken".to_string()];
        assert!(is_version_skipped(&failed, "nightly-broken"));
        assert!(is_version_skipped(&failed, "  nightly-broken  "));
        assert!(!is_version_skipped(&failed, "nightly-fixed"));
    }
}
