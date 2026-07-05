//! Failed-version isolation for the self-updater.
//!
//! After a self-update whose new build fails to boot, the supervisor rolls the
//! binary back to the previous build. But the anti-rollback gate in the update
//! engine compares a downloaded binary against the *running* (now old) build, so
//! the SAME bad build still passes the (version, build) gate on the next
//! auto-check — producing a download → swap → fail → rollback → re-download loop
//! that repeats forever until upstream ships a different build. Entries are keyed
//! by (version, build) so a bad build 2 is skipped without blacklisting a later
//! good build 3 of the same version.
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

use super::{current_build, is_newer_build, parse_semver, UpdateState};

/// Skiplist identity for a release: `"<version>+<build>"` (e.g. `"27.0.0+2"`).
/// Persisted in `attempted_version` / `failed_versions` so the loop-breaker is
/// build-specific — a failed build 2 must NOT blacklist a future good build 3 of
/// the same version.
pub(crate) fn release_ident(version: &str, build: u64) -> String {
    format!("{}+{build}", version.trim())
}

/// Split a stored identity back into `(version, build)`. A legacy bare-version
/// entry (no `+build` suffix, from before builds were tracked) reads as build 0.
fn split_ident(s: &str) -> (&str, u64) {
    match s.trim().rsplit_once('+') {
        Some((v, b)) => (v.trim(), b.trim().parse().unwrap_or(0)),
        None => (s.trim(), 0),
    }
}

/// Pure skip decision (unit-testable without touching the filesystem): the release
/// `(version, build)` is refused if it matches an entry in the failed-boot
/// skiplist. The version is compared on the parsed semver (so a `v`-prefix or
/// `1.2` vs `1.2.0` still matches) AND the build number must be equal; an
/// unparseable version falls back to an exact string match.
pub(crate) fn is_version_skipped(failed: &[String], version: &str, build: u64) -> bool {
    let target = parse_semver(version);
    failed.iter().any(|f| {
        let (fv, fb) = split_ident(f);
        fb == build
            && match (parse_semver(fv), target) {
                (Some(a), Some(b)) => a == b,
                _ => fv == version.trim(),
            }
    })
}

/// Record the release we're about to swap in as the pending attempt, persisting
/// it *before* the rename so a rollback (which re-execs the supervisor) can still
/// learn which build failed even though nothing in memory survives the re-exec.
/// The caller (`install_verified`) has already refused any skiplisted build, so
/// this never records a known-bad one. Best-effort: a save failure only loses the
/// skiplist net, never blocks the update.
pub(crate) fn record_attempted_release(version: &str, build: u64) {
    let ident = release_ident(version, build);
    let mut st = UpdateState::load();
    st.attempted_version = Some(ident.clone());
    if let Err(e) = st.save() {
        tracing::warn!("could not persist attempted update {ident}: {e}");
    }
}

/// Move the pending [`attempted_version`](super::UpdateState::attempted_version)
/// onto the failed-boot [`failed_versions`](super::UpdateState::failed_versions)
/// skiplist. Called by the supervisor after it rolls a failed update back, so the
/// auto-checker won't re-offer the same broken build. Idempotent and
/// de-duplicating. Returns the version that was skiplisted, if any.
pub fn skiplist_failed_update() -> Option<String> {
    let mut st = UpdateState::load();
    let v = st.attempted_version.take()?; // an identity "<version>+<build>"
    let (ver, build) = split_ident(&v);
    if !is_version_skipped(&st.failed_versions, ver, build) {
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
    let cur_build = current_build();
    UpdateState::load()
        .failed_versions
        .iter()
        .rev()
        .map(|f| split_ident(f))
        .find(|(v, b)| is_newer_build(current, cur_build, v, *b))
        .map(|(v, b)| {
            if b > 0 {
                format!("{v} (build {b})")
            } else {
                v.to_string()
            }
        })
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
    use super::{is_version_skipped, release_ident};

    // The skiplist is the loop-breaker: after a rollback the same bad build still
    // passes the (version, build) gate against the running old build on every
    // check, so it MUST be refused by (version, build) — matching the version by
    // semver (not exact string) but requiring the build to be equal.
    #[test]
    fn skiplist_matches_by_semver_and_build() {
        let failed = vec![release_ident("1.2.3", 5)]; // "1.2.3+5"
                                                      // Same version + same build is skipped, tolerant of a `v` prefix / spelling.
        assert!(is_version_skipped(&failed, "1.2.3", 5));
        assert!(is_version_skipped(&failed, "v1.2.3", 5));
        assert!(is_version_skipped(&[release_ident("1.2", 5)], "1.2.0", 5));
        // Same version, DIFFERENT build is NOT skipped — a fixed build installs.
        assert!(!is_version_skipped(&failed, "1.2.3", 6));
        // A different version is NOT skipped.
        assert!(!is_version_skipped(&failed, "1.2.4", 5));
        assert!(!is_version_skipped(&failed, "1.3.0", 5));
        // A legacy bare-version entry (pre-build era) reads as build 0.
        assert!(is_version_skipped(&["1.2.3".to_string()], "1.2.3", 0));
        assert!(!is_version_skipped(&["1.2.3".to_string()], "1.2.3", 2));
        // An empty skiplist skips nothing.
        assert!(!is_version_skipped(&[], "1.2.3", 1));
    }

    // A weird/unparseable version must still be skiplistable by exact string (+
    // build), so a non-semver release that failed to boot doesn't loop either.
    #[test]
    fn skiplist_falls_back_to_exact_match_for_unparseable_versions() {
        let failed = vec![release_ident("nightly-broken", 0)];
        assert!(is_version_skipped(&failed, "nightly-broken", 0));
        assert!(is_version_skipped(&failed, "  nightly-broken  ", 0));
        assert!(!is_version_skipped(&failed, "nightly-fixed", 0));
    }
}
