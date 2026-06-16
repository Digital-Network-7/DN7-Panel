//! Release-notes changelog (merge + cache) (split from update.rs).
use super::*;

// ---------------------------------------------------------------------------
// Changelog (release notes between current and latest)
// ---------------------------------------------------------------------------

/// "What's new" for the update UI: the release notes for every published
/// version (current and past), newest first, so users can browse the full
/// history regardless of whether an update is pending.
#[derive(Debug, Serialize)]
pub struct ChangelogResult {
    pub current: String,
    pub entries: Vec<fetch::ReleaseNote>,
}

/// Build the changelog from a process-lifetime merge cache. Behaviour:
///   * the parsed release index is cached and reused within a freshness window
///     so re-opening "what's new" doesn't refetch every time;
///   * entries are merged by version, and a version's notes are NEVER
///     overwritten with an empty list — so once notes are seen (from either
///     source) they stick;
///   * if any cached version still has blank notes, the cache is considered
///     incomplete and a refetch (preferred source, then the other to backfill)
///     is attempted on the next call after a short retry interval.
pub async fn changelog(cfg: &PanelConfig) -> ChangelogResult {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // Decide whether to (re)fetch.
    const FRESH_TTL: u64 = 600; // 10 min: a complete cache is reused as-is
    const RETRY_TTL: u64 = 45; // re-attempt backfill of blank notes this often
    let now = now_secs();
    let (have, fresh, blank, last) = {
        let c = changelog_cache().lock().unwrap_or_else(|p| p.into_inner());
        let blank = c.by_version.values().any(|n| n.notes.is_empty());
        (
            !c.by_version.is_empty(),
            now.saturating_sub(c.fetched_at) < FRESH_TTL,
            blank,
            c.fetched_at,
        )
    };
    let need_fetch = !have || !fresh || (blank && now.saturating_sub(last) >= RETRY_TTL);

    if need_fetch {
        let st = UpdateState::load();
        let prefer = SourceKind::from_str(&st.source_pref)
            .or_else(|| st.chosen.as_deref().and_then(SourceKind::from_str))
            .unwrap_or(SourceKind::Github);
        let mut got_any = false;
        if let Ok(list) = fetch::releases_index_from(cfg, prefer).await {
            got_any |= !list.is_empty();
            merge_changelog(list);
        }
        // If any version still lacks notes, try the other source to backfill.
        if changelog_has_blank() {
            if let Ok(list) = fetch::releases_index_from(cfg, prefer.other()).await {
                got_any |= !list.is_empty();
                merge_changelog(list);
            }
        }
        if got_any {
            changelog_cache()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .fetched_at = now;
        }
    }

    // Emit the merged set, newest-first, capped to the 10 most recent versions.
    let mut entries: Vec<fetch::ReleaseNote> = {
        let c = changelog_cache().lock().unwrap_or_else(|p| p.into_inner());
        c.by_version.values().cloned().collect()
    };
    entries.sort_by_key(|e| std::cmp::Reverse(parse_semver(&e.version).unwrap_or((0, 0, 0))));
    entries.truncate(10);
    // A version with no fetched release notes shows a neutral English summary
    // rather than an empty "(no release notes)" placeholder.
    for e in &mut entries {
        if e.notes.is_empty() {
            e.notes = vec![
                "Routine maintenance: stability, performance and security improvements."
                    .to_string(),
            ];
        }
    }
    ChangelogResult { current, entries }
}

/// Process-lifetime changelog cache: version -> note, plus the last fetch time.
#[derive(Default)]
pub(crate) struct ChangelogCache {
    by_version: std::collections::HashMap<String, fetch::ReleaseNote>,
    fetched_at: u64,
}

pub(crate) fn changelog_cache() -> &'static std::sync::Mutex<ChangelogCache> {
    static C: std::sync::OnceLock<std::sync::Mutex<ChangelogCache>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(ChangelogCache::default()))
}

/// Merge a freshly-fetched index into the cache. A version's notes are replaced
/// only when the incoming notes are non-empty (so a blank fetch never erases
/// notes we already have); a new version is inserted as-is.
pub(crate) fn merge_changelog(list: Vec<fetch::ReleaseNote>) {
    let mut c = changelog_cache().lock().unwrap_or_else(|p| p.into_inner());
    for note in list {
        match c.by_version.get_mut(&note.version) {
            Some(existing) => {
                if !note.notes.is_empty() {
                    existing.notes = note.notes;
                }
                if !note.date.is_empty() {
                    existing.date = note.date;
                }
            }
            None => {
                c.by_version.insert(note.version.clone(), note);
            }
        }
    }
}

/// Whether any cached version still has empty notes (cache incomplete).
pub(crate) fn changelog_has_blank() -> bool {
    changelog_cache()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .by_version
        .values()
        .any(|n| n.notes.is_empty())
}
