//! Small shared helpers for the panel's JSON manifest / state files.
//!
//! Every subsystem used to inline the same read-parse-default and
//! create-dir-then-write-pretty boilerplate. These four helpers give one place
//! for that I/O, and `save_private` routes sensitive files through the atomic
//! 0600 [`crate::platform::paths::write_private`] primitive (no create-then-chmod window).

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

/// Load + parse a JSON file, returning `T::default()` on any error (missing
/// file or parse failure). For manifests/state with a sensible empty default.
pub(crate) fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Load + parse a JSON file, returning `None` when absent/corrupt.
pub(crate) fn load_opt<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

// ---------------------------------------------------------------------------
// (mtime, len)-validated parse cache
//
// Read-heavy stores (users.json on every authenticated request, nginx sites /
// access, settings) were re-read + re-parsed from disk per call. Memoize the
// parsed value keyed by the file's (mtime, len): any write changes at least one
// of them, so the cache can never serve a value older than what's on disk —
// safe even for the auth store and for out-of-band edits. Assumes the host FS
// reports sub-second mtime (Linux ext4/xfs do) and that writes to a given store
// are serialized (they are: USERS_LOCK / nginx state_lock / atomic write_private).
// A failed/torn parse is returned but NOT cached, so it self-heals on the next
// call rather than sticking an empty/default value.
// ---------------------------------------------------------------------------

struct CacheEntry {
    mtime: Option<SystemTime>,
    len: u64,
    value: Arc<dyn Any + Send + Sync>,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, CacheEntry>> {
    static C: OnceLock<Mutex<HashMap<PathBuf, CacheEntry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Core of the cached loaders. `parse` maps the file contents (None when
/// absent/unreadable) to `(value, cache_it)`; `cache_it=false` skips caching so
/// a failed/torn read is retried next time.
fn cached_load<R>(path: &Path, parse: impl FnOnce(Option<String>) -> (R, bool)) -> R
where
    R: Clone + Send + Sync + 'static,
{
    let meta = std::fs::metadata(path).ok();
    let mtime = meta.as_ref().and_then(|m| m.modified().ok());
    let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    {
        let c = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = c.get(path) {
            if e.mtime == mtime && e.len == len {
                if let Some(v) = e.value.downcast_ref::<R>() {
                    return v.clone();
                }
            }
        }
    }
    let (value, cache_it) = parse(std::fs::read_to_string(path).ok());
    if cache_it {
        let arc: Arc<dyn Any + Send + Sync> = Arc::new(value.clone());
        cache().lock().unwrap_or_else(|e| e.into_inner()).insert(
            path.to_path_buf(),
            CacheEntry {
                mtime,
                len,
                value: arc,
            },
        );
    }
    value
}

/// Cached form of [`load_or_default`] (see the cache module comment).
pub(crate) fn load_or_default_cached<T>(path: &Path) -> T
where
    T: DeserializeOwned + Default + Clone + Send + Sync + 'static,
{
    cached_load(path, |c| {
        match c.and_then(|s| serde_json::from_str::<T>(&s).ok()) {
            Some(v) => (v, true),
            None => (T::default(), false), // absent/corrupt: don't cache the default
        }
    })
}

/// Persist `value` as pretty JSON, creating the parent directory. For
/// non-secret manifests/config (site lists, access metadata, tuning).
pub(crate) fn save_pretty<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

/// Persist `value` as pretty JSON with owner-only (0600) permissions from the
/// moment of creation, written atomically (see [`crate::platform::paths::write_private`]).
/// For sensitive files (credentials, tokens, account/instance manifests).
pub(crate) fn save_private<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let data = serde_json::to_string_pretty(value)?;
    crate::platform::paths::write_private(path, data.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_load_reflects_rewrites() {
        let p = std::env::temp_dir().join(format!("dn7-jsoncache-{}.json", std::process::id()));
        // Absent file -> default, not cached.
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), Vec::<i64>::new());
        // Write a value; a load picks it up and caches it.
        std::fs::write(&p, "[1,2,3]").unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![1, 2, 3]);
        // A second load returns the same (cache hit).
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![1, 2, 3]);
        // Rewrite with a different length -> (mtime,len) changes -> cache refreshes.
        std::fs::write(&p, "[9]").unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![9]);
        // A torn/corrupt read returns the default but is NOT cached, so a
        // subsequent valid read still self-heals.
        std::fs::write(&p, "{ not json").unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), Vec::<i64>::new());
        std::fs::write(&p, "[7,7]").unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![7, 7]);
        let _ = std::fs::remove_file(&p);
    }
}
