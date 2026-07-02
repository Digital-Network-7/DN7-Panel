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

/// Strict loader for read-modify-write paths. Distinguishes the three outcomes
/// [`load_or_default`] silently collapses into a default:
///
/// - **absent file** → `Ok(None)` (a fresh install has no manifest yet).
/// - **present + parseable** → `Ok(Some(value))`.
/// - **present + UNPARSEABLE** → `Err` — and the bad file is *quarantined* by a
///   best-effort rename to `<name>.corrupt-<unix_ts>` so the real records are
///   preserved for inspection instead of being clobbered by the next save.
///
/// RMW mutators must call this (not [`load_or_default`]) as their base read: a
/// parse error here means "refuse to save" rather than persisting an empty
/// default over live data. Quarantining also lets the *next* save start from a
/// clean path (the corrupt bytes are moved aside, not overwritten in place).
pub(crate) fn load_strict<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        // Genuinely absent → not an error (fresh install); any other I/O error
        // (permissions, etc.) IS surfaced so we don't RMW-default over it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("读取 {} 失败：{e}", path.display())),
    };
    match serde_json::from_str::<T>(&s) {
        Ok(v) => Ok(Some(v)),
        Err(e) => match quarantine_corrupt(path) {
            Some(dest) => Err(anyhow::anyhow!(
                "{} 解析失败，已隔离到 {}：{e}",
                path.display(),
                dest.display()
            )),
            None => Err(anyhow::anyhow!(
                "{} 解析失败（隔离未成功）：{e}",
                path.display()
            )),
        },
    }
}

/// Best-effort: move a corrupt manifest aside to `<name>.corrupt-<unix_ts>` so
/// it's preserved for inspection and the next save writes a fresh file instead
/// of clobbering the bad bytes in place. Returns the destination on success.
/// Also drops any cached entry so a later valid write is observed immediately.
fn quarantine_corrupt(path: &Path) -> Option<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.file_name()?.to_os_string();
    name.push(format!(".corrupt-{ts}"));
    let dest = path.with_file_name(name);
    std::fs::rename(path, &dest).ok()?;
    invalidate_cache(path);
    Some(dest)
}

// ---------------------------------------------------------------------------
// (mtime, len)-validated parse cache
//
// Read-heavy stores (users.json on every authenticated request, website sites /
// access) were re-read + re-parsed from disk per call. Memoize the parsed value
// keyed by the file's (mtime, len). The save helpers (`save_pretty`/
// `save_private`) call `invalidate_cache`, so an **in-process write busts the
// entry immediately** — the cache never depends on mtime resolution for the
// panel's own writes (this is what makes it safe for the auth store: a same-
// length password rotation can't serve a stale verifier). The (mtime, len)
// check is the fallback for **out-of-band edits** only; any such write changes
// at least one of mtime/len on a sub-second-mtime FS (Linux ext4/xfs).
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

/// Cached form of [`load_opt`]: returns `Some(T)` when present + parseable,
/// `None` when absent. A successful parse (incl. a confirmed-absent file) is
/// cached; a torn/corrupt read is not, so it self-heals next call. For types
/// without a `Default` that are read repeatedly during conf generation.
pub(crate) fn load_opt_cached<T>(path: &Path) -> Option<T>
where
    T: DeserializeOwned + Clone + Send + Sync + 'static,
{
    cached_load(path, |c| match c {
        // File present: cache the parse result (Some on success). A parse failure
        // returns None but is NOT cached, so a fixed file is picked up next call.
        Some(s) => match serde_json::from_str::<T>(&s).ok() {
            Some(v) => (Some(v), true),
            None => (None, false),
        },
        // File absent: a stable None worth caching (busted on our own writes).
        None => (None, true),
    })
}

/// Drop any cached entry for `path`. Called by the save helpers so an
/// **in-process** write is reflected immediately — without this the cache would
/// rely on (mtime,len) changing, and a same-length rewrite (e.g. a panel-user
/// password rotation: salt/hash are fixed-length hex) within one coarse mtime
/// tick could otherwise serve the stale value. Out-of-band edits still fall back
/// to the (mtime,len) check.
fn invalidate_cache(path: &Path) {
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(path);
}

/// Persist `value` as pretty JSON, creating the parent directory. For
/// non-secret manifests/config (site lists, access metadata, tuning). Written
/// atomically (temp file + fsync + rename via
/// [`crate::platform::paths::write_public`]) so a crash or a concurrent reader
/// can never observe a torn/half-written file — a corrupt parse here makes
/// `load_or_default` silently return the empty default, which would drop the
/// whole manifest.
pub(crate) fn save_pretty<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let data = serde_json::to_string_pretty(value)?;
    crate::platform::paths::write_public(path, data.as_bytes())?;
    invalidate_cache(path);
    Ok(())
}

/// Persist `value` as pretty JSON with owner-only (0600) permissions from the
/// moment of creation, written atomically (see [`crate::platform::paths::write_private`]).
/// For sensitive files (credentials, tokens, account/instance manifests).
pub(crate) fn save_private<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let data = serde_json::to_string_pretty(value)?;
    crate::platform::paths::write_private(path, data.as_bytes())?;
    invalidate_cache(path);
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

    #[test]
    fn load_opt_cached_present_absent_and_corrupt() {
        let p = std::env::temp_dir().join(format!("dn7-optcache-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        // Absent → None (cached).
        assert_eq!(load_opt_cached::<Vec<i64>>(&p), None);
        // Present → Some, picked up on a length change (busts the cache).
        std::fs::write(&p, "[1,2]").unwrap();
        assert_eq!(load_opt_cached::<Vec<i64>>(&p), Some(vec![1, 2]));
        // Corrupt → None and NOT cached, so a later valid write self-heals.
        std::fs::write(&p, "{ broken").unwrap();
        assert_eq!(load_opt_cached::<Vec<i64>>(&p), None);
        std::fs::write(&p, "[3]").unwrap();
        assert_eq!(load_opt_cached::<Vec<i64>>(&p), Some(vec![3]));
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_strict_absent_present_and_corrupt_quarantine() {
        let p = std::env::temp_dir().join(format!("dn7-strict-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        // Absent → Ok(None) (a fresh install has no manifest; not an error).
        assert!(matches!(load_strict::<Vec<i64>>(&p), Ok(None)));
        // Present + parseable → Ok(Some(value)).
        std::fs::write(&p, "[1,2,3]").unwrap();
        assert_eq!(load_strict::<Vec<i64>>(&p).unwrap(), Some(vec![1, 2, 3]));
        // Present + UNPARSEABLE → Err, and the bad file is quarantined (moved
        // aside), NOT left in place to be clobbered by the next save.
        std::fs::write(&p, "{ not json").unwrap();
        assert!(load_strict::<Vec<i64>>(&p).is_err());
        assert!(
            !p.exists(),
            "corrupt file must be moved aside on quarantine"
        );
        // Exactly one quarantine copy exists, preserving the original bytes.
        let dir = p.parent().unwrap();
        let stem = p.file_name().unwrap().to_string_lossy().to_string();
        let quarantined: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with(&stem) && n.contains(".corrupt-")
            })
            .collect();
        assert_eq!(
            quarantined.len(),
            1,
            "corrupt bytes preserved for inspection"
        );
        assert_eq!(
            std::fs::read_to_string(quarantined[0].path()).unwrap(),
            "{ not json"
        );
        for q in &quarantined {
            let _ = std::fs::remove_file(q.path());
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn strict_rmw_refuses_to_clobber_corrupt_file() {
        // Simulates the RMW mutators (users/sites/access): base-load STRICT, and
        // only save when it parsed. A corrupt file must make the whole op error
        // BEFORE any save, so real records are never overwritten by a default.
        let p = std::env::temp_dir().join(format!("dn7-strictrmw-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, "{ half-restored garbage").unwrap();

        // The mutate shape used by the real stores: strict-load, mutate, save.
        let rmw = |path: &Path| -> anyhow::Result<()> {
            let mut v: Vec<i64> = load_strict(path)?.unwrap_or_default();
            v.push(7); // the "modify"
            save_pretty(path, &v)?; // must NOT be reached on a corrupt base
            Ok(())
        };
        assert!(rmw(&p).is_err(), "RMW must refuse a corrupt base load");

        // The empty default was never written back: the only file the RMW leaves
        // is the quarantine copy holding the original (corrupt) bytes.
        assert!(!p.exists(), "must not resurrect the manifest as a default");
        let dir = p.parent().unwrap();
        let stem = p.file_name().unwrap().to_string_lossy().to_string();
        let quarantined: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with(&stem) && n.contains(".corrupt-")
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(
            std::fs::read_to_string(quarantined[0].path()).unwrap(),
            "{ half-restored garbage"
        );
        for q in &quarantined {
            let _ = std::fs::remove_file(q.path());
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn save_pretty_roundtrips_and_busts_cache() {
        let p = std::env::temp_dir().join(format!("dn7-savepretty-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        // Seed the cache with the on-disk value.
        save_pretty(&p, &vec![1, 2, 3]).unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![1, 2, 3]);
        // A same-length rewrite must still be observed immediately (cache busted
        // by the save helper, not reliant on mtime/len changing).
        save_pretty(&p, &vec![4, 5, 6]).unwrap();
        assert_eq!(load_or_default_cached::<Vec<i64>>(&p), vec![4, 5, 6]);
        // No leftover temp files in the directory (atomic rename cleaned up).
        let dir = p.parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with(".dn7-savepretty") && n.contains(".tmp-")
            })
            .collect();
        assert!(leftovers.is_empty(), "atomic write left a temp file behind");
        let _ = std::fs::remove_file(&p);
    }
}
