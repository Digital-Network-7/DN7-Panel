//! Small shared helpers for the panel's JSON manifest / state files.
//!
//! Every subsystem used to inline the same read-parse-default and
//! create-dir-then-write-pretty boilerplate. These four helpers give one place
//! for that I/O, and `save_private` routes sensitive files through the atomic
//! 0600 [`crate::platform::paths::write_private`] primitive (no create-then-chmod window).

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;

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
