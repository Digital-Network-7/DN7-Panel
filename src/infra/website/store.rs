//! Access-list + global website settings store: a pure persistence adapter
//! (JSON load/save + path helpers + id generation). The auth-hash crypto lives
//! in `htpasswd` and the size/value validators in `validate`.
use super::*;

// Access-list store + global website settings.
// ---------------------------------------------------------------------------

pub(crate) fn access_file() -> std::path::PathBuf {
    base_dir().join("access.json")
}
pub(crate) fn websettings_file() -> std::path::PathBuf {
    base_dir().join("websettings.json")
}

pub(crate) fn load_access() -> Vec<AccessList> {
    // Cached (mtime+len-validated): read during conf generation + access checks.
    crate::infra::support::json_store::load_or_default_cached(&access_file())
}
/// Strict load for the read-modify-write path: `Err` (and the bad file is
/// quarantined) when access.json is present but unparseable, so a save/delete
/// REFUSES to clobber the manifest with an empty default. `Ok(Vec::new())` only
/// when the file is genuinely absent.
pub(crate) fn load_access_strict() -> Result<Vec<AccessList>> {
    Ok(crate::infra::support::json_store::load_strict(&access_file())?.unwrap_or_default())
}
pub(crate) fn save_access(lists: &[AccessList]) -> Result<()> {
    crate::infra::support::json_store::save_pretty(&access_file(), lists)
}
pub(crate) fn load_webglobal() -> WebGlobal {
    // Cached: read per site during conf generation (default-site + resync loops).
    crate::infra::support::json_store::load_or_default_cached(&websettings_file())
}
/// Strict load for the default-site read-modify-write path: `Err` (and the bad
/// file is quarantined) when websettings.json is present but unparseable, so the
/// apply refuses to overwrite it with a default. `Ok(None)` when genuinely absent.
pub(crate) fn load_webglobal_strict() -> Result<Option<WebGlobal>> {
    crate::infra::support::json_store::load_strict(&websettings_file())
}
pub(crate) fn save_webglobal(g: &WebGlobal) -> Result<()> {
    crate::infra::support::json_store::save_pretty(&websettings_file(), g)
}

pub(crate) fn webtuning_file() -> std::path::PathBuf {
    base_dir().join("webtuning.json")
}
/// Load tuning, or `None` when never configured (so we don't override the
/// distro's http defaults on managed sites until the operator opts in).
pub(crate) fn load_tuning_opt() -> Option<HttpTuning> {
    // Cached: render_tuning_block reads this once per site, inside the N-site
    // resync / rewrite loops — an uncached re-parse per site was O(N) disk reads.
    crate::infra::support::json_store::load_opt_cached(&webtuning_file())
}
pub(crate) fn save_tuning(t: &HttpTuning) -> Result<()> {
    crate::infra::support::json_store::save_pretty(&webtuning_file(), t)
}

/// An access-list id (random, filesystem-safe).
pub(crate) fn new_access_id() -> String {
    format!("al{:08x}", rand::random::<u32>())
}
