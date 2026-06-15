//! Access-list + global website settings store: a pure persistence adapter
//! (JSON load/save + path helpers + id generation). The auth-file crypto lives
//! in `htpasswd`, the http-tuning config rendering in `confgen`, and the
//! size/value validators in `validate`.
use super::*;

// Access-list store + global website settings.
// ---------------------------------------------------------------------------

pub(crate) fn access_file() -> std::path::PathBuf {
    base_dir().join("access.json")
}
pub(crate) fn access_dir() -> std::path::PathBuf {
    base_dir().join("access")
}
pub(crate) fn websettings_file() -> std::path::PathBuf {
    base_dir().join("websettings.json")
}

pub(crate) fn load_access() -> Vec<AccessList> {
    crate::json_store::load_or_default(&access_file())
}
pub(crate) fn save_access(lists: &[AccessList]) -> Result<()> {
    crate::json_store::save_pretty(&access_file(), lists)
}
pub(crate) fn load_webglobal() -> WebGlobal {
    crate::json_store::load_or_default(&websettings_file())
}
pub(crate) fn save_webglobal(g: &WebGlobal) -> Result<()> {
    crate::json_store::save_pretty(&websettings_file(), g)
}

pub(crate) fn webtuning_file() -> std::path::PathBuf {
    base_dir().join("webtuning.json")
}
/// Load tuning, or `None` when never configured (so we don't override the
/// distro's http defaults on managed sites until the operator opts in).
pub(crate) fn load_tuning_opt() -> Option<HttpTuning> {
    crate::json_store::load_opt(&webtuning_file())
}
pub(crate) fn save_tuning(t: &HttpTuning) -> Result<()> {
    crate::json_store::save_pretty(&webtuning_file(), t)
}

/// An access-list id (random, filesystem-safe).
pub(crate) fn new_access_id() -> String {
    format!("al{:08x}", rand::random::<u32>())
}
