//! Panel-users store: `<data>/users.json` (0600). Pure persistence of the
//! `PanelUser` domain entity — no validation, no system-account side effects
//! (those live in `app::users` orchestration / `infra::system`).

use anyhow::Result;

use crate::core::identity::PanelUser;

fn path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("users.json")
}

pub(crate) fn load() -> Vec<PanelUser> {
    // Cached (mtime+len-validated): read on every authenticated request.
    crate::infra::support::json_store::load_or_default_cached(&path())
}

pub(crate) fn save(users: &[PanelUser]) -> Result<()> {
    crate::infra::support::json_store::save_private(&path(), users)
}
