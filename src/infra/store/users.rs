//! Panel-users store: `<data>/users.json` (0600). Pure persistence of the
//! `PanelUser` domain entity — no validation, no system-account side effects
//! (those live in `app::users` orchestration / `infra::system`).

use anyhow::Result;

use crate::domain::identity::PanelUser;

fn path() -> std::path::PathBuf {
    crate::paths::data_dir().join("users.json")
}

pub(crate) fn load() -> Vec<PanelUser> {
    crate::json_store::load_or_default(&path())
}

pub(crate) fn save(users: &[PanelUser]) -> Result<()> {
    crate::json_store::save_private(&path(), users)
}
