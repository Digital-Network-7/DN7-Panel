//! Console-settings store: `<data>/web.json` (0600). Pure persistence of the
//! `WebSettings` domain entity — seeding/reset/validation stay in
//! `web::settings`.

use anyhow::Result;

use crate::domain::settings::WebSettings;

fn path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("web.json")
}

/// Read persisted settings without seeding. None when not initialized/corrupt.
pub(crate) fn load() -> Option<WebSettings> {
    crate::infra::json_store::load_opt(&path())
}

/// Persist settings 0600 atomically (no create-then-chmod window).
pub(crate) fn save(s: &WebSettings) -> Result<()> {
    crate::infra::json_store::save_private(&path(), s)
}
