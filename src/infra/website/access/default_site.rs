//! Default (catch-all) site settings (split from access.rs).
use super::*;

/// Persist an already-validated default-site entity and rebuild the edge route
/// table from it — rolling back the manifest if the new model is rejected. The
/// edge's default (catch-all) server is built from `WebGlobal` in `build_runtime`,
/// so persisting + reloading is all that's needed. The validation/build of the
/// entity is owned by `core::website::build_default_site`.
pub(crate) async fn apply_default_site(g: &WebGlobal) -> Result<Value> {
    let lo = layout()?;
    // Strict load: if websettings.json is present but corrupt, refuse (and
    // quarantine it) instead of clobbering it with `g` and then rolling back to
    // a fabricated default. `None` (genuinely absent) rolls back to defaults.
    let prev = load_webglobal_strict()?.unwrap_or_default();
    save_webglobal(g)?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back to the previous default-site settings.
        let _ = save_webglobal(&prev);
        let _ = reload().await;
        return Err(e);
    }
    Ok(json!({ "ok": true }))
}
