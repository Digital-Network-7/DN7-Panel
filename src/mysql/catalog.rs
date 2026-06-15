//! MySQL/MariaDB engine catalog + credential generation — the domain rules for
//! which engines/versions are offered and how root passwords are minted. Kept
//! separate from the manifest store so `store` stays a pure persistence adapter.
use super::*;

// ---------------------------------------------------------------------------
// Supported engines + versions (curated). 8.0 is the default in the UI.
// ---------------------------------------------------------------------------

/// Curated version list per engine, newest first. The UI defaults to "8.0".
pub(crate) fn supported_versions(engine: &str) -> &'static [&'static str] {
    match engine {
        "mysql" => &["8.4", "8.0", "5.7"],
        "mariadb" => &["11.4", "10.11", "10.6"],
        _ => &[],
    }
}

/// Validate an engine name.
pub(crate) fn valid_engine(e: &str) -> bool {
    e == "mysql" || e == "mariadb"
}

/// Validate a version against the curated list for the engine (prevents an
/// arbitrary tag / injection into the image reference).
pub(crate) fn valid_version(engine: &str, version: &str) -> bool {
    supported_versions(engine).contains(&version)
}

/// The Docker image reference for an engine+version (official images only).
pub(crate) fn image_ref(engine: &str, version: &str) -> String {
    // Both `mysql` and `mariadb` are official Docker Hub images.
    format!("{engine}:{version}")
}

/// Generate a strong random root password (no shell-special chars so it's safe
/// to pass as a separate argv entry / env value; length 24).
pub(crate) fn gen_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
