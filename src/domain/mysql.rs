//! MySQL/MariaDB engine catalog — the domain rules for which engines/versions
//! are offered and the (injection-safe) image reference they map to. Pure (no
//! I/O). Credential generation (gen_password) stays in the mysql infra-support.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_version_rules() {
        assert!(valid_engine("mysql"));
        assert!(valid_engine("mariadb"));
        assert!(!valid_engine("postgres"));
        assert!(valid_version("mysql", "8.0"));
        assert!(!valid_version("mysql", "9.9"));
        assert!(!valid_version("postgres", "8.0"));
        assert_eq!(image_ref("mariadb", "11.4"), "mariadb:11.4");
    }
}

use serde::{Deserialize, Serialize};

/// Persisted per-instance manifest (`<data>/mysql/<id>.json`, 0600).
///
/// NOTE: a persisted **domain entity** — the `serde` derive is a reviewed
/// exception (see steering §2/§4). Fields are `pub(crate)` so the mysql
/// submodules (store/provision/query) read/build them across modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) id: String,
    pub(crate) engine: String,    // "mysql" | "mariadb"
    pub(crate) version: String,   // image tag, e.g. "8.0"
    pub(crate) container: String, // container name (dn7-mysql-<id>)
    pub(crate) volume: String,    // named data volume (dn7-mysql-<id>-data)
    /// host port if exposed, else None.
    pub(crate) port: Option<i64>,
    /// at-rest-encrypted root password (nonce:cipher), via crate::infra::crypto.
    pub(crate) root_enc: String,
    pub(crate) created_at: i64,
    /// The primary admin account name shown to the user (default "root"). When
    /// non-root, an additional full-privilege account is created at install.
    #[serde(default)]
    pub(crate) admin_user: String,
}
