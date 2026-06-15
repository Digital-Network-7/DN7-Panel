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
