//! MySQL/MariaDB engine catalog — the domain rules for which engines/versions
//! are offered and the (injection-safe) image reference they map to. Pure (no
//! I/O). Credential generation (gen_password) stays in the mysql infra-support.

/// A MySQL capability error — a **typed, exhaustive** replacement for the
/// scattered `anyhow!("ERR_CODE:mysql.*")` string literals. Each variant owns
/// its stable wire code (aligned with the frontend `err.<code>` map) in one
/// place, so the code set can't drift or typo. Pure/semantic: it carries no
/// transport detail beyond the code string the web boundary already speaks.
///
/// Domain owns only the **semantic** code (`mysql.*`); the transport marker
/// (`ERR_CODE:` prefix the `op_err_body` boundary parses) is added in infra, not
/// here, so the domain stays free of front-end/transport strings (§2/§4). A
/// later step can return `MysqlError` through the op dispatch and map it at the
/// web boundary directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MysqlError {
    MissingInstanceId,
    InstanceNotFound,
    InstanceExists,
    InstanceNotReady,
    PortRange,
    BadEngine,
    BadVersion,
    SameVersion,
    UserNameRules,
    BadPassword,
    BadHost,
    BadUserOrHost,
    BadAuthPlugin,
    BadLimit,
    BadPrivType,
    NoDropSystemUser,
    DbNameRules,
    ReservedDbName,
    BadDbName,
    NoDropSystemDb,
    BadCharset,
    BadCollation,
    BadTable,
    BadColumn,
    BadColType,
}

impl MysqlError {
    /// The stable, `mysql.`-namespaced semantic code (no transport prefix);
    /// e.g. `"mysql.bad_db_name"`. Aligned with the frontend `err.<code>` map.
    pub(crate) fn code(self) -> &'static str {
        use MysqlError::*;
        match self {
            MissingInstanceId => "mysql.missing_instance_id",
            InstanceNotFound => "mysql.instance_not_found",
            InstanceExists => "mysql.instance_exists",
            InstanceNotReady => "mysql.instance_not_ready",
            PortRange => "mysql.port_range",
            BadEngine => "mysql.bad_engine",
            BadVersion => "mysql.bad_version",
            SameVersion => "mysql.same_version",
            UserNameRules => "mysql.user_name_rules",
            BadPassword => "mysql.bad_password",
            BadHost => "mysql.bad_host",
            BadUserOrHost => "mysql.bad_user_or_host",
            BadAuthPlugin => "mysql.bad_auth_plugin",
            BadLimit => "mysql.bad_limit",
            BadPrivType => "mysql.bad_priv_type",
            NoDropSystemUser => "mysql.no_drop_system_user",
            DbNameRules => "mysql.db_name_rules",
            ReservedDbName => "mysql.reserved_db_name",
            BadDbName => "mysql.bad_db_name",
            NoDropSystemDb => "mysql.no_drop_system_db",
            BadCharset => "mysql.bad_charset",
            BadCollation => "mysql.bad_collation",
            BadTable => "mysql.bad_table",
            BadColumn => "mysql.bad_column",
            BadColType => "mysql.bad_col_type",
        }
    }
}

impl std::fmt::Display for MysqlError {
    /// Renders the semantic code only (no transport prefix); the infra boundary
    /// adds the `ERR_CODE:` marker when constructing the wire error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for MysqlError {}

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

    #[test]
    fn mysql_error_codes_are_namespaced_and_wire_stable() {
        // Representative codes match the exact strings the frontend `err.*` map
        // and `op_err_body` expect (this is the contract the migration preserves).
        assert_eq!(MysqlError::BadDbName.code(), "mysql.bad_db_name");
        // Display renders the semantic code only — no transport prefix in domain.
        assert_eq!(
            MysqlError::InstanceNotReady.to_string(),
            "mysql.instance_not_ready"
        );
        // Every variant's code is `mysql.`-namespaced and snake_case (no drift).
        for e in [
            MysqlError::MissingInstanceId,
            MysqlError::InstanceNotFound,
            MysqlError::InstanceExists,
            MysqlError::InstanceNotReady,
            MysqlError::PortRange,
            MysqlError::BadEngine,
            MysqlError::BadVersion,
            MysqlError::SameVersion,
            MysqlError::UserNameRules,
            MysqlError::BadPassword,
            MysqlError::BadHost,
            MysqlError::BadUserOrHost,
            MysqlError::BadAuthPlugin,
            MysqlError::BadLimit,
            MysqlError::BadPrivType,
            MysqlError::NoDropSystemUser,
            MysqlError::DbNameRules,
            MysqlError::ReservedDbName,
            MysqlError::BadDbName,
            MysqlError::NoDropSystemDb,
            MysqlError::BadCharset,
            MysqlError::BadCollation,
            MysqlError::BadTable,
            MysqlError::BadColumn,
            MysqlError::BadColType,
        ] {
            let c = e.code();
            assert!(c.starts_with("mysql."), "{c} not namespaced");
            assert!(
                c[6..]
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{c} not snake_case"
            );
        }
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
