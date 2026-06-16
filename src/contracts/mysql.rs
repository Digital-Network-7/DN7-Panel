//! MySQL/MariaDB capability — external request DTO (the wire protocol the
//! console sends). Owned here (the contracts layer), read by the `infra::mysql`
//! dispatcher/adapters. Fields are `pub(crate)` so the adapters can read them.
//! All fields are primitives (no domain/infra types), so this DTO is pure
//! transport with no business rules.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) id: i64,
    pub(crate) op: String,
    /// instance id (start/stop/remove/...)
    #[serde(default)]
    pub(crate) inst: Option<String>,
    /// engine "mysql" | "mariadb" (install)
    #[serde(default)]
    pub(crate) engine: Option<String>,
    /// image version tag (install / switch_version)
    #[serde(default)]
    pub(crate) version: Option<String>,
    /// host port to publish 3306 on (install / change_port)
    #[serde(default)]
    pub(crate) port: Option<i64>,
    /// whether to publish the port to the host (install / change_port)
    #[serde(default)]
    pub(crate) expose: Option<bool>,
    /// keep the data volume on remove (default false = delete data too)
    #[serde(default)]
    pub(crate) keep_data: Option<bool>,
    /// op id (op_log / dismiss_op)
    #[serde(default)]
    pub(crate) op_id: Option<String>,
    /// account management: username / host / password / privileges / database
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) host: Option<String>,
    #[serde(default)]
    pub(crate) password: Option<String>,
    #[serde(default)]
    pub(crate) database: Option<String>,
    /// privilege scope: "all" (read+write) | "ro" (read-only) | "custom" later
    #[serde(default)]
    pub(crate) privilege: Option<String>,
    /// table browsing / column editing.
    #[serde(default)]
    pub(crate) table: Option<String>,
    #[serde(default)]
    pub(crate) column: Option<String>,
    #[serde(default)]
    pub(crate) new_name: Option<String>,
    /// SQL column type, e.g. "VARCHAR(255)" (modify_column).
    #[serde(default)]
    pub(crate) col_type: Option<String>,
    #[serde(default)]
    pub(crate) col_null: Option<bool>,
    #[serde(default)]
    pub(crate) col_default: Option<String>,
    /// row-preview limit (table_rows).
    #[serde(default)]
    pub(crate) limit: Option<i64>,
    /// database character set + collation (create_database).
    #[serde(default)]
    pub(crate) charset: Option<String>,
    #[serde(default)]
    pub(crate) collation: Option<String>,
    /// account authentication plugin (create_user); empty = engine default.
    #[serde(default)]
    pub(crate) auth_plugin: Option<String>,
    /// account resource limits (create_user); 0 = unlimited.
    #[serde(default)]
    pub(crate) max_queries: Option<i64>,
    #[serde(default)]
    pub(crate) max_connections: Option<i64>,
    #[serde(default)]
    pub(crate) max_user_connections: Option<i64>,
    /// require an encrypted (SSL/TLS) connection for the account (create_user).
    #[serde(default)]
    pub(crate) require_ssl: Option<bool>,
    /// grant/revoke on the cPanel-style `<user>\_%` database prefix instead of a
    /// single database (grant / revoke).
    #[serde(default)]
    pub(crate) prefix: Option<bool>,
}
