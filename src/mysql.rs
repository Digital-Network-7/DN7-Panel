//! Panel-side MySQL / MariaDB management.
//!
//! DN7 Panel provisions and manages MySQL/MariaDB **inside Docker containers** on
//! the user's server. We only ever touch instances *we* created: each managed
//! container carries the label `dn7.mysql=1` plus a `dn7.mysql.id` and a
//! local manifest under `<data>/mysql/<id>.json` (0600) recording the engine,
//! version, port mapping, data volume, and the at-rest-encrypted root password.
//! A user's own, hand-run MySQL is never listed or modified.
//!
//! Exposed to the web console via `web_dispatch` — a request/response JSON
//! protocol backed by the local Docker daemon (bollard). There is no backend
//! relay.
//!
//! Requests (client -> panel):
//!   {"id","op":"info"}                                  docker present? + engines/versions
//!   {"id","op":"list"}                                  DN7 Panel-managed instances
//!   {"id","op":"install","engine","version","port"?,"expose"?}  -> {op_id} (detached)
//!   {"id","op":"start"|"stop"|"restart","inst"}
//!   {"id","op":"remove","inst","keep_data"?}
//!   {"id","op":"reset_password","inst"}                 -> {password}
//!   {"id","op":"change_port","inst","port"?,"expose"}   -> recreate, keep volume
//!   {"id","op":"switch_version","inst","engine"?,"version"} -> {op_id} (detached)
//!   {"id","op":"databases","inst"}                      -> [{name,tables,size}]
//!   {"id","op":"create_database","inst","database"}     create a new schema
//!   {"id","op":"drop_database","inst","database"}       drop a (non-system) schema
//!   {"id","op":"credentials","inst"}                    -> {host,port,user,password}
//!   {"id","op":"list_users","inst"}                     -> [{user,host,system}]
//!   {"id","op":"create_user","inst","username","host","password"}
//!   {"id","op":"drop_user","inst","username","host"}
//!   {"id","op":"grant"|"revoke","inst","username","host","database","privilege"}
//!   {"id","op":"query","inst","sql"}                     -> {columns,rows,truncated}
//!   {"id","op":"backup","inst"}                          -> {op_id} (detached dump)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}
//!
//! Only ONE instance is supported (fixed container `dn7-mysql`); create
//! multiple databases inside it. Engine/version switching recreates the
//! container against the same data volume — the UI warns that major upgrades
//! or cross-engine swaps may be incompatible and recommends a backup first.
//! Responses: {"id","ok":true,"data":..} / {"id","ok":false,"error":".."}

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use bollard::Docker;
use futures::StreamExt;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Label marking a DN7 Panel-managed MySQL/MariaDB container.
const LABEL_MANAGED: &str = "dn7.mysql";
/// Label carrying our instance id on a managed container.
const LABEL_ID: &str = "dn7.mysql.id";
/// Label carrying the engine ("mysql"|"mariadb").
const LABEL_ENGINE: &str = "dn7.mysql.engine";

/// Single-instance model: one DN7 Panel MySQL/MariaDB per host with stable names
/// (no random suffix). Create multiple databases inside it instead of multiple
/// instances. These are also used to protect the container from deletion in the
/// Docker page.
pub const INSTANCE_ID: &str = "default";
pub const CONTAINER: &str = "dn7-mysql";
const VOLUME: &str = "dn7-mysql-data";

/// Connect to the local Docker daemon (or fail with a friendly hint).
fn dkr() -> Result<Docker> {
    Docker::connect_with_defaults().map_err(|e| {
        anyhow!("无法连接 Docker 守护进程：{e}（请先在 Docker 管理中安装并启动 Docker）")
    })
}

#[derive(Debug, Deserialize)]
struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    id: i64,
    op: String,
    /// instance id (start/stop/remove/...)
    #[serde(default)]
    inst: Option<String>,
    /// engine "mysql" | "mariadb" (install)
    #[serde(default)]
    engine: Option<String>,
    /// image version tag (install / switch_version)
    #[serde(default)]
    version: Option<String>,
    /// host port to publish 3306 on (install / change_port)
    #[serde(default)]
    port: Option<i64>,
    /// whether to publish the port to the host (install / change_port)
    #[serde(default)]
    expose: Option<bool>,
    /// keep the data volume on remove (default false = delete data too)
    #[serde(default)]
    keep_data: Option<bool>,
    /// op id (op_log / dismiss_op)
    #[serde(default)]
    op_id: Option<String>,
    /// account management: username / host / password / privileges / database
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    database: Option<String>,
    /// privilege scope: "all" (read+write) | "ro" (read-only) | "custom" later
    #[serde(default)]
    privilege: Option<String>,
    /// table browsing / column editing.
    #[serde(default)]
    table: Option<String>,
    #[serde(default)]
    column: Option<String>,
    #[serde(default)]
    new_name: Option<String>,
    /// SQL column type, e.g. "VARCHAR(255)" (modify_column).
    #[serde(default)]
    col_type: Option<String>,
    #[serde(default)]
    col_null: Option<bool>,
    #[serde(default)]
    col_default: Option<String>,
    /// row-preview limit (table_rows).
    #[serde(default)]
    limit: Option<i64>,
    /// database character set + collation (create_database).
    #[serde(default)]
    charset: Option<String>,
    #[serde(default)]
    collation: Option<String>,
    /// account authentication plugin (create_user); empty = engine default.
    #[serde(default)]
    auth_plugin: Option<String>,
    /// account resource limits (create_user); 0 = unlimited.
    #[serde(default)]
    max_queries: Option<i64>,
    #[serde(default)]
    max_connections: Option<i64>,
    #[serde(default)]
    max_user_connections: Option<i64>,
    /// require an encrypted (SSL/TLS) connection for the account (create_user).
    #[serde(default)]
    require_ssl: Option<bool>,
    /// grant/revoke on the cPanel-style `<user>\_%` database prefix instead of a
    /// single database (grant / revoke).
    #[serde(default)]
    prefix: Option<bool>,
}

/// Persisted per-instance manifest (`<data>/mysql/<id>.json`, 0600).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    id: String,
    engine: String,    // "mysql" | "mariadb"
    version: String,   // image tag, e.g. "8.0"
    container: String, // container name (dn7-mysql-<id>)
    volume: String,    // named data volume (dn7-mysql-<id>-data)
    /// host port if exposed, else None.
    port: Option<i64>,
    /// at-rest-encrypted root password (nonce:cipher), via crate::crypto.
    root_enc: String,
    created_at: i64,
    /// The primary admin account name shown to the user (default "root"). When
    /// non-root, an additional full-privilege account is created at install.
    #[serde(default)]
    admin_user: String,
}

// ---------------------------------------------------------------------------
// Submodules (see .kiro/steering/code-structure.md). Req/Manifest stay here so
// descendant modules can read their private fields.
// ---------------------------------------------------------------------------
mod accounts;
mod catalog;
mod exec;
mod provision;
mod query;
mod store;
mod tables;
use crate::domain::mysql::{image_ref, supported_versions, valid_engine, valid_version};
use accounts::*;
use catalog::*;
use exec::*;
use provision::*;
use query::*;
use store::*;
use tables::*;

// ---------------------------------------------------------------------------
// Detached op registry (install / switch / backup) — see `opreg` submodule.
// ---------------------------------------------------------------------------
mod opreg;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};

// ---------------------------------------------------------------------------
// Channel loop.
// ---------------------------------------------------------------------------

/// Public entrypoint for the local web console: parse a JSON request and run it.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad mysql request: {e}"))?;
    handle(&r).await
}

/// Dispatch one request.
async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => info().await,
        "list" => list_instances().await,
        "install" => start_install(req),
        "start" => {
            let m = load_manifest(need_inst(req)?)?;
            dkr()?
                .start_container(
                    &m.container,
                    None::<bollard::container::StartContainerOptions<String>>,
                )
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "started": m.id }))
        }
        "stop" => {
            let m = load_manifest(need_inst(req)?)?;
            let opts = bollard::container::StopContainerOptions { t: 20 };
            dkr()?
                .stop_container(&m.container, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "stopped": m.id }))
        }
        "restart" => {
            let m = load_manifest(need_inst(req)?)?;
            let opts = bollard::container::RestartContainerOptions { t: 20 };
            dkr()?
                .restart_container(&m.container, Some(opts))
                .await
                .map_err(|e| anyhow!(friendly(&e)))?;
            Ok(json!({ "restarted": m.id }))
        }
        "remove" => remove_instance(req).await,
        "reset_password" => reset_password(req).await,
        "change_port" => change_port(req).await,
        "switch_version" => start_switch(req),
        "databases" => databases(req).await,
        "create_database" => create_database(req).await,
        "drop_database" => drop_database(req).await,
        "tables" => tables(req).await,
        "columns" => columns(req).await,
        "table_rows" => table_rows(req).await,
        "modify_column" => modify_column(req).await,
        "credentials" => credentials(req).await,
        "list_users" => list_users(req).await,
        "create_user" => create_user(req).await,
        "drop_user" => drop_user(req).await,
        "grant" => grant(req).await,
        "revoke" => revoke(req).await,
        "user_grants" => user_grants(req).await,
        "backup" => start_backup(req),
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => Ok(op_log(req.op_id.as_deref().unwrap_or(""))),
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
        other => Err(anyhow!("不支持的操作：{other}")),
    }
}

fn need_inst(req: &Req) -> Result<&str> {
    req.inst
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:mysql.missing_instance_id"))
}

// ---------------------------------------------------------------------------
// info / list.
// ---------------------------------------------------------------------------

/// Detect Docker availability and report the curated engine/version catalog so
/// the client can render the install form (or prompt to set up Docker first).
async fn info() -> Result<Value> {
    let docker_ok = match dkr() {
        Ok(d) => d.ping().await.is_ok(),
        Err(_) => false,
    };
    Ok(json!({
        "docker_ok": docker_ok,
        "engines": [
            { "key": "mysql", "name": "MySQL", "versions": supported_versions("mysql"), "default": "8.0" },
            { "key": "mariadb", "name": "MariaDB", "versions": supported_versions("mariadb"), "default": "10.11" },
        ],
        "default_engine": "mysql",
    }))
}

/// List DN7 Panel-managed instances (from manifests), enriched with live container
/// state. Manifests are the source of truth for ownership — we never list a
/// container we didn't create.
async fn list_instances() -> Result<Value> {
    let dkr = dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: true,
        ..Default::default()
    };
    let containers = dkr.list_containers(Some(opts)).await.unwrap_or_default();

    let mut items = Vec::new();
    for m in all_manifests() {
        // Find the matching container by name (manifests are authoritative).
        let c = containers.iter().find(|c| {
            c.names
                .as_ref()
                .map(|ns| ns.iter().any(|n| n.trim_start_matches('/') == m.container))
                .unwrap_or(false)
        });
        let (state, status) = match c {
            Some(c) => (
                c.state.clone().unwrap_or_default(),
                c.status.clone().unwrap_or_default(),
            ),
            None => ("missing".to_string(), "容器不存在".to_string()),
        };

        // A `running` container may still be initializing its data dir (queries
        // fail until mysqld is up). Probe so the UI can show "初始化中" vs
        // "运行中". `restarting` usually means an init/config failure loop.
        let mut phase = state.clone();
        let mut ready = false;
        if state == "running" {
            let pwd = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
            ready = is_ready_cached(&m.container, &pwd).await;
            if !ready {
                phase = "initializing".to_string();
            }
        }

        items.push(json!({
            "id": m.id,
            "engine": m.engine,
            "version": m.version,
            "container": m.container,
            "port": m.port,
            "exposed": m.port.is_some(),
            "state": state,
            "phase": phase,
            "ready": ready,
            "status": status,
            "running": state == "running",
            "created_at": m.created_at,
        }));
    }
    Ok(json!({ "instances": items }))
}

/// Map a bollard error to a short friendly message.
fn friendly(e: &bollard::errors::Error) -> String {
    let s = e.to_string();
    if s.contains("No such container") || s.contains("404") {
        "容器不存在（实例可能已被手动删除）".to_string()
    } else if s.contains("Cannot connect") || s.contains("permission denied") {
        "无法连接 Docker 守护进程".to_string()
    } else {
        s.chars().take(300).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_and_versions() {
        assert!(valid_engine("mysql"));
        assert!(valid_engine("mariadb"));
        assert!(!valid_engine("postgres"));
        assert!(valid_version("mysql", "8.0"));
        assert!(valid_version("mariadb", "10.11"));
        assert!(!valid_version("mysql", "10.11"));
        assert!(!valid_version("mysql", "8.0; rm -rf /"));
    }

    #[test]
    fn image_refs() {
        assert_eq!(image_ref("mysql", "8.0"), "mysql:8.0");
        assert_eq!(image_ref("mariadb", "10.11"), "mariadb:10.11");
    }

    #[test]
    fn password_is_shell_safe() {
        let p = gen_password();
        assert_eq!(p.len(), 24);
        assert!(!p.contains('\'') && !p.contains('"') && !p.contains('\\') && !p.contains('$'));
    }

    #[test]
    fn sql_escape_quotes() {
        assert_eq!(sql_escape("a'b"), "a\\'b");
        assert_eq!(sql_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn port_validation() {
        assert!(validate_port(3306).is_ok());
        assert!(validate_port(0).is_err());
        assert!(validate_port(70000).is_err());
    }

    #[test]
    fn ident_validation() {
        assert!(valid_ident("app_user", false));
        assert!(valid_ident("my-db.1", false));
        assert!(!valid_ident("", false));
        assert!(!valid_ident("bad name", false));
        assert!(!valid_ident("drop;table", false));
        // wildcard only allowed for host.
        assert!(valid_ident("%", true));
        assert!(!valid_ident("%", false));
        assert!(!valid_ident(&"x".repeat(65), false));
    }

    #[test]
    fn ident_quote_escapes_backticks() {
        assert_eq!(ident_quote("db"), "`db`");
        assert_eq!(ident_quote("a`b"), "`a``b`");
    }

    #[test]
    fn grant_scope_forms() {
        assert_eq!(grant_scope("*").unwrap(), "*.*");
        assert_eq!(grant_scope("mydb").unwrap(), "`mydb`.*");
        assert!(grant_scope("bad db").is_err());
    }

    #[test]
    fn prefix_scope_form() {
        assert_eq!(prefix_scope("app"), "`app\\_%`.*");
    }

    #[test]
    fn charset_name_validation() {
        assert!(valid_charset_name("utf8mb4"));
        assert!(valid_charset_name("utf8mb4_unicode_ci"));
        assert!(!valid_charset_name("utf8;DROP"));
        assert!(!valid_charset_name(""));
    }

    #[test]
    fn auth_plugin_validation() {
        assert!(valid_auth_plugin("mysql", "caching_sha2_password"));
        assert!(valid_auth_plugin("mariadb", "ed25519"));
        assert!(!valid_auth_plugin("mysql", "ed25519"));
        assert!(!valid_auth_plugin("mariadb", "caching_sha2_password"));
        assert!(!valid_auth_plugin("mysql", "evil_plugin"));
    }

    #[test]
    fn limit_validation() {
        assert!(valid_limit(0));
        assert!(valid_limit(1000));
        assert!(!valid_limit(-1));
        assert!(!valid_limit(100_000_000));
    }

    #[test]
    fn col_type_canonical_and_injection_safe() {
        assert_eq!(
            canonical_col_type("varchar(255)").as_deref(),
            Some("VARCHAR(255)")
        );
        assert_eq!(canonical_col_type("int").as_deref(), Some("INT"));
        assert_eq!(
            canonical_col_type("decimal(10,2)").as_deref(),
            Some("DECIMAL(10,2)")
        );
        assert_eq!(
            canonical_col_type("int unsigned").as_deref(),
            Some("INT UNSIGNED")
        );
        assert_eq!(canonical_col_type("TEXT").as_deref(), Some("TEXT"));
        // Injection / malformed inputs must be rejected.
        assert!(canonical_col_type("INT, ADD COLUMN x INT").is_none());
        assert!(canonical_col_type("varchar(255); DROP TABLE t").is_none());
        assert!(canonical_col_type("enum('a','b')").is_none());
        assert!(canonical_col_type("int default 0").is_none());
        assert!(canonical_col_type("notatype").is_none());
        assert!(canonical_col_type("varchar(255) collate x").is_none());
        assert!(canonical_col_type("").is_none());
    }
}
