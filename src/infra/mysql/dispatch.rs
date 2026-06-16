//! MySQL/MariaDB dispatch + shared constants/helpers (labels, names, the
//! Docker client, the typed-error bridge, op routing, and info/list).
use super::*;

pub(crate) const LABEL_MANAGED: &str = "dn7.mysql";
/// Label carrying our instance id on a managed container.
pub(crate) const LABEL_ID: &str = "dn7.mysql.id";
/// Label carrying the engine ("mysql"|"mariadb").
pub(crate) const LABEL_ENGINE: &str = "dn7.mysql.engine";

/// Single-instance model: one DN7 Panel MySQL/MariaDB per host with stable names
/// (no random suffix). Create multiple databases inside it instead of multiple
/// instances. These are also used to protect the container from deletion in the
/// Docker page.
pub const INSTANCE_ID: &str = "default";
pub const CONTAINER: &str = "dn7-mysql";
pub(crate) const VOLUME: &str = "dn7-mysql-data";

/// Build the transitional `anyhow` error for a typed [`MysqlError`]: prefixes
/// the semantic code with the `ERR_CODE:` transport marker the `op_err_body`
/// web boundary parses into the wire `code`. The `ERR_CODE:` marker lives here
/// (infra), not in the domain enum, per §2/§4.
pub(crate) fn mysql_err(e: MysqlError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// Connect to the local Docker daemon (or fail with a friendly hint).
pub(crate) fn dkr() -> Result<Docker> {
    Docker::connect_with_defaults().map_err(|e| {
        anyhow!("无法连接 Docker 守护进程：{e}（请先在 Docker 管理中安装并启动 Docker）")
    })
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Dispatch.
// ---------------------------------------------------------------------------

/// Execute one already-parsed mysql capability request. The `app::mysql` router
/// owns parsing + the in-memory op-registry ops; this holds the authoritative
/// match for the DB/container ops (each interleaved with bollard / in-container
/// exec state, so it stays as one adapter cluster rather than being re-typed in
/// the app layer).
pub(crate) async fn run_op(req: &Req) -> Result<Value> {
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
        other => Err(anyhow!("不支持的操作：{other}")),
    }
}

/// Read-only detached-op-registry projections + dismiss, exposed for the
/// `app::mysql` router (the registry fns themselves are `pub(super)`). These ops
/// touch neither the DB nor Docker.
pub(crate) fn ops_snapshot_value() -> Value {
    ops_snapshot()
}
pub(crate) fn op_log_value(op_id: &str) -> Value {
    op_log(op_id)
}
pub(crate) fn op_dismiss_registry(op_id: &str) {
    op_dismiss(op_id);
}

pub(crate) fn need_inst(req: &Req) -> Result<&str> {
    req.inst
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| mysql_err(MysqlError::MissingInstanceId))
}

// ---------------------------------------------------------------------------
// info / list.
// ---------------------------------------------------------------------------

/// Detect Docker availability and report the curated engine/version catalog so
/// the client can render the install form (or prompt to set up Docker first).
pub(crate) async fn info() -> Result<Value> {
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

/// Project one managed instance (manifest + optional live container) into the
/// list row, probing readiness for a `running` container so the UI can show
/// "初始化中" vs "运行中".
async fn instance_row(m: &Manifest, c: Option<&bollard::models::ContainerSummary>) -> Value {
    let (state, status) = match c {
        Some(c) => (
            c.state.clone().unwrap_or_default(),
            c.status.clone().unwrap_or_default(),
        ),
        None => ("missing".to_string(), "容器不存在".to_string()),
    };
    // A `running` container may still be initializing its data dir (queries fail
    // until mysqld is up). `restarting` usually means an init/config failure loop.
    let mut phase = state.clone();
    let mut ready = false;
    if state == "running" {
        let pwd = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
        ready = is_ready_cached(&m.container, &pwd).await;
        if !ready {
            phase = "initializing".to_string();
        }
    }
    json!({
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
    })
}

/// List DN7 Panel-managed instances (from manifests), enriched with live container
/// state. Manifests are the source of truth for ownership — we never list a
/// container we didn't create.
pub(crate) async fn list_instances() -> Result<Value> {
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
        items.push(instance_row(&m, c).await);
    }
    Ok(json!({ "instances": items }))
}

/// Map a bollard error to a short friendly message.
pub(crate) fn friendly(e: &bollard::errors::Error) -> String {
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
        // A single quote is doubled (mode-independent), not backslash-escaped —
        // so it stays safe under NO_BACKSLASH_ESCAPES / ANSI mode too.
        assert_eq!(sql_escape("a'b"), "a''b");
        assert_eq!(sql_escape("a\\b"), "a\\\\b");
        // A quote adjacent to a backslash can't break out of the literal.
        assert_eq!(sql_escape("a\\'b"), "a\\\\''b");
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
