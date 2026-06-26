//! MySQL account management: users, grants, revoke (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// Account management (B): list / create / drop users, grant / revoke.
// ---------------------------------------------------------------------------

/// Validate a MySQL identifier (username / database / host) used inside quoted
/// SQL. We allow a conservative charset so a value can't break out of its quote
/// even though we also escape; `%` is allowed for the host wildcard.
pub(crate) fn valid_ident(s: &str, allow_wildcard: bool) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') || (allow_wildcard && c == '%')
    })
}

/// Backtick-escape an identifier (double any backticks) for `\`name\``.
pub(crate) fn ident_quote(s: &str) -> String {
    format!("`{}`", s.replace('`', "``"))
}

/// Validate a charset / collation name (e.g. "utf8mb4", "utf8mb4_unicode_ci").
/// These are emitted unquoted in CREATE DATABASE, so restrict to a safe charset.
pub(crate) fn valid_charset_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validate an authentication plugin against the engine's allowed set. An empty
/// plugin means "use the engine default".
pub(crate) fn valid_auth_plugin(engine: &str, plugin: &str) -> bool {
    match engine {
        "mysql" => matches!(plugin, "caching_sha2_password" | "mysql_native_password"),
        "mariadb" => matches!(plugin, "mysql_native_password" | "ed25519"),
        _ => false,
    }
}

/// Clamp/validate a resource limit (queries/connections per hour, etc).
pub(crate) fn valid_limit(n: i64) -> bool {
    (0..=10_000_000).contains(&n)
}

/// List non-system MySQL accounts as {user, host}. Reads mysql.user.
pub(crate) async fn list_users(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let sql = "SELECT User, Host FROM mysql.user ORDER BY User, Host;";
    let (code, out) = mysql_exec_query(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    // System/internal accounts we don't surface for management.
    const SYS_USERS: [&str; 6] = [
        "mysql.sys",
        "mysql.session",
        "mysql.infoschema",
        "root",
        "mariadb.sys",
        "healthcheck",
    ];
    let mut users = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let user = it.next().unwrap_or("").trim();
        let host = it.next().unwrap_or("").trim();
        if user.is_empty() {
            continue;
        }
        users.push(json!({
            "user": user,
            "host": host,
            "system": SYS_USERS.contains(&user),
        }));
    }
    Ok(json!({ "users": users }))
}

/// Create a user `'name'@'host'` with a password. Optional advanced options:
/// an authentication plugin (engine-aware syntax), resource limits, and a
/// require-SSL flag.
pub(crate) async fn create_user(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let pwd = req.password.as_deref().unwrap_or("");
    if !valid_ident(user, false) {
        return Err(mysql_err(MysqlError::UserNameRules));
    }
    // Refuse reserved system-account names (valid_ident allows 'root' and the
    // 'mysql.'/'mariadb.' prefixes) — drop_user won't delete them, so creating
    // one would be a non-removable, possibly superuser-shadowing account.
    if user.eq_ignore_ascii_case("root")
        || user.starts_with("mysql.")
        || user.starts_with("mariadb.")
    {
        return Err(mysql_err(MysqlError::UserNameRules));
    }
    if !valid_ident(host, true) {
        return Err(mysql_err(MysqlError::BadHost));
    }
    // Minimum 6 chars (matches the root-password rule in provision/install.rs);
    // also covers the empty case.
    if pwd.len() < 6 || pwd.len() > 128 {
        return Err(mysql_err(MysqlError::BadPassword));
    }

    // Authentication clause — syntax differs between MySQL and MariaDB.
    let plugin = req
        .auth_plugin
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(p) = plugin {
        if !valid_auth_plugin(&m.engine, p) {
            return Err(mysql_err(MysqlError::BadAuthPlugin));
        }
    }
    let auth = mysql_auth_clause(&m.engine, plugin, &sql_escape(pwd));

    // Resource limits (0 = unlimited / not set) + optional SSL requirement.
    let with = mysql_limits_clause(req)?;
    let ssl = if req.require_ssl.unwrap_or(false) {
        " REQUIRE SSL"
    } else {
        ""
    };

    let sql = format!(
        "CREATE USER '{}'@'{}' {auth}{ssl}{with};",
        sql_escape(user),
        sql_escape(host),
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "created": user, "host": host }))
}

/// The `IDENTIFIED ...` auth clause for `CREATE USER`. `esc_pw` is the already
/// sql-escaped password; `plugin` is a pre-validated auth plugin (or None for
/// the engine default). MySQL and MariaDB differ in syntax.
fn mysql_auth_clause(engine: &str, plugin: Option<&str>, esc_pw: &str) -> String {
    match (engine, plugin) {
        // MySQL: IDENTIFIED WITH <plugin> BY '<pw>'
        ("mysql", Some(p)) => format!("IDENTIFIED WITH {p} BY '{esc_pw}'"),
        // MariaDB ed25519: IDENTIFIED VIA ed25519 USING PASSWORD('<pw>')
        ("mariadb", Some("ed25519")) => {
            format!("IDENTIFIED VIA ed25519 USING PASSWORD('{esc_pw}')")
        }
        // Everything else (incl. native on either engine): IDENTIFIED BY '<pw>'
        _ => format!("IDENTIFIED BY '{esc_pw}'"),
    }
}

/// The optional ` WITH <limits>` clause for `CREATE USER`. Each limit is
/// validated; 0 means "unset". Returns an empty string when no limit is set.
fn mysql_limits_clause(req: &Req) -> Result<String> {
    let mq = req.max_queries.unwrap_or(0);
    let mc = req.max_connections.unwrap_or(0);
    let muc = req.max_user_connections.unwrap_or(0);
    for v in [mq, mc, muc] {
        if !valid_limit(v) {
            return Err(mysql_err(MysqlError::BadLimit));
        }
    }
    let mut limit_clause = String::new();
    if mq > 0 {
        limit_clause.push_str(&format!(" MAX_QUERIES_PER_HOUR {mq}"));
    }
    if mc > 0 {
        limit_clause.push_str(&format!(" MAX_CONNECTIONS_PER_HOUR {mc}"));
    }
    if muc > 0 {
        limit_clause.push_str(&format!(" MAX_USER_CONNECTIONS {muc}"));
    }
    Ok(if limit_clause.is_empty() {
        String::new()
    } else {
        format!(" WITH{limit_clause}")
    })
}

/// Drop a user `'name'@'host'`. root and system accounts are protected.
pub(crate) async fn drop_user(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(mysql_err(MysqlError::BadUserOrHost));
    }
    if user.eq_ignore_ascii_case("root")
        || user.starts_with("mysql.")
        || user.starts_with("mariadb.")
    {
        return Err(mysql_err(MysqlError::NoDropSystemUser));
    }
    let sql = format!("DROP USER '{}'@'{}';", sql_escape(user), sql_escape(host));
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "dropped": user, "host": host }))
}

/// Grant privileges on a database to a user. `privilege` is "all" (read+write)
/// or "ro" (SELECT only). Database "*" means all databases.
pub(crate) async fn grant(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let db = req.database.as_deref().map(str::trim).unwrap_or("*");
    let priv_kind = req.privilege.as_deref().unwrap_or("all");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(mysql_err(MysqlError::BadUserOrHost));
    }
    let privs = match priv_kind {
        "ro" => "SELECT",
        "all" => "ALL PRIVILEGES",
        _ => return Err(mysql_err(MysqlError::BadPrivType)),
    };
    let scope = if req.prefix.unwrap_or(false) {
        prefix_scope(user)
    } else {
        grant_scope(db)?
    };
    let sql = format!(
        "GRANT {privs} ON {scope} TO '{}'@'{}'; FLUSH PRIVILEGES;",
        sql_escape(user),
        sql_escape(host)
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "granted": priv_kind, "db": db }))
}

/// Revoke all privileges on a database from a user.
pub(crate) async fn revoke(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::support::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    let db = req.database.as_deref().map(str::trim).unwrap_or("*");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(mysql_err(MysqlError::BadUserOrHost));
    }
    let scope = if req.prefix.unwrap_or(false) {
        prefix_scope(user)
    } else {
        grant_scope(db)?
    };
    let sql = format!(
        "REVOKE ALL PRIVILEGES, GRANT OPTION ON {scope} FROM '{}'@'{}'; FLUSH PRIVILEGES;",
        sql_escape(user),
        sql_escape(host)
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "revoked": db }))
}

/// Build a GRANT scope `\`db\`.*` or `*.*`. Validates the db identifier.
pub(crate) fn grant_scope(db: &str) -> Result<String> {
    if db == "*" {
        Ok("*.*".to_string())
    } else if valid_ident(db, false) {
        Ok(format!("{}.*", ident_quote(db)))
    } else {
        Err(mysql_err(MysqlError::BadDbName))
    }
}

/// cPanel-style prefix scope: `` `<user>\_%`.* `` — every database whose name
/// starts with `<user>_`. The underscore is escaped (literal) and `%` stays a
/// wildcard. The user is already restricted to a safe identifier charset.
pub(crate) fn prefix_scope(user: &str) -> String {
    format!("`{}\\_%`.*", user.replace('`', "``"))
}

/// Run a statement expecting success; surfaces the engine's error message.
pub(crate) async fn run_stmt(container: &str, password: &str, sql: &str) -> Result<()> {
    let (code, out) = mysql_exec(container, password, sql).await?;
    if code == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            out.trim().chars().take(240).collect::<String>()
        ))
    }
}
