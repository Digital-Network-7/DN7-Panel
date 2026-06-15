//! MySQL database CRUD: list / create / drop (split from provision.rs).
use super::*;

/// List databases with table count and on-disk size (from information_schema).
/// System schemas are flagged so the UI can de-emphasize them.
pub(crate) async fn databases(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();

    // Tab-separated output: schema \t tables \t bytes. ORDER keeps it stable.
    let sql = "SELECT s.schema_name, \
        (SELECT COUNT(*) FROM information_schema.tables t WHERE t.table_schema = s.schema_name) AS tbls, \
        COALESCE((SELECT SUM(data_length + index_length) FROM information_schema.tables t WHERE t.table_schema = s.schema_name),0) AS bytes \
        FROM information_schema.schemata s ORDER BY s.schema_name;";
    let (code, out) = mysql_exec_query(&m.container, &password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }

    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    let mut dbs = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() || name == "schema_name" {
            continue; // skip a header row if the client emits one
        }
        let tables: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let bytes: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        dbs.push(json!({
            "name": name,
            "tables": tables,
            "bytes": bytes,
            "system": SYS.contains(&name),
        }));
    }
    Ok(json!({ "databases": dbs }))
}

/// Create a new (non-system) database/schema in the single instance.
pub(crate) async fn create_database(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.db_name_rules"));
    }
    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    if SYS.contains(&db) {
        return Err(anyhow!("ERR_CODE:mysql.reserved_db_name"));
    }
    // Character set + collation: validated as plain charset identifiers so they
    // can't break out of the statement. Invalid combos are rejected by the
    // server (surfaced as a friendly error). Defaults: utf8mb4 / unicode_ci.
    let charset = req
        .charset
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("utf8mb4");
    let collation = req
        .collation
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("utf8mb4_unicode_ci");
    if !valid_charset_name(charset) {
        return Err(anyhow!("ERR_CODE:mysql.bad_charset"));
    }
    if !valid_charset_name(collation) {
        return Err(anyhow!("ERR_CODE:mysql.bad_collation"));
    }
    // Backtick-quote the identifier; valid_ident already restricts the charset.
    let sql = format!(
        "CREATE DATABASE IF NOT EXISTS `{}` CHARACTER SET {} COLLATE {};",
        db, charset, collation
    );
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "created": db }))
}

/// Drop a (non-system) database/schema.
pub(crate) async fn drop_database(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    const SYS: [&str; 4] = ["information_schema", "performance_schema", "mysql", "sys"];
    if SYS.contains(&db) {
        return Err(anyhow!("ERR_CODE:mysql.no_drop_system_db"));
    }
    let sql = format!("DROP DATABASE `{}`;", db);
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "dropped": db }))
}
