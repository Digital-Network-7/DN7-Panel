//! MySQL table browsing + column editing (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// Table browsing + column editing.
// ---------------------------------------------------------------------------

/// Unescape a mysql `-B` batch-output field (\t \n \r \\ \0).
pub(crate) fn unescape_field(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('t') => out.push('\t'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('0') => out.push('\0'),
                Some('\\') => out.push('\\'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn valid_table(s: &str) -> bool {
    valid_ident(s, false)
}

/// List base tables in a database with row estimate, size, and engine.
pub(crate) async fn tables(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    let sql = format!(
        "SELECT table_name, COALESCE(table_rows,0), COALESCE(data_length+index_length,0), COALESCE(engine,'') \
         FROM information_schema.tables WHERE table_schema='{}' AND table_type='BASE TABLE' ORDER BY table_name;",
        sql_escape(db)
    );
    let (code, out) = mysql_exec_query(&m.container, &password, &sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    let mut tbls = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split('\t');
        let name = it.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let rows: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let bytes: i64 = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let engine = it.next().unwrap_or("").trim();
        tbls.push(json!({ "name": name, "rows": rows, "bytes": bytes, "engine": engine }));
    }
    Ok(json!({ "tables": tbls }))
}

/// List a table's columns (name / type / nullable / key / default / extra).
pub(crate) async fn columns(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    let tbl = req.table.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    if !valid_table(tbl) {
        return Err(anyhow!("ERR_CODE:mysql.bad_table"));
    }
    let sql = format!(
        "SELECT column_name, column_type, is_nullable, column_key, IFNULL(column_default,'\\0NULL'), extra \
         FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}' ORDER BY ordinal_position;",
        sql_escape(db),
        sql_escape(tbl)
    );
    let (code, out) = mysql_exec_query(&m.container, &password, &sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    let mut cols = Vec::new();
    for line in out.lines() {
        if line.trim_end().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let g = |i: usize| f.get(i).map(|s| unescape_field(s)).unwrap_or_default();
        let name = g(0);
        if name.is_empty() {
            continue;
        }
        let def_raw = g(4);
        let default = if def_raw == "\0NULL" {
            Value::Null
        } else {
            json!(def_raw)
        };
        cols.push(json!({
            "name": name, "type": g(1), "nullable": g(2) == "YES",
            "key": g(3), "default": default, "extra": g(5),
        }));
    }
    Ok(json!({ "columns": cols }))
}

/// Preview rows of a table (default 100, capped 500) → column names + rows.
pub(crate) async fn table_rows(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    let tbl = req.table.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    if !valid_table(tbl) {
        return Err(anyhow!("ERR_CODE:mysql.bad_table"));
    }
    let limit = req.limit.unwrap_or(100).clamp(1, 500);

    let col_sql = format!(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='{}' AND table_name='{}' ORDER BY ordinal_position;",
        sql_escape(db),
        sql_escape(tbl)
    );
    let cout = query_or_err(&m.container, &password, &col_sql).await?;
    let cols: Vec<String> = cout
        .lines()
        .map(|l| l.trim_end().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let sql = format!(
        "SELECT * FROM {}.{} LIMIT {};",
        ident_quote(db),
        ident_quote(tbl),
        limit
    );
    let out = query_or_err(&m.container, &password, &sql).await?;
    let rows = parse_tsv_rows(&out);
    Ok(json!({ "columns": cols, "rows": rows, "limit": limit }))
}

/// Run a query in the instance container and return its stdout, mapping a
/// non-zero exit into a truncated "查询失败" error.
async fn query_or_err(container: &str, password: &str, sql: &str) -> Result<String> {
    let (code, out) = mysql_exec_query(container, password, sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    Ok(out)
}

/// Parse mysql `-B` batch output (tab-separated, one row per line) into JSON
/// row arrays. A literal `NULL` field becomes JSON null; everything else is
/// unescaped and kept as a string.
fn parse_tsv_rows(out: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    for line in out.lines() {
        if line.is_empty() {
            continue;
        }
        let row: Vec<Value> = line
            .split('\t')
            .map(|p| {
                if p == "NULL" {
                    Value::Null
                } else {
                    json!(unescape_field(p))
                }
            })
            .collect();
        rows.push(Value::Array(row));
    }
    rows
}

/// Parse a column type into a safe, canonical form, or `None` if it isn't a
/// recognized type. This is the structural-injection guard for `modify_column`:
/// only a whitelisted base type with an optional numeric `(len)` / `(m,d)` and
/// optional `UNSIGNED` / `ZEROFILL` modifiers is accepted — no quotes, commas
/// outside the length, semicolons, or extra keywords can survive, so the result
/// can't smuggle additional `ALTER` clauses. The returned string is rebuilt
/// from validated tokens (never the raw input).
pub(crate) fn canonical_col_type(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    // Hard character gate: only letters/digits/parens/comma/space may appear.
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '(' | ')' | ',' | ' '))
    {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let (base, args, tail) = split_col_type(&lower)?;
    if !col_base_known(base) {
        return None;
    }
    // Trailing modifiers: only UNSIGNED / ZEROFILL (in any order), nothing else.
    let (unsigned, zerofill) = col_type_modifiers(tail)?;
    let mut out = base.to_ascii_uppercase();
    if let Some(a) = args {
        out.push('(');
        out.push_str(&a);
        out.push(')');
    }
    if unsigned {
        out.push_str(" UNSIGNED");
    }
    if zerofill {
        out.push_str(" ZEROFILL");
    }
    Some(out)
}

/// Split a lowercased column type into (base, optional "(args)" digits, tail of
/// trailing modifiers). Validates the length args (1-2 numeric, ≤4 digits) and
/// the parenthesis structure. Returns None on any malformed shape.
fn split_col_type(lower: &str) -> Option<(&str, Option<String>, &str)> {
    let Some(i) = lower.find('(') else {
        // No length: first word is the base type, the rest are modifiers.
        let mut it = lower.splitn(2, char::is_whitespace);
        let base = it.next().unwrap_or("").trim();
        let tail = it.next().unwrap_or("").trim();
        return Some((base, None, tail));
    };
    let j = lower.find(')')?;
    if j < i || lower[j + 1..].contains('(') || lower[..i].contains(')') {
        return None;
    }
    let inner = lower[i + 1..j].trim();
    // 1 or 2 numeric components (e.g. DECIMAL(m,d)); each ≤4 digits.
    let parts: Vec<&str> = inner.split(',').map(|p| p.trim()).collect();
    if parts.is_empty() || parts.len() > 2 {
        return None;
    }
    for p in &parts {
        if p.is_empty() || p.len() > 4 || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    Some((
        lower[..i].trim(),
        Some(parts.join(",")),
        lower[j + 1..].trim(),
    ))
}

/// Whether `base` is a recognized MySQL column base type.
fn col_base_known(base: &str) -> bool {
    const NOARG: &[&str] = &[
        "tinytext",
        "text",
        "mediumtext",
        "longtext",
        "tinyblob",
        "blob",
        "mediumblob",
        "longblob",
        "json",
        "date",
        "bool",
        "boolean",
    ];
    const OPTARG: &[&str] = &[
        "tinyint",
        "smallint",
        "mediumint",
        "int",
        "integer",
        "bigint",
        "bit",
        "char",
        "varchar",
        "binary",
        "varbinary",
        "decimal",
        "numeric",
        "float",
        "double",
        "real",
        "datetime",
        "timestamp",
        "time",
        "year",
    ];
    NOARG.contains(&base) || OPTARG.contains(&base)
}

/// Parse trailing column-type modifiers: only UNSIGNED / ZEROFILL (any order,
/// no repeats), nothing else. Returns (unsigned, zerofill) or None if invalid.
fn col_type_modifiers(tail: &str) -> Option<(bool, bool)> {
    let mut unsigned = false;
    let mut zerofill = false;
    for w in tail.split_whitespace() {
        match w {
            "unsigned" if !unsigned => unsigned = true,
            "zerofill" if !zerofill => zerofill = true,
            _ => return None,
        }
    }
    Some((unsigned, zerofill))
}

/// Modify a column's name / type / nullability / default via ALTER TABLE.
pub(crate) async fn modify_column(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let db = req.database.as_deref().map(str::trim).unwrap_or("");
    let tbl = req.table.as_deref().map(str::trim).unwrap_or("");
    let col = req.column.as_deref().map(str::trim).unwrap_or("");
    let new = req
        .new_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(col);
    let ctype = req.col_type.as_deref().map(str::trim).unwrap_or("");
    if !valid_ident(db, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_db_name"));
    }
    if !valid_table(tbl) {
        return Err(anyhow!("ERR_CODE:mysql.bad_table"));
    }
    if !valid_ident(col, false) || !valid_ident(new, false) {
        return Err(anyhow!("ERR_CODE:mysql.bad_column"));
    }
    // Canonicalize the type from a whitelist — never interpolate raw input
    // (prevents smuggling extra DDL clauses through the type field).
    let ctype = canonical_col_type(ctype).ok_or_else(|| anyhow!("ERR_CODE:mysql.bad_col_type"))?;
    let nullable = req.col_null.unwrap_or(true);
    let mut sql = format!(
        "ALTER TABLE {}.{} CHANGE COLUMN {} {} {}",
        ident_quote(db),
        ident_quote(tbl),
        ident_quote(col),
        ident_quote(new),
        ctype
    );
    sql.push_str(if nullable { " NULL" } else { " NOT NULL" });
    if let Some(d) = req
        .col_default
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sql.push_str(&format!(" DEFAULT '{}'", sql_escape(d)));
    }
    sql.push(';');
    run_stmt(&m.container, &password, &sql).await?;
    Ok(json!({ "modified": new }))
}

/// Summarize a user's per-database privileges by parsing SHOW GRANTS, as a map
/// of database → "all" | "ro" (`*.*` maps to the key "*").
pub(crate) async fn user_grants(req: &Req) -> Result<Value> {
    let m = load_manifest(need_inst(req)?)?;
    let password = crate::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    let user = req.username.as_deref().map(str::trim).unwrap_or("");
    let host = req.host.as_deref().map(str::trim).unwrap_or("%");
    if !valid_ident(user, false) || !valid_ident(host, true) {
        return Err(anyhow!("ERR_CODE:mysql.bad_user_or_host"));
    }
    let sql = format!(
        "SHOW GRANTS FOR '{}'@'{}';",
        sql_escape(user),
        sql_escape(host)
    );
    let (code, out) = mysql_exec_query(&m.container, &password, &sql).await?;
    if code != 0 {
        return Err(anyhow!(
            "查询失败：{}",
            out.trim().chars().take(200).collect::<String>()
        ));
    }
    let mut grants = serde_json::Map::new();
    for line in out.lines() {
        let l = line.trim();
        let upper = l.to_uppercase();
        if !upper.starts_with("GRANT ") {
            continue;
        }
        let on = match upper.find(" ON ") {
            Some(i) => i,
            None => continue,
        };
        let privs = &upper[6..on];
        let rest = &l[on + 4..];
        let scope_end = rest.to_uppercase().find(" TO ").unwrap_or(rest.len());
        let scope = rest[..scope_end].trim();
        let db = scope
            .split('.')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('`');
        if db.is_empty() {
            continue;
        }
        let key = if scope.starts_with("*.") {
            "*".to_string()
        } else {
            db.to_string()
        };
        let level =
            if privs.contains("ALL") || (privs.contains("INSERT") && privs.contains("UPDATE")) {
                "all"
            } else if privs.contains("SELECT") {
                "ro"
            } else {
                continue; // USAGE / no real privileges
            };
        grants.insert(key, json!(level));
    }
    Ok(json!({ "grants": grants }))
}
