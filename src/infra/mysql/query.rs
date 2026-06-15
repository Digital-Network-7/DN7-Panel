//! MySQL query runner + backup (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// Query runner (B): run arbitrary SQL, return columns + rows for display.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Backup (B): mysqldump the whole instance to a SQL file, return its text.
// ---------------------------------------------------------------------------

/// Start a detached backup op (mysqldump). The op log streams progress; on
/// success the dump is written to a file inside the container and its path +
/// size are reported. (Download wiring is a follow-up; this captures the dump
/// safely without holding it all in a single WS frame.)
pub(crate) fn start_backup(req: &Req) -> Result<Value> {
    let inst = need_inst(req)?.to_string();
    let _ = load_manifest(&inst)?; // validate it exists
    let op_id = new_op_id();
    op_create(&op_id, "backup", &inst);
    let op_t = op_id.clone();
    let inst_t = inst.clone();
    tokio::spawn(async move {
        match run_backup_detached(&op_t, &inst_t).await {
            Ok(()) => op_finish(&op_t, "done", "", &inst_t),
            Err(e) => op_finish(&op_t, "error", &e.to_string(), ""),
        }
    });
    Ok(json!({ "op_id": op_id, "inst_id": inst }))
}

/// Run `mysqldump --all-databases` inside the container, writing to
/// `/var/lib/mysql/dn7-backup-<ts>.sql` (on the persistent data volume so it
/// survives), and report the path + size.
pub(crate) async fn run_backup_detached(op_id: &str, inst: &str) -> Result<()> {
    let m = load_manifest(inst)?;
    let password = crate::infra::crypto::maybe_decrypt(&m.root_enc).unwrap_or_default();
    if !is_ready(&m.container, &password).await {
        return Err(anyhow!("ERR_CODE:mysql.instance_not_ready"));
    }
    op_push(op_id, &pmsg("my.exporting", &[]));
    let ts = now_secs();
    let path = format!("/var/lib/mysql/dn7-backup-{ts}.sql");
    // Use the dump tool that matches the engine; both accept the same flags.
    let script = format!(
        "if command -v mysqldump >/dev/null 2>&1; then DUMP=mysqldump; else DUMP=mariadb-dump; fi; \
         \"$DUMP\" -uroot --all-databases --single-transaction --routines --events > '{}' 2>/tmp/dumperr; \
         rc=$?; if [ $rc -ne 0 ]; then cat /tmp/dumperr; exit $rc; fi; \
         wc -c < '{}'",
        path, path
    );
    let (code, out) = exec_sh(&m.container, &password, &script).await?;
    if code != 0 {
        return Err(anyhow!(
            "备份失败：{}",
            out.trim().chars().take(240).collect::<String>()
        ));
    }
    let bytes: i64 = out
        .trim()
        .lines()
        .last()
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    op_push(
        op_id,
        &pmsg("my.backup_done", &[path.as_str(), &bytes.to_string()]),
    );
    Ok(())
}
