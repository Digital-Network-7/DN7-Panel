//! In-container mysql client exec helpers + readiness probe (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// In-container mysql client exec helpers.
// ---------------------------------------------------------------------------

/// Run a SQL statement inside the container using the bundled `mysql`/`mariadb`
/// client over the local socket, authenticating as root. The password is passed
/// via the `MYSQL_PWD` env var (not argv) and the SQL via `-e`. Returns
/// (exit_code, combined_output).
pub(crate) async fn mysql_exec(
    container: &str,
    password: &str,
    sql: &str,
) -> Result<(i64, String)> {
    exec_client(container, password, sql, false).await
}

/// Like `mysql_exec` but requests batch/tab-separated, header-less output
/// (`-N -B`) suitable for parsing query results.
pub(crate) async fn mysql_exec_query(
    container: &str,
    password: &str,
    sql: &str,
) -> Result<(i64, String)> {
    exec_client(container, password, sql, true).await
}

/// Run an arbitrary `/bin/sh -c` script inside the container with `MYSQL_PWD`
/// set (so a dump tool can authenticate). Returns (exit_code, combined output).
pub(crate) async fn exec_sh(
    container: &str,
    password: &str,
    script: &str,
) -> Result<(i64, String)> {
    exec_raw(
        container,
        password,
        vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
    )
    .await
}

/// Exec the mysql client inside the container. `batch` adds `-N -B` for
/// machine-readable output. `MYSQL_PWD` carries the password so it never
/// appears in argv / process list.
pub(crate) async fn exec_client(
    container: &str,
    password: &str,
    sql: &str,
    batch: bool,
) -> Result<(i64, String)> {
    let mut args: Vec<String> = vec!["-uroot".to_string(), "--protocol=socket".to_string()];
    if batch {
        args.push("-N".to_string());
        args.push("-B".to_string());
    }
    args.push("-e".to_string());
    args.push(sql.to_string());
    exec_argv(container, password, args).await
}

/// Run the mysql/mariadb client inside the container with the given client args
/// (a small shell test picks whichever client binary exists). `MYSQL_PWD`
/// carries the password. Returns (exit_code, combined output).
pub(crate) async fn exec_argv(
    container: &str,
    password: &str,
    client_args: Vec<String>,
) -> Result<(i64, String)> {
    let mut cmd: Vec<String> = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        // `exec` so the client's exit code is the exec's exit code.
        "if command -v mysql >/dev/null 2>&1; then exec mysql \"$@\"; else exec mariadb \"$@\"; fi"
            .to_string(),
        "sh".to_string(),
    ];
    cmd.extend(client_args);
    exec_raw(container, password, cmd).await
}

/// Low-level container exec: run `cmd` (argv) with `MYSQL_PWD` set. Returns
/// (exit_code, combined stdout+stderr).
pub(crate) async fn exec_raw(
    container: &str,
    password: &str,
    cmd: Vec<String>,
) -> Result<(i64, String)> {
    use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};

    let dkr = dkr()?;
    let exec = dkr
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                env: Some(vec![format!("MYSQL_PWD={password}")]),
                cmd: Some(cmd),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{}", friendly(&e)))?;

    let started = dkr
        .start_exec(
            &exec.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .map_err(|e| anyhow!("容器内执行失败：{}", friendly(&e)))?;

    let mut buf = String::new();
    if let StartExecResults::Attached { mut output, .. } = started {
        while let Some(item) = output.next().await {
            if let Ok(msg) = item {
                buf.push_str(&String::from_utf8_lossy(&msg.into_bytes()));
            }
        }
    }
    let code = dkr
        .inspect_exec(&exec.id)
        .await
        .ok()
        .and_then(|i| i.exit_code)
        .unwrap_or(0);
    Ok((code, buf))
}

// ---------------------------------------------------------------------------
// Readiness probe.
// ---------------------------------------------------------------------------

/// Whether mysqld inside the container actually accepts connections yet. A
/// freshly-started container is `running` long before the server finishes
/// initializing its data dir, so we probe with a real `SELECT 1`.
pub(crate) async fn is_ready(container: &str, password: &str) -> bool {
    match mysql_exec_query(container, password, "SELECT 1;").await {
        Ok((code, _)) => code == 0,
        Err(_) => false,
    }
}

/// Cached readiness check for the polled `list` path: the client polls `list`
/// (e.g. every 1.5s) and probing every running instance with an exec each time
/// is wasteful. Cache the result briefly so repeated list calls don't re-exec.
/// `wait_ready` deliberately bypasses this and probes fresh.
pub(crate) async fn is_ready_cached(container: &str, password: &str) -> bool {
    use std::sync::OnceLock;
    use std::time::Instant;
    static CACHE: OnceLock<Mutex<HashMap<String, (bool, Instant)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    const TTL: std::time::Duration = std::time::Duration::from_secs(5);

    if let Ok(m) = cache.lock() {
        if let Some((ready, at)) = m.get(container) {
            if at.elapsed() < TTL {
                return *ready;
            }
        }
    }
    let ready = is_ready(container, password).await;
    if let Ok(mut m) = cache.lock() {
        m.insert(container.to_string(), (ready, Instant::now()));
    }
    ready
}

/// Poll `is_ready` until it returns true or the timeout elapses. Pushes a few
/// progress lines into the op log so the UI shows "初始化中…" rather than a
/// silent hang. Returns true once ready, false on timeout.
pub(crate) async fn wait_ready(
    container: &str,
    password: &str,
    op_id: &str,
    timeout_secs: u64,
) -> bool {
    let start = std::time::Instant::now();
    let mut announced = false;
    loop {
        if is_ready(container, password).await {
            return true;
        }
        if start.elapsed().as_secs() >= timeout_secs {
            return false;
        }
        if !announced {
            op_push(op_id, &pmsg("my.initializing", &[]));
            announced = true;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
