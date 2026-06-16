//! Setup: install + configure host nginx via the system package manager
//! (split from nginx.rs). DN7 Panel manages the host's own nginx — it does not
//! run nginx in a container.
use super::*;

// Validation (no raw config; everything is form-driven and checked).
// ---------------------------------------------------------------------------

// Validators (valid_server_name, primary_host, valid_host_token, …) live in
// the `validate` submodule.

// ---------------------------------------------------------------------------
// Setup: install + enable host nginx via the system package manager. Detached.
// ---------------------------------------------------------------------------

pub(crate) fn start_setup() -> Result<Value> {
    const SETUP_OP: &str = "setup";
    if opreg::op_running(SETUP_OP) {
        return Ok(json!({ "op_id": SETUP_OP, "already_running": true }));
    }
    if !is_root() {
        return Err(anyhow!("ERR_CODE:nginx.need_root"));
    }

    op_create(SETUP_OP, "setup", "host");
    tokio::spawn(async move {
        match setup_host(SETUP_OP).await {
            Ok(()) => {
                let _ = mark_setup();
                op_push(SETUP_OP, &pmsg("ng.setup_done", &[]));
                op_finish(SETUP_OP, "done", "");
            }
            Err(e) => op_finish(SETUP_OP, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": SETUP_OP, "target": "host" }))
}

/// Ensure host nginx is installed (distro package manager), enabled, running,
/// and that our conf.d drop-in dir + state dirs exist.
pub(crate) async fn setup_host(op_id: &str) -> Result<()> {
    // Already present?
    if run("nginx", &["-v"])
        .await
        .map(|(ok, ..)| ok)
        .unwrap_or(false)
    {
        op_push(op_id, &pmsg("ng.detected_host", &[]));
    } else {
        op_push(op_id, &pmsg("ng.installing", &[]));
        let script = r#"set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y nginx
elif command -v yum >/dev/null 2>&1; then
  yum install -y nginx
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache nginx
else
  echo "no supported package manager" >&2; exit 1
fi"#;
        stream_sh(op_id, script).await?;
    }

    op_push(op_id, &pmsg("ng.ensure_enable", &[]));
    let _ = sh(&format!("mkdir -p {HOST_CONFD}")).await;
    // Our state dirs (certs + webroots) that nginx reads from.
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    let _ = sh("systemctl enable nginx 2>/dev/null || true; systemctl restart nginx 2>/dev/null || service nginx restart 2>/dev/null || nginx 2>/dev/null || true").await;

    // Verify it's runnable.
    let (ok, _, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置测试失败".into())
        ));
    }
    Ok(())
}

/// Stream a shell script's output into the op log, erroring on non-zero exit.
pub(crate) async fn stream_sh(op_id: &str, script: &str) -> Result<()> {
    stream_cmd(op_id, "sh", &["-c", script]).await
}

/// Stream a command's combined output into the op log, erroring on non-zero.
pub(crate) async fn stream_cmd(op_id: &str, cmd: &str, args: &[&str]) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    // Drain stderr concurrently so a child that fills the stderr pipe can't
    // deadlock against us waiting on stdout.
    let stderr = child.stderr.take();
    let err_task = tokio::spawn(async move {
        let mut buf = String::new();
        if let Some(mut er) = stderr {
            let _ = er.read_to_string(&mut buf).await;
        }
        buf
    });
    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|e| anyhow!("{cmd} 执行失败：{e}"))?;
    let err = err_task.await.unwrap_or_default();
    for line in err
        .lines()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        op_push(op_id, line.trim());
    }
    if !status.success() {
        return Err(anyhow!("{cmd} 返回非零退出码"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
