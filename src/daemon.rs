//! Background daemonization for the agent (supervisor role).
//!
//! On a normal launch the binary prints its pairing QR + code in the foreground
//! (so the operator can scan it), then detaches and keeps running in the
//! background, writing logs to `teaops-agent.log`. Pass `--foreground` / `-f`
//! (or set `TEAOPS_FOREGROUND=1`) to stay attached.
//!
//! Daemonization must happen before the tokio runtime is created.

/// Log file the daemonized process appends stdout/stderr to.
pub const LOG_FILE: &str = "teaops-agent.log";
/// PID file written by the daemonized supervisor.
pub const PID_FILE: &str = "teaops-supervisor.daemon.pid";

/// True when the process should stay in the foreground (no detaching).
pub fn wants_foreground() -> bool {
    if std::env::args()
        .skip(1)
        .any(|a| a == "--foreground" || a == "-f")
    {
        return true;
    }
    matches!(
        std::env::var("TEAOPS_FOREGROUND").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Detach from the terminal and run in the background. Logs/PID and the working
/// directory are anchored at the base dir (`/var/ops`, falling back to cwd) so
/// they're consistent regardless of where the agent was launched from.
#[cfg(unix)]
pub fn daemonize() -> anyhow::Result<()> {
    use std::fs::OpenOptions;

    let base = crate::paths::default_base_dir();
    let log_path = base.join(LOG_FILE);
    let pid_path = base.join(PID_FILE);

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let log_err = log.try_clone()?;

    daemonize::Daemonize::new()
        .pid_file(pid_path)
        .working_directory(&base)
        .stdout(log)
        .stderr(log_err)
        .start()?;
    Ok(())
}

#[cfg(not(unix))]
pub fn daemonize() -> anyhow::Result<()> {
    eprintln!("daemonization is only supported on unix; running in foreground");
    Ok(())
}
