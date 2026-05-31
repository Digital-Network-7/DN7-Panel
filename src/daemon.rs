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
    if std::env::args().skip(1).any(|a| a == "--foreground" || a == "-f") {
        return true;
    }
    matches!(
        std::env::var("TEAOPS_FOREGROUND").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// Detach from the terminal and run in the background. The working directory is
/// left unchanged so relative paths (token file, runtime dir, log) resolve the
/// same as in the foreground.
#[cfg(unix)]
pub fn daemonize() -> anyhow::Result<()> {
    use std::fs::OpenOptions;

    let log = OpenOptions::new().create(true).append(true).open(LOG_FILE)?;
    let log_err = log.try_clone()?;

    daemonize::Daemonize::new()
        .pid_file(PID_FILE)
        .working_directory(".")
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
