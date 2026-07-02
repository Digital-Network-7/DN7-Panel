//! PTY-backed exec into a running container (the web terminal). Enters the
//! container's namespaces via `nsenter` with a pseudo-terminal as the shell's
//! controlling terminal; the master fd is handed back for the caller to bridge to
//! a WebSocket. Uses `Command` + `pre_exec` (the fork is std's, so only
//! async-signal-safe libc calls run in the child) rather than a manual fork.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use nix::pty::openpty;

use crate::container::state::{State, Status};
use crate::error::{Error, Result};

/// A live PTY exec session: the master side + the child process.
pub struct ExecPty {
    pub master: OwnedFd,
    pub child: Child,
}

impl ExecPty {
    /// Resize the pty to `cols` × `rows` (`TIOCSWINSZ` on the master).
    pub fn resize(&self, cols: u16, rows: u16) {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctl on our own master fd with a valid winsize pointer.
        unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
    }

    /// Best-effort terminate the session's child + reap it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Open a PTY and exec `argv` inside running container `id`'s namespaces, with the
/// pty slave as the controlling terminal. Returns the master + child.
pub fn exec_pty(id: &str, argv: &[String]) -> Result<ExecPty> {
    if argv.is_empty() {
        return Err(Error::Other("exec needs a command".into()));
    }
    let mut s = State::load(id)?;
    if s.refresh_status() != Status::Running {
        return Err(Error::BadState {
            id: id.into(),
            state: s.status.as_str(),
            action: "exec",
        });
    }

    let pty = openpty(None, None).map_err(Error::sys("openpty"))?;
    // Command takes ownership of three slave handles (stdin/stdout/stderr).
    let s_in = pty.slave.try_clone().map_err(Error::io("pty slave"))?;
    let s_out = pty.slave.try_clone().map_err(Error::io("pty slave"))?;
    let s_err = pty.slave; // moved

    // Enter the container's namespaces via setns(2) (no `nsenter`), then exec the
    // shell directly with the pty slave as its controlling terminal.
    let ns = super::open_ns_fds(s.pid)?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env("TERM", "xterm-256color")
        .stdin(Stdio::from(s_in))
        .stdout(Stdio::from(s_out))
        .stderr(Stdio::from(s_err));
    super::enter_namespaces(&mut cmd, ns); // setns pre_exec (runs first)
                                           // SAFETY: runs in the forked child before exec, AFTER the setns pre_exec; only
                                           // async-signal-safe libc calls. fd 0 is the pty slave, so it becomes the
                                           // controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::ioctl(0, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| Error::Other(format!("exec: {e}")))?;
    Ok(ExecPty {
        master: pty.master,
        child,
    })
}
