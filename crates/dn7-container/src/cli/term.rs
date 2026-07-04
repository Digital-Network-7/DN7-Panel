//! The interactive PTY bridge behind `exec -it` / `exec-pty`: raw local
//! termios, stdin/stdout pumps, and window-size mirroring.

use crate::container;

/// Bridge the caller's terminal to an interactive PTY exec (docker `exec -it`):
/// raw local termios (restored on exit), stdin → pty pump, pty → stdout pump,
/// and the local window size mirrored onto the pty (initial + 300ms poll — no
/// signal-handler plumbing needed for SIGWINCH fidelity at this cadence).
pub(super) fn exec_tty(id: &str, cmd: &[String]) -> Result<i32, String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let argv: Vec<String> = if cmd.is_empty() {
        vec!["/bin/sh".to_string()]
    } else {
        cmd.to_vec()
    };
    let session = container::exec_pty(id, &argv).map_err(|e| e.to_string())?;
    let container::ExecPty { master, mut child } = session;

    // Put OUR terminal in raw mode so keystrokes (incl. Ctrl-C) go to the
    // container shell; guaranteed-restored on every exit path via Drop.
    struct RawGuard(Option<nix::sys::termios::Termios>);
    impl Drop for RawGuard {
        fn drop(&mut self) {
            if let Some(t) = &self.0 {
                let _ = nix::sys::termios::tcsetattr(
                    std::io::stdin(),
                    nix::sys::termios::SetArg::TCSANOW,
                    t,
                );
            }
        }
    }
    let stdin_tty = nix::unistd::isatty(std::io::stdin().as_raw_fd()).unwrap_or(false);
    let _raw = if stdin_tty {
        let saved = nix::sys::termios::tcgetattr(std::io::stdin())
            .map_err(|e| format!("tcgetattr: {e}"))?;
        let mut raw = saved.clone();
        nix::sys::termios::cfmakeraw(&mut raw);
        nix::sys::termios::tcsetattr(std::io::stdin(), nix::sys::termios::SetArg::TCSANOW, &raw)
            .map_err(|e| format!("tcsetattr: {e}"))?;
        RawGuard(Some(saved))
    } else {
        RawGuard(None)
    };

    let done = Arc::new(AtomicBool::new(false));
    let mfd = master.as_raw_fd();

    // Mirror our window size onto the pty (now + whenever it changes).
    let sync_winsize = move || {
        let mut ws = libc::winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: ioctls on our own stdin/pty fds with a valid winsize struct.
        unsafe {
            if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
                libc::ioctl(mfd, libc::TIOCSWINSZ, &ws);
            }
        }
        (ws.ws_col, ws.ws_row)
    };
    if stdin_tty {
        let mut last = sync_winsize();
        let done_w = done.clone();
        std::thread::spawn(move || {
            while !done_w.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let cur = sync_winsize();
                if cur != last {
                    last = cur;
                }
            }
        });
    }

    // stdin → pty pump. Blocks on read; exits with the process (the pty read
    // loop below ends when the shell exits, and main returns right after).
    let mut master_w = std::fs::File::from(
        master
            .try_clone()
            .map_err(|e| format!("clone pty fd: {e}"))?,
    );
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if master_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // pty → stdout pump (main thread). EOF when the shell exits.
    let mut f = std::fs::File::from(master);
    let mut out = std::io::stdout();
    let mut buf = [0u8; 4096];
    loop {
        match f.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = out.flush();
            }
        }
    }
    done.store(true, Ordering::Relaxed);
    let code = child.wait().ok().and_then(|st| st.code()).unwrap_or(0);
    Ok(code)
}
