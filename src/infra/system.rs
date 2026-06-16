//! System-account layer: the OS side of a panel user.
//!
//! A panel user maps 1:1 to a real Linux account (same name). This module owns
//! every privileged, OS-touching operation — `useradd`/`userdel`/`usermod`,
//! sudo-group membership, `chpasswd`, and passwd-db lookups — isolated here so
//! the panel-identity/store layer (`users.rs`) and the authorization layer
//! (`server::accounts`) stay free of direct system calls. Keeping the
//! root-level command surface in one file also makes it easy to audit.

use std::ffi::{CStr, CString};

use anyhow::{anyhow, Result};

use crate::domain::identity::SystemUserError;

/// Build the transitional `anyhow` error for a typed [`SystemUserError`]:
/// prefixes the semantic code with the `ERR_CODE:` transport marker the
/// `op_err_body` boundary parses. The marker lives here (infra), not in domain.
fn users_err(e: SystemUserError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

/// Look up a system account's uid + home dir (None if it doesn't exist). Uses
/// the reentrant `getpwnam_r` (no shared static buffer → thread-safe).
pub fn getpwnam(name: &str) -> Option<(u32, String)> {
    let cname = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        // SAFETY: `getpwnam_r` fills `pwd` + `buf` and sets `result` to `&pwd`
        // on success (or null when the user doesn't exist). Reentrant: no shared
        // static buffer. We copy fields out while `buf` is still alive.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 65536 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let uid = pwd.pw_uid;
        let dir = if pwd.pw_dir.is_null() {
            format!("/home/{name}")
        } else {
            // SAFETY: `pw_dir` points into `buf`, still alive here.
            unsafe { CStr::from_ptr(pwd.pw_dir) }
                .to_string_lossy()
                .to_string()
        };
        return Some((uid, dir));
    }
}

/// Run a system command to completion, returning an error with stderr on a
/// non-zero exit. Used for useradd/userdel/usermod (root-only).
async fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(anyhow!(
            "{cmd} 失败：{}",
            err.trim().chars().take(200).collect::<String>()
        ))
    }
}

fn group_exists(group: &str) -> bool {
    CString::new(group)
        .ok()
        .map(|g| unsafe { !libc::getgrnam(g.as_ptr()).is_null() })
        .unwrap_or(false)
}

/// Add the user to the system's admin group (Debian/Ubuntu `sudo`, RHEL
/// `wheel`) — whichever exists.
async fn grant_sudo(username: &str) -> Result<()> {
    for group in ["sudo", "wheel"] {
        if group_exists(group) {
            return run("usermod", &["-aG", group, username]).await;
        }
    }
    Err(users_err(SystemUserError::NoSudoGroup))
}

/// Create (or adopt) the backing system account: `useradd -m` with the GECOS
/// name, grant the admin group for admins, and sync the OS password to the
/// panel password (so the user can log in over SSH/console). Adopting a
/// pre-existing system user rather than failing keeps the op idempotent-ish.
pub async fn provision(username: &str, full_name: &str, admin: bool, password: &str) -> Result<()> {
    // The GECOS field lands in colon/newline-delimited /etc/passwd; only pass it
    // when free of field-forging chars (control / ':'), else drop it. See gecos_ok.
    let gecos = if !full_name.is_empty() && gecos_ok(full_name) {
        Some(full_name)
    } else {
        None
    };
    if getpwnam(username).is_none() {
        let mut args = vec!["-m", "-s", "/bin/bash"];
        if let Some(fname) = gecos {
            args.push("-c");
            args.push(fname);
        }
        args.push(username);
        run("useradd", &args).await?;
    } else if let Some(fname) = gecos {
        let _ = run("usermod", &["-c", fname, username]).await;
    }
    if admin {
        grant_sudo(username).await?;
    }
    if !password.is_empty() {
        set_system_password(username, password).await?;
    }
    Ok(())
}

/// Remove the system account and its home directory (`userdel -r`). No-op when
/// the account doesn't exist.
pub async fn remove(username: &str) -> Result<()> {
    if getpwnam(username).is_some() {
        run("userdel", &["-r", username]).await
    } else {
        Ok(())
    }
}

/// Set the system account's password to match the panel password, via
/// `chpasswd` over stdin (so the plaintext never appears in argv/process list).
/// No-op when the system account doesn't exist. Lets the user log in at the OS
/// level (SSH/console) with the same password as the panel.
pub async fn set_system_password(username: &str, password: &str) -> Result<()> {
    if getpwnam(username).is_none() {
        return Ok(());
    }
    // Defense in depth at the OS boundary: a control char in `password` would
    // forge an extra `user:password` chpasswd record (callers validate too).
    if !crate::domain::identity::valid_os_secret(password) {
        return Err(users_err(SystemUserError::SetPwFailed));
    }
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 chpasswd：{e}"))?;
    if let Some(mut si) = child.stdin.take() {
        let _ = si
            .write_all(format!("{username}:{password}\n").as_bytes())
            .await;
        let _ = si.shutdown().await;
    }
    let out = child.wait_with_output().await.map_err(|e| anyhow!("{e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(users_err(SystemUserError::SetPwFailed))
    }
}

/// Grant or revoke the system admin group (sudo/wheel) for a user — used when
/// an account's role changes between admin and user.
pub async fn set_sudo(username: &str, on: bool) -> Result<()> {
    if on {
        grant_sudo(username).await
    } else {
        for group in ["sudo", "wheel"] {
            if group_exists(group) {
                let _ = run("gpasswd", &["-d", username, group]).await;
            }
        }
        Ok(())
    }
}

/// Whether a GECOS (full-name) value is safe to write into /etc/passwd: no ASCII
/// control char (a newline would forge a passwd line) and no ':' (the passwd
/// field separator). Defense in depth — `useradd`/`usermod` also validate, but
/// we don't rely on the host tool's checks (mirrors the chpasswd hardening).
fn gecos_ok(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b':')
}

/// Set the system account's GECOS full-name field (`usermod -c`). Best-effort;
/// a field-forging value is refused (not written) rather than passed through.
pub async fn set_full_name(username: &str, full_name: &str) -> Result<()> {
    if !gecos_ok(full_name) {
        return Err(users_err(SystemUserError::BadFullName));
    }
    if getpwnam(username).is_some() {
        run("usermod", &["-c", full_name, username]).await
    } else {
        Ok(())
    }
}
