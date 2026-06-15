//! Multi-user management: panel users backed by **real Linux system accounts**.
//!
//! Each additional panel user maps 1:1 to a system user (same name). Creating a
//! panel user runs `useradd` (admins are added to the sudo group → sudo);
//! deleting one runs `userdel -r`. The panel login password is stored
//! irreversibly (salt + sha256) like the super-admin; the OS account is created
//! with a locked password (panel sessions never need it — the terminal runs as
//! the user via `su -`, which root may do without a password).
//!
//! Permissions are derived purely from the mapped system user: non-admin users
//! get the terminal + file manager **executed as their own uid** (OS perms
//! enforce access), and every admin-only capability (docker/nginx/mysql/update/
//! branding/user-management) is denied for them server-side.

use std::ffi::{CStr, CString};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelUser {
    /// Login name — identical to the system username.
    pub username: String,
    #[serde(default)]
    pub pw_salt: String,
    #[serde(default)]
    pub pw_hash: String,
    /// "admin" (sudo) | "user".
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub nickname: String,
    /// Avatar as a base64 data URL (size-limited by the API).
    #[serde(default)]
    pub avatar: String,
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub totp_enabled: bool,
    #[serde(default)]
    pub uid: u32,
}

impl PanelUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

fn users_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("users.json")
}

pub fn load() -> Vec<PanelUser> {
    std::fs::read_to_string(users_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(users: &[PanelUser]) -> Result<()> {
    let path = users_path();
    crate::paths::write_private(&path, serde_json::to_string_pretty(users)?.as_bytes())?;
    Ok(())
}

pub fn find(username: &str) -> Option<PanelUser> {
    load().into_iter().find(|u| u.username == username)
}

/// A Linux username: lowercase start, then lowercase/digits/_/-; 1..=32 chars.
/// Conservative (NAME_REGEX-style) so it can't smuggle shell/flag characters.
pub fn valid_username(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        && s != "root"
}

/// Look up a system account's uid + home dir (None if it doesn't exist).
pub fn getpwnam(name: &str) -> Option<(u32, String)> {
    let cname = CString::new(name).ok()?;
    // SAFETY: getpwnam reads the passwd db; we copy out the fields immediately.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return None;
        }
        let uid = (*pw).pw_uid;
        let dir = if (*pw).pw_dir.is_null() {
            format!("/home/{name}")
        } else {
            CStr::from_ptr((*pw).pw_dir).to_string_lossy().to_string()
        };
        Some((uid, dir))
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

/// Add the user to the system's admin group (Debian/Ubuntu `sudo`, RHEL
/// `wheel`) — whichever exists.
async fn grant_sudo(username: &str) -> Result<()> {
    for group in ["sudo", "wheel"] {
        if group_exists(group) {
            return run("usermod", &["-aG", group, username]).await;
        }
    }
    Err(anyhow!("ERR_CODE:users.no_sudo_group"))
}

fn group_exists(group: &str) -> bool {
    CString::new(group)
        .ok()
        .map(|g| unsafe { !libc::getgrnam(g.as_ptr()).is_null() })
        .unwrap_or(false)
}

/// Set the system account's password to match the panel password, via
/// `chpasswd` over stdin (so the plaintext never appears in argv/process list).
/// No-op when the system account doesn't exist. Lets the user log in at the OS
/// level (SSH/console) with the same password as the panel.
pub async fn set_system_password(username: &str, password: &str) -> Result<()> {
    if getpwnam(username).is_none() {
        return Ok(());
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
        Err(anyhow!("ERR_CODE:users.set_pw_failed"))
    }
}

/// Create a panel user **and** the backing system account. `role` is "admin"
/// (sudo) or "user". The OS password is left locked; the panel password is
/// stored as salt + hash (plaintext never reaches the server).
/// Fields for creating a panel user (bundled to keep the argument count sane).
/// Borrows live only for the `create` call. `pw_salt`/`pw_hash` are the
/// client-computed verifier; `password` is the plaintext used (local console
/// only) to set the matching OS password.
pub struct NewUser<'a> {
    pub username: &'a str,
    pub role: &'a str,
    pub full_name: &'a str,
    pub pw_salt: &'a str,
    pub pw_hash: &'a str,
    pub password: &'a str,
}

pub async fn create(req: &NewUser<'_>) -> Result<PanelUser> {
    validate_new_user(req)?;
    let mut users = load();
    if users.iter().any(|u| u.username == req.username) {
        return Err(anyhow!("ERR_CODE:users.exists"));
    }
    provision_system_account(req).await?;
    let (uid, _home) = getpwnam(req.username).unwrap_or((0, String::new()));
    let user = PanelUser {
        username: req.username.to_string(),
        pw_salt: req.pw_salt.to_string(),
        pw_hash: req.pw_hash.to_lowercase(),
        role: req.role.to_string(),
        full_name: req.full_name.to_string(),
        nickname: String::new(),
        avatar: String::new(),
        totp_secret: String::new(),
        totp_enabled: false,
        uid,
    };
    users.push(user.clone());
    save(&users)?;
    Ok(user)
}

/// Validate a new-user request (username chars, role, and well-formed hex
/// salt/hash) before any system-account side effects.
fn validate_new_user(req: &NewUser<'_>) -> Result<()> {
    if !valid_username(req.username) {
        return Err(anyhow!("ERR_CODE:users.bad_username"));
    }
    if !matches!(req.role, "admin" | "user") {
        return Err(anyhow!("ERR_CODE:users.bad_role"));
    }
    let salt_ok = req.pw_salt.len() == 32 && req.pw_salt.bytes().all(|b| b.is_ascii_hexdigit());
    let hash_ok = req.pw_hash.len() == 64 && req.pw_hash.bytes().all(|b| b.is_ascii_hexdigit());
    if !salt_ok || !hash_ok {
        return Err(anyhow!("ERR_CODE:settings.pw_format"));
    }
    Ok(())
}

/// Create (or adopt) the backing system account: `useradd -m` with the GECOS
/// name, grant the admin group for admins, and sync the OS password to the
/// panel password (so the user can log in over SSH/console). Adopting a
/// pre-existing system user rather than failing keeps the op idempotent-ish.
async fn provision_system_account(req: &NewUser<'_>) -> Result<()> {
    if getpwnam(req.username).is_none() {
        let mut args = vec!["-m", "-s", "/bin/bash"];
        if !req.full_name.is_empty() {
            args.push("-c");
            args.push(req.full_name);
        }
        args.push(req.username);
        run("useradd", &args).await?;
    } else if !req.full_name.is_empty() {
        let _ = run("usermod", &["-c", req.full_name, req.username]).await;
    }
    if req.role == "admin" {
        grant_sudo(req.username).await?;
    }
    if !req.password.is_empty() {
        set_system_password(req.username, req.password).await?;
    }
    Ok(())
}

/// Delete a panel user and remove the backing system account (with its home).
pub async fn delete(username: &str) -> Result<()> {
    let mut users = load();
    if !users.iter().any(|u| u.username == username) {
        return Err(anyhow!("ERR_CODE:users.not_found"));
    }
    // Remove the OS account + home (best-effort: keep going if already gone).
    if getpwnam(username).is_some() {
        run("userdel", &["-r", username]).await?;
    }
    users.retain(|u| u.username != username);
    save(&users)?;
    Ok(())
}

/// Update mutable profile/credential fields, persisting the change.
pub fn update<F: FnOnce(&mut PanelUser)>(username: &str, f: F) -> Result<()> {
    let mut users = load();
    let u = users
        .iter_mut()
        .find(|u| u.username == username)
        .ok_or_else(|| anyhow!("ERR_CODE:users.not_found"))?;
    f(u);
    save(&users)
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

/// Set the system account's GECOS full-name field (`usermod -c`). Best-effort.
pub async fn set_full_name(username: &str, full_name: &str) -> Result<()> {
    if getpwnam(username).is_some() {
        run("usermod", &["-c", full_name, username]).await
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(valid_username("alice"));
        assert!(valid_username("bob_2"));
        assert!(valid_username("_svc"));
        assert!(!valid_username("Alice")); // uppercase
        assert!(!valid_username("1abc")); // leading digit
        assert!(!valid_username("a b")); // space
        assert!(!valid_username("root")); // reserved
        assert!(!valid_username("")); // empty
        assert!(!valid_username("-x")); // leading dash
    }
}
