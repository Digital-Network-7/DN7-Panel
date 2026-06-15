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

use anyhow::{anyhow, Result};

use super::system_account;

/// The panel-user entity now lives in the domain layer; re-exported so call
/// sites (`crate::web::users::PanelUser`) stay stable while this module keeps
/// the system-account orchestration. Persistence is delegated to infra/store.
pub(crate) use crate::domain::identity::PanelUser;
pub(crate) use crate::infra::store::users::{load, save};

/// Serializes read-modify-write access to users.json so concurrent admin
/// requests can't lose updates: each `load -> modify -> save` runs under this
/// lock. Reads (`load`/`find`) are intentionally unlocked — a write is a single
/// atomic rename, so a concurrent reader sees either the old or new file, never
/// a partial one. Poison is recovered (the data is reloaded from disk each
/// time, so there's no in-memory invariant a panic could corrupt).
static USERS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run an atomic read-modify-write against users.json under `USERS_LOCK`.
fn mutate<T>(f: impl FnOnce(&mut Vec<PanelUser>) -> Result<T>) -> Result<T> {
    let _guard = USERS_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut users = load();
    let out = f(&mut users)?;
    save(&users)?;
    Ok(out)
}

pub fn find(username: &str) -> Option<PanelUser> {
    load().into_iter().find(|u| u.username == username)
}

/// A Linux username: lowercase start, then lowercase/digits/_/-; 1..=32 chars.
/// Conservative (NAME_REGEX-style) so it can't smuggle shell/flag characters.
/// Validators now live in the domain layer; re-exported so existing call sites
/// (`crate::web::users::valid_username` / `valid_pw_format`) stay stable.
pub(crate) use crate::domain::identity::{valid_pw_format, valid_username};

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
    // Fast-fail before any system-account side effects; re-checked under the
    // mutation lock below to close the create-vs-create race.
    if find(req.username).is_some() {
        return Err(anyhow!("ERR_CODE:users.exists"));
    }
    provision_system_account(req).await?;
    let (uid, _home) = system_account::getpwnam(req.username).unwrap_or((0, String::new()));
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
    let u = user.clone();
    mutate(move |users| {
        if users.iter().any(|x| x.username == u.username) {
            return Err(anyhow!("ERR_CODE:users.exists"));
        }
        users.push(u);
        Ok(())
    })?;
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
    if !valid_pw_format(req.pw_salt, req.pw_hash) {
        return Err(anyhow!("ERR_CODE:settings.pw_format"));
    }
    Ok(())
}

/// Provision the backing system account for a new panel user (delegates the OS
/// side to `system_account`).
async fn provision_system_account(req: &NewUser<'_>) -> Result<()> {
    system_account::provision(
        req.username,
        req.full_name,
        req.role == "admin",
        req.password,
    )
    .await
}

/// Delete a panel user and remove the backing system account (with its home).
pub async fn delete(username: &str) -> Result<()> {
    if find(username).is_none() {
        return Err(anyhow!("ERR_CODE:users.not_found"));
    }
    // Remove the OS account + home (best-effort: keep going if already gone).
    system_account::remove(username).await?;
    mutate(|users| {
        users.retain(|u| u.username != username);
        Ok(())
    })
}

/// Update mutable profile/credential fields, persisting the change atomically.
pub fn update<F: FnOnce(&mut PanelUser)>(username: &str, f: F) -> Result<()> {
    mutate(|users| {
        let u = users
            .iter_mut()
            .find(|u| u.username == username)
            .ok_or_else(|| anyhow!("ERR_CODE:users.not_found"))?;
        f(u);
        Ok(())
    })
}
