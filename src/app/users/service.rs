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

use crate::app::ports::users::UsersEnv;
use crate::core::Error;
use crate::infra::system;

/// Result alias for the user use-cases — semantic [`Error`], mapped to a wire
/// code at the single web boundary (`map_core_err`), consistent with
/// `app::account`.
type Result<T> = std::result::Result<T, Error>;

/// The panel-user entity lives in the domain layer; re-exported so call sites
/// (`crate::app::users::PanelUser`) stay stable while this module keeps the
/// system-account orchestration. Persistence is delegated to infra/store.
pub(crate) use crate::core::identity::PanelUser;
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
    save(&users).map_err(|e| Error::Persist(e.to_string()))?;
    Ok(out)
}

pub fn find(username: &str) -> Option<PanelUser> {
    load().into_iter().find(|u| u.username == username)
}

/// The live [`UsersEnv`]: real `useradd`/`userdel` over `infra::system` and the
/// `users.json` store under `USERS_LOCK`. The public `create`/`delete` wrappers
/// run the generic use-cases against this; tests swap in an in-memory fake.
struct LiveUsersEnv;

impl UsersEnv for LiveUsersEnv {
    async fn provision(
        &self,
        username: &str,
        full_name: &str,
        admin: bool,
        password: &str,
    ) -> anyhow::Result<()> {
        system::provision(username, full_name, admin, password).await
    }

    async fn remove(&self, username: &str) -> anyhow::Result<()> {
        system::remove(username).await
    }

    fn getpwnam(&self, username: &str) -> Option<(u32, String)> {
        system::getpwnam(username)
    }

    fn mutate(&self, f: &mut dyn FnMut(&mut Vec<PanelUser>) -> Result<()>) -> Result<()> {
        mutate(|users| f(users))
    }

    fn exists(&self, username: &str) -> bool {
        find(username).is_some()
    }
}

/// A Linux username: lowercase start, then lowercase/digits/_/-; 1..=32 chars.
/// Conservative (NAME_REGEX-style) so it can't smuggle shell/flag characters.
/// Validators live in the domain layer; re-exported so existing call sites
/// (`crate::app::users::valid_username` / `valid_pw_format`) stay stable.
pub(crate) use crate::core::identity::{valid_os_secret, valid_pw_format, valid_username};

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
    /// KDF scheme used to compute `pw_hash` (e.g. "s256:30000"); empty = legacy.
    pub pw_kdf: &'a str,
    pub password: &'a str,
}

pub async fn create(req: &NewUser<'_>) -> Result<PanelUser> {
    create_with(&LiveUsersEnv, req).await
}

/// Create a panel user against `env` (the live infra, or a test fake). Order:
/// validate → fast-fail existence → provision the OS account → persist, with a
/// re-check under the store lock to close the create-vs-create race.
async fn create_with(env: &impl UsersEnv, req: &NewUser<'_>) -> Result<PanelUser> {
    validate_new_user(req)?;
    // Fast-fail before any system-account side effects; re-checked under the
    // mutation lock below to close the create-vs-create race.
    if env.exists(req.username) {
        return Err(Error::UserExists);
    }
    env.provision(
        req.username,
        req.full_name,
        req.role == "admin",
        req.password,
    )
    .await
    .map_err(|e| Error::Persist(e.to_string()))?;

    // The backing OS account now EXISTS. Build + store the panel record, and on
    // ANY later failure roll the OS account back — otherwise a failed create
    // leaves an orphaned (possibly sudo) Linux account behind.
    let result: Result<PanelUser> = async {
        // getpwnam must resolve a just-created account; a None here is a real
        // failure — never default the stored uid to 0 (root's uid).
        let (uid, _home) = env
            .getpwnam(req.username)
            .ok_or_else(|| Error::Persist("无法解析新账号的 uid".to_string()))?;
        // Store Argon2id(verifier), not the client verifier itself, so a leaked
        // user file can't be replayed as a login.
        let pw_hash = crate::infra::auth::hash_verifier(&req.pw_hash.to_lowercase())
            .ok_or_else(|| Error::Persist("密码哈希失败".to_string()))?;
        let user = PanelUser {
            username: req.username.to_string(),
            pw_salt: req.pw_salt.to_string(),
            pw_hash,
            pw_kdf: req.pw_kdf.to_string(),
            role: req.role.to_string(),
            full_name: req.full_name.to_string(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            uid,
        };
        let mut pushed = Some(user.clone());
        env.mutate(&mut |users| {
            let u = pushed.take().ok_or(Error::UserExists)?;
            if users.iter().any(|x| x.username == u.username) {
                return Err(Error::UserExists);
            }
            users.push(u);
            Ok(())
        })?;
        Ok(user)
    }
    .await;

    if result.is_err() {
        let _ = env.remove(req.username).await; // best-effort rollback
    }
    result
}

/// Validate a new-user request (username chars, role, and well-formed hex
/// salt/hash) before any system-account side effects.
fn validate_new_user(req: &NewUser<'_>) -> Result<()> {
    if !valid_username(req.username) {
        return Err(Error::UsernameInvalid);
    }
    if !matches!(req.role, "admin" | "user") {
        return Err(Error::RoleInvalid);
    }
    if !valid_pw_format(req.pw_salt, req.pw_hash) {
        return Err(Error::PasswordMalformed);
    }
    // The plaintext is used to set the backing OS password via `chpasswd`;
    // reject control chars that could forge an extra record (see valid_os_secret).
    if !valid_os_secret(req.password) {
        return Err(Error::PasswordMalformed);
    }
    Ok(())
}

/// Delete a panel user and remove the backing system account (with its home).
pub async fn delete(username: &str) -> Result<()> {
    delete_with(&LiveUsersEnv, username).await
}

/// Delete a panel user against `env`. Order: existence check → remove the OS
/// account → drop from the store.
async fn delete_with(env: &impl UsersEnv, username: &str) -> Result<()> {
    if !env.exists(username) {
        return Err(Error::UserNotFound);
    }
    // Remove the OS account + home (best-effort: keep going if already gone).
    env.remove(username)
        .await
        .map_err(|e| Error::Persist(e.to_string()))?;
    env.mutate(&mut |users| {
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
            .ok_or(Error::UserNotFound)?;
        f(u);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// In-memory [`UsersEnv`] fake: records the OS side effects and holds the
    /// store in a RefCell so the create/delete orchestration can be exercised
    /// without touching the OS or disk.
    #[derive(Default)]
    struct FakeEnv {
        users: RefCell<Vec<PanelUser>>,
        provisioned: RefCell<Vec<String>>,
        removed: RefCell<Vec<String>>,
        /// When set, provision() fails (simulates a useradd error).
        fail_provision: bool,
        /// Extra username to inject into the store right before the locked
        /// re-check, to simulate a concurrent create winning the race.
        race_inject: Option<String>,
    }

    impl UsersEnv for FakeEnv {
        async fn provision(&self, u: &str, _f: &str, _a: bool, _p: &str) -> anyhow::Result<()> {
            if self.fail_provision {
                anyhow::bail!("useradd failed");
            }
            self.provisioned.borrow_mut().push(u.to_string());
            Ok(())
        }
        async fn remove(&self, u: &str) -> anyhow::Result<()> {
            self.removed.borrow_mut().push(u.to_string());
            Ok(())
        }
        fn getpwnam(&self, _u: &str) -> Option<(u32, String)> {
            Some((1001, "/home/x".into()))
        }
        fn mutate(&self, f: &mut dyn FnMut(&mut Vec<PanelUser>) -> Result<()>) -> Result<()> {
            let mut users = self.users.borrow_mut();
            if let Some(name) = &self.race_inject {
                if !users.iter().any(|u| &u.username == name) {
                    users.push(mk_user(name));
                }
            }
            f(&mut users)
        }
        fn exists(&self, u: &str) -> bool {
            self.users.borrow().iter().any(|x| x.username == u)
        }
    }

    fn mk_user(name: &str) -> PanelUser {
        PanelUser {
            username: name.into(),
            pw_salt: "0".repeat(32),
            pw_hash: "a".repeat(64),
            pw_kdf: String::new(),
            role: "user".into(),
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            uid: 0,
        }
    }

    /// Build a valid request with owned salt/hash held by the caller's bindings.
    fn fixtures() -> (String, String) {
        ("0".repeat(32), "a".repeat(64))
    }
    fn req<'a>(username: &'a str, role: &'a str, salt: &'a str, hash: &'a str) -> NewUser<'a> {
        NewUser {
            username,
            role,
            full_name: "Test User",
            pw_salt: salt,
            pw_hash: hash,
            pw_kdf: "",
            password: "s3cret-pw",
        }
    }

    #[tokio::test]
    async fn create_happy_path_provisions_and_persists() {
        let env = FakeEnv::default();
        let (s, h) = fixtures();
        let u = create_with(&env, &req("alice", "admin", &s, &h))
            .await
            .unwrap();
        assert_eq!(u.username, "alice");
        assert_eq!(u.role, "admin");
        assert_eq!(env.provisioned.borrow().as_slice(), ["alice"]);
        assert_eq!(env.users.borrow().len(), 1);
    }

    #[tokio::test]
    async fn create_rejects_invalid_before_side_effects() {
        let env = FakeEnv::default();
        let (s, h) = fixtures();
        // Bad username → UsernameInvalid, and no OS provisioning happened.
        let e = create_with(&env, &req("Bad Name", "user", &s, &h))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::UsernameInvalid));
        assert!(env.provisioned.borrow().is_empty());
        // Bad role.
        let e = create_with(&env, &req("ok", "wheel", &s, &h))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::RoleInvalid));
    }

    #[tokio::test]
    async fn create_fast_fails_on_existing_user() {
        let env = FakeEnv::default();
        env.users.borrow_mut().push(mk_user("alice"));
        let (s, h) = fixtures();
        let e = create_with(&env, &req("alice", "user", &s, &h))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::UserExists));
        assert!(env.provisioned.borrow().is_empty()); // never provisioned
    }

    #[tokio::test]
    async fn create_loses_race_rechecks_under_lock() {
        // Passes the fast-fail check, provisions, then a concurrent create wins
        // (injected into the store) → the locked re-check rejects with UserExists.
        let env = FakeEnv {
            race_inject: Some("alice".into()),
            ..Default::default()
        };
        let (s, h) = fixtures();
        let e = create_with(&env, &req("alice", "user", &s, &h))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::UserExists));
        assert_eq!(env.provisioned.borrow().as_slice(), ["alice"]); // OS side ran
        assert_eq!(env.users.borrow().len(), 1); // only the racing one
    }

    #[tokio::test]
    async fn create_surfaces_provision_failure() {
        let env = FakeEnv {
            fail_provision: true,
            ..Default::default()
        };
        let (s, h) = fixtures();
        let e = create_with(&env, &req("alice", "user", &s, &h))
            .await
            .unwrap_err();
        assert!(matches!(e, Error::Persist(_)));
        assert!(env.users.borrow().is_empty());
    }

    #[tokio::test]
    async fn delete_removes_os_account_and_store_entry() {
        let env = FakeEnv::default();
        env.users.borrow_mut().push(mk_user("alice"));
        delete_with(&env, "alice").await.unwrap();
        assert_eq!(env.removed.borrow().as_slice(), ["alice"]);
        assert!(env.users.borrow().is_empty());
    }

    #[tokio::test]
    async fn delete_missing_user_errors_before_os_call() {
        let env = FakeEnv::default();
        let e = delete_with(&env, "ghost").await.unwrap_err();
        assert!(matches!(e, Error::UserNotFound));
        assert!(env.removed.borrow().is_empty());
    }
}
