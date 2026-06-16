//! Port for the panel-user use-cases. The live implementation (`infra`-backed)
//! runs `useradd`/`userdel` and persists `users.json`; tests implement it with
//! an in-memory fake so the create/delete orchestration (validation order,
//! create-race re-check, persistence) is exercised without touching the OS.

use crate::core::identity::PanelUser;

/// The environment a user use-case runs against: the backing system-account
/// side effects + the panel-user store. One cohesive capability port (not split
/// per method) so a use-case takes a single `env` argument.
#[allow(async_fn_in_trait)] // used only via generics (`impl UsersEnv`), never as `dyn`
pub(crate) trait UsersEnv {
    /// Provision the backing OS account (useradd, sudo group when admin, locked
    /// password, then set the panel password).
    async fn provision(
        &self,
        username: &str,
        full_name: &str,
        admin: bool,
        password: &str,
    ) -> anyhow::Result<()>;

    /// Remove the backing OS account and its home (best-effort).
    async fn remove(&self, username: &str) -> anyhow::Result<()>;

    /// Resolve a username to `(uid, home)`; `None` when the account is absent.
    fn getpwnam(&self, username: &str) -> Option<(u32, String)>;

    /// Run an atomic read-modify-write against the panel-user store, serialized
    /// so concurrent creates can't lose an update (the live impl holds a lock;
    /// the closure receives the current users and may mutate them in place).
    fn mutate(
        &self,
        f: &mut dyn FnMut(&mut Vec<PanelUser>) -> Result<(), crate::core::Error>,
    ) -> Result<(), crate::core::Error>;

    /// Whether a panel user with `username` already exists (unlocked read).
    fn exists(&self, username: &str) -> bool;
}
