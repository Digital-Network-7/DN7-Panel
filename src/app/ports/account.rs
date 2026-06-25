//! Ports for the account use-cases. The web layer implements `AccountEnv` over
//! the live console state (settings/users store, session guard, audit sink,
//! system accounts); tests implement it with in-memory fakes.

use crate::core::identity::Principal;
use crate::core::Error;

/// The environment an account use-case runs against: credential persistence +
/// the side effects a credential change triggers (OS password sync, session
/// revocation, audit). Kept as one cohesive capability port (not split per
/// method) so a use-case takes a single `env` argument.
#[allow(async_fn_in_trait)] // used only via generics (`impl AccountEnv`), never as `dyn`
pub(crate) trait AccountEnv {
    /// The account's currently stored password verifier (empty if none).
    fn current_verifier(&self, who: &Principal) -> String;

    /// Consume a one-time challenge nonce (true if it was valid + unused). The
    /// current-password proof carries this nonce so the exact request can't be
    /// trivially replayed.
    fn consume_challenge(&self, nonce: &str) -> bool;

    /// Whether the presented `verifier` (the client-computed
    /// `deriveVerifier(salt, pw, kdf)`) matches the account's `stored` credential
    /// — Argon2id verify, or constant-time compare for a legacy raw verifier.
    fn verify_current(&self, stored: &str, verifier: &str) -> bool;

    /// Persist a new password verifier (salt + hash + KDF scheme) for the account.
    fn save_password(&self, who: &Principal, salt: &str, hash: &str, kdf: &str)
        -> Result<(), Error>;

    /// Sync the backing OS account's password (best-effort; no-op when the
    /// account has no system user).
    async fn sync_system_password(&self, system_user: &str, plaintext: &str);

    /// Revoke the account's other sessions/tickets, keeping `keep` (the caller's
    /// current token) alive.
    fn revoke_other_sessions(&self, username: &str, keep: Option<&str>);

    /// The account's pending/active TOTP secret (empty when none).
    fn read_totp(&self, who: &Principal) -> String;

    /// Persist the account's TOTP secret + enabled flag.
    fn write_totp(&self, who: &Principal, secret: &str, enabled: bool) -> Result<(), Error>;

    /// Verify a TOTP `code` against `secret` (pure algorithm behind the port so
    /// the use-case doesn't depend on the crypto module's location).
    fn verify_totp(&self, secret: &str, code: &str) -> bool;

    /// Append an audit record for an account action (actor == target).
    fn audit(&self, username: &str, action: &str);
}
