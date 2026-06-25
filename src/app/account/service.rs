//! Account use-cases. One explicit entry point each; the handler only parses
//! the request, resolves the `Principal`, calls the use-case, and maps the
//! result. The orchestration sequence (validate → verify → persist → OS sync →
//! revoke sessions → audit) lives here so no entry point can forget a step.

use crate::app::ports::account::AccountEnv;
use crate::core::identity::{valid_os_secret, valid_pw_format, Principal};
use crate::core::Error;

/// A self-service password change request: the client-computed new verifier
/// (`salt`/`hash`), the `old_verifier` proving the current password, the
/// `plaintext` (system users only) that syncs the OS password, and `keep_token`
/// (the caller's current session, kept alive while the rest are revoked).
/// Bundled into a struct to keep [`change_password`] within the param limit.
pub(crate) struct PasswordChange<'a> {
    pub(crate) salt: &'a str,
    pub(crate) hash: &'a str,
    /// KDF scheme the new `hash` was computed with (e.g. "s256:30000"); stored so
    /// login recomputes the same verifier.
    pub(crate) kdf: &'a str,
    /// One-time challenge nonce the `old_verifier` proof is bound to.
    pub(crate) nonce: &'a str,
    /// `sha256(nonce ":" current_verifier)` — proves knowledge of the current
    /// password, bound to a single-use nonce so it can't be replayed.
    pub(crate) old_verifier: &'a str,
    pub(crate) plaintext: &'a str,
    pub(crate) keep_token: Option<&'a str>,
}

/// Change the caller's own panel password.
pub(crate) async fn change_password(
    env: &impl AccountEnv,
    who: &Principal,
    ch: PasswordChange<'_>,
) -> Result<(), Error> {
    if !valid_pw_format(ch.salt, ch.hash) {
        return Err(Error::PasswordMalformed);
    }
    // The plaintext (system users only) is fed to `chpasswd` over stdin; reject
    // any control char that could forge an extra `user:password` record and
    // rewrite another OS account (incl. root). Checked before persisting so a
    // malformed value never leaves the panel password half-changed.
    if !ch.plaintext.is_empty() && !valid_os_secret(ch.plaintext) {
        return Err(Error::PasswordMalformed);
    }
    let current = env.current_verifier(who);
    // Bind a single-use challenge nonce into the current-password proof (as the
    // login path does) so a captured `old_verifier` can't be replayed. Consume
    // the nonce first so a wrong proof still burns it.
    let nonce_ok = env.consume_challenge(ch.nonce);
    if current.is_empty() || !nonce_ok || !env.verify_proof(ch.nonce, &current, ch.old_verifier) {
        return Err(Error::OldPasswordWrong);
    }
    env.save_password(who, ch.salt, &ch.hash.to_lowercase(), ch.kdf)?;
    if !ch.plaintext.is_empty() {
        if let Some(sys) = &who.system_user {
            env.sync_system_password(sys, ch.plaintext).await;
        }
    }
    // Any other (possibly leaked) sessions die immediately; keep the caller's.
    env.revoke_other_sessions(&who.username, ch.keep_token);
    env.audit(&who.username, "account.password");
    Ok(())
}

/// Enable TOTP 2FA after verifying a live code against the pending secret.
pub(crate) fn enable_2fa(
    env: &impl AccountEnv,
    who: &Principal,
    code: &str,
    keep_token: Option<&str>,
) -> Result<(), Error> {
    let secret = env.read_totp(who);
    if secret.is_empty() || !env.verify_totp(&secret, code) {
        return Err(Error::TotpInvalid);
    }
    env.write_totp(who, &secret, true)?;
    env.revoke_other_sessions(&who.username, keep_token);
    env.audit(&who.username, "account.2fa_enable");
    Ok(())
}

/// Disable TOTP 2FA. When a secret is set, a valid current code is required.
pub(crate) fn disable_2fa(
    env: &impl AccountEnv,
    who: &Principal,
    code: &str,
    keep_token: Option<&str>,
) -> Result<(), Error> {
    let secret = env.read_totp(who);
    if !secret.is_empty() && !env.verify_totp(&secret, code) {
        return Err(Error::TotpInvalid);
    }
    env.write_totp(who, "", false)?;
    env.revoke_other_sessions(&who.username, keep_token);
    env.audit(&who.username, "account.2fa_disable");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// In-memory fake environment (justifies the AccountEnv port per steering §5).
    #[derive(Default)]
    struct FakeEnv {
        verifier: String,
        nonce_ok: bool,
        totp_secret: String,
        totp_code_ok: bool,
        saved: RefCell<Option<(String, String)>>,
        totp_written: RefCell<Option<(String, bool)>>,
        synced: RefCell<Option<(String, String)>>,
        revoked: RefCell<Option<(String, Option<String>)>>,
        audited: RefCell<Vec<String>>,
    }

    impl AccountEnv for FakeEnv {
        fn current_verifier(&self, _who: &Principal) -> String {
            self.verifier.clone()
        }
        fn consume_challenge(&self, _nonce: &str) -> bool {
            self.nonce_ok
        }
        // Models the real nonce-bound proof check: a non-empty verifier and a
        // proof that matches it (case-insensitively, as the real hex compare is).
        fn verify_proof(&self, _nonce: &str, verifier: &str, proof: &str) -> bool {
            !verifier.is_empty() && proof.eq_ignore_ascii_case(verifier)
        }
        fn save_password(
            &self,
            _who: &Principal,
            salt: &str,
            hash: &str,
            _kdf: &str,
        ) -> Result<(), Error> {
            *self.saved.borrow_mut() = Some((salt.to_string(), hash.to_string()));
            Ok(())
        }
        async fn sync_system_password(&self, system_user: &str, plaintext: &str) {
            *self.synced.borrow_mut() = Some((system_user.to_string(), plaintext.to_string()));
        }
        fn revoke_other_sessions(&self, username: &str, keep: Option<&str>) {
            *self.revoked.borrow_mut() = Some((username.to_string(), keep.map(str::to_string)));
        }
        fn read_totp(&self, _who: &Principal) -> String {
            self.totp_secret.clone()
        }
        fn write_totp(&self, _who: &Principal, secret: &str, enabled: bool) -> Result<(), Error> {
            *self.totp_written.borrow_mut() = Some((secret.to_string(), enabled));
            Ok(())
        }
        fn verify_totp(&self, _secret: &str, _code: &str) -> bool {
            self.totp_code_ok
        }
        fn audit(&self, username: &str, action: &str) {
            self.audited
                .borrow_mut()
                .push(format!("{username}:{action}"));
        }
    }

    fn principal(system: Option<&str>) -> Principal {
        Principal {
            username: "alice".into(),
            is_super: system.is_none(),
            system_user: system.map(str::to_string),
        }
    }

    const SALT: &str = "0123456789abcdef0123456789abcdef";
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Terse builder for a `PasswordChange` in tests. The nonce is a fixed stub;
    /// whether it's "valid" is controlled by `FakeEnv::nonce_ok`.
    fn pc<'a>(
        salt: &'a str,
        hash: &'a str,
        old_verifier: &'a str,
        plaintext: &'a str,
        keep_token: Option<&'a str>,
    ) -> PasswordChange<'a> {
        PasswordChange {
            salt,
            hash,
            kdf: "s256:30000",
            nonce: "nonce",
            old_verifier,
            plaintext,
            keep_token,
        }
    }

    #[tokio::test]
    async fn rejects_bad_format() {
        let env = FakeEnv::default();
        let r = change_password(&env, &principal(None), pc("short", HASH, "", "", None)).await;
        assert!(matches!(r, Err(Error::PasswordMalformed)));
        assert!(env.saved.borrow().is_none());
    }

    #[tokio::test]
    async fn rejects_wrong_old_password() {
        let env = FakeEnv {
            verifier: "the-real-verifier".into(),
            nonce_ok: true,
            ..Default::default()
        };
        let r = change_password(&env, &principal(None), pc(SALT, HASH, "wrong", "", None)).await;
        assert!(matches!(r, Err(Error::OldPasswordWrong)));
        assert!(env.saved.borrow().is_none());
    }

    #[tokio::test]
    async fn rejects_replayed_or_invalid_nonce() {
        // Correct proof, but the challenge nonce is invalid/already-consumed.
        let env = FakeEnv {
            verifier: "cur".into(),
            nonce_ok: false,
            ..Default::default()
        };
        let r = change_password(&env, &principal(None), pc(SALT, HASH, "cur", "", None)).await;
        assert!(matches!(r, Err(Error::OldPasswordWrong)));
        assert!(env.saved.borrow().is_none());
    }

    #[tokio::test]
    async fn happy_path_super_admin() {
        let env = FakeEnv {
            verifier: "cur".into(),
            nonce_ok: true,
            ..Default::default()
        };
        let r = change_password(
            &env,
            &principal(None),
            pc(SALT, HASH, "CUR", "", Some("tok")),
        )
        .await;
        assert!(r.is_ok());
        assert_eq!(env.saved.borrow().as_ref().unwrap().0, SALT);
        assert!(env.synced.borrow().is_none()); // super-admin has no system user
        assert_eq!(
            env.revoked.borrow().as_ref().unwrap(),
            &("alice".to_string(), Some("tok".to_string()))
        );
        assert_eq!(env.audited.borrow().as_slice(), ["alice:account.password"]);
    }

    #[tokio::test]
    async fn happy_path_system_user_syncs_os_password() {
        let env = FakeEnv {
            verifier: "cur".into(),
            nonce_ok: true,
            ..Default::default()
        };
        let who = principal(Some("alice"));
        let r = change_password(&env, &who, pc(SALT, HASH, "cur", "Secret123", None)).await;
        assert!(r.is_ok());
        assert_eq!(
            env.synced.borrow().as_ref().unwrap(),
            &("alice".to_string(), "Secret123".to_string())
        );
    }

    #[test]
    fn enable_2fa_rejects_bad_code() {
        let env = FakeEnv {
            totp_secret: "SECRET".into(),
            totp_code_ok: false,
            ..Default::default()
        };
        let r = enable_2fa(&env, &principal(None), "000000", None);
        assert!(matches!(r, Err(Error::TotpInvalid)));
        assert!(env.totp_written.borrow().is_none());
    }

    #[test]
    fn enable_2fa_happy_path() {
        let env = FakeEnv {
            totp_secret: "SECRET".into(),
            totp_code_ok: true,
            ..Default::default()
        };
        let r = enable_2fa(&env, &principal(None), "123456", Some("tok"));
        assert!(r.is_ok());
        assert_eq!(
            env.totp_written.borrow().as_ref().unwrap(),
            &("SECRET".to_string(), true)
        );
        assert_eq!(
            env.audited.borrow().as_slice(),
            ["alice:account.2fa_enable"]
        );
    }

    #[test]
    fn disable_2fa_clears_secret() {
        let env = FakeEnv {
            totp_secret: "SECRET".into(),
            totp_code_ok: true,
            ..Default::default()
        };
        let r = disable_2fa(&env, &principal(None), "123456", None);
        assert!(r.is_ok());
        assert_eq!(
            env.totp_written.borrow().as_ref().unwrap(),
            &(String::new(), false)
        );
        assert_eq!(
            env.audited.borrow().as_slice(),
            ["alice:account.2fa_disable"]
        );
    }
}
