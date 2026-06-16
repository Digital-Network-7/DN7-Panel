//! Account use-cases. One explicit entry point each; the handler only parses
//! the request, resolves the `Principal`, calls the use-case, and maps the
//! result. The orchestration sequence (validate → verify → persist → OS sync →
//! revoke sessions → audit) lives here so no entry point can forget a step.

use crate::app::ports::account::AccountEnv;
use crate::domain::identity::{valid_os_secret, valid_pw_format, Principal};
use crate::domain::Error;

/// Change the caller's own panel password.
///
/// `salt`/`hash` are the client-computed new verifier; `old_verifier` proves
/// the current password; `plaintext` (system users only) syncs the OS password;
/// `keep_token` is the caller's current session (kept alive while the rest are
/// revoked).
pub(crate) async fn change_password(
    env: &impl AccountEnv,
    who: &Principal,
    salt: &str,
    hash: &str,
    old_verifier: &str,
    plaintext: &str,
    keep_token: Option<&str>,
) -> Result<(), Error> {
    if !valid_pw_format(salt, hash) {
        return Err(Error::PasswordMalformed);
    }
    // The plaintext (system users only) is fed to `chpasswd` over stdin; reject
    // any control char that could forge an extra `user:password` record and
    // rewrite another OS account (incl. root). Checked before persisting so a
    // malformed value never leaves the panel password half-changed.
    if !plaintext.is_empty() && !valid_os_secret(plaintext) {
        return Err(Error::PasswordMalformed);
    }
    let current = env.current_verifier(who);
    if current.is_empty() || old_verifier.to_lowercase() != current {
        return Err(Error::OldPasswordWrong);
    }
    env.save_password(who, salt, &hash.to_lowercase())?;
    if !plaintext.is_empty() {
        if let Some(sys) = &who.system_user {
            env.sync_system_password(sys, plaintext).await;
        }
    }
    // Any other (possibly leaked) sessions die immediately; keep the caller's.
    env.revoke_other_sessions(&who.username, keep_token);
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
        fn save_password(&self, _who: &Principal, salt: &str, hash: &str) -> Result<(), Error> {
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

    #[tokio::test]
    async fn rejects_bad_format() {
        let env = FakeEnv::default();
        let r = change_password(&env, &principal(None), "short", HASH, "", "", None).await;
        assert!(matches!(r, Err(Error::PasswordMalformed)));
        assert!(env.saved.borrow().is_none());
    }

    #[tokio::test]
    async fn rejects_wrong_old_password() {
        let env = FakeEnv {
            verifier: "the-real-verifier".into(),
            ..Default::default()
        };
        let r = change_password(&env, &principal(None), SALT, HASH, "wrong", "", None).await;
        assert!(matches!(r, Err(Error::OldPasswordWrong)));
        assert!(env.saved.borrow().is_none());
    }

    #[tokio::test]
    async fn happy_path_super_admin() {
        let env = FakeEnv {
            verifier: "cur".into(),
            ..Default::default()
        };
        let r = change_password(&env, &principal(None), SALT, HASH, "CUR", "", Some("tok")).await;
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
            ..Default::default()
        };
        let who = principal(Some("alice"));
        let r = change_password(&env, &who, SALT, HASH, "cur", "Secret123", None).await;
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
