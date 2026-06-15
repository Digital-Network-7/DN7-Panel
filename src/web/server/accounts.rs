//! Account authorization model: privilege levels and the strictly-lower-
//! privilege management rule, shared by the account self-service and admin
//! user-management handlers so the policy lives in one place.
use super::*;

/// Privilege level: super-admin (owner) 2, admin (sudo) 1, plain user 0.
pub(crate) fn account_level(a: &Account) -> u8 {
    crate::domain::authz::level(a.is_super, a.is_admin)
}

/// Privilege model lives in the domain layer; re-exported so the user handlers
/// can keep calling `role_level` / `accounts::can_manage` unchanged.
pub(crate) use crate::domain::authz::{can_manage, role_level};

// ---------------------------------------------------------------------------
// Account use-case services
//
// The credential/2FA flows below own the domain sequence (verify → persist →
// OS sync → session revocation → audit) so the HTTP handlers stay thin and no
// entry point can forget the session/audit policy after a credential change.
// ---------------------------------------------------------------------------

/// Map an account domain error to its HTTP response. This is the single
/// domain→transport mapping point for the account/credential flows; it lives in
/// the web layer because it owns the wire codes (aligned with the frontend
/// `err.*`). Shared by the account, settings and user-management handlers.
pub(crate) fn map_domain_err(e: crate::domain::Error) -> Response {
    use crate::domain::Error::*;
    match e {
        PasswordMalformed => api_err(StatusCode::BAD_REQUEST, "settings.pw_format"),
        OldPasswordWrong => api_err(StatusCode::BAD_REQUEST, "settings.bad_old_password"),
        TotpInvalid => api_err(StatusCode::BAD_REQUEST, "auth.bad_totp"),
        Persist(detail) => api_err_detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "common.save_failed",
            detail,
        ),
    }
}

/// Read the caller's pending/active TOTP secret.
pub(crate) fn read_totp(state: &Shared, a: &Account) -> String {
    if a.is_super {
        state.settings.lock().unwrap().totp_secret.clone()
    } else {
        crate::web::users::find(&a.username)
            .map(|u| u.totp_secret)
            .unwrap_or_default()
    }
}

/// Persist the caller's TOTP secret + enabled flag.
pub(crate) fn write_totp(
    state: &Shared,
    a: &Account,
    secret: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    if a.is_super {
        let mut s = state.settings.lock().unwrap();
        s.totp_secret = secret.to_string();
        s.totp_enabled = enabled;
        let saved = s.clone();
        drop(s);
        settings::save(&saved)
    } else {
        crate::web::users::update(&a.username, |u| {
            u.totp_secret = secret.to_string();
            u.totp_enabled = enabled;
        })
    }
}

/// Run the side effects every self-service credential change shares: revoke the
/// account's other sessions/tickets (keeping the caller's current session) so a
/// previously-leaked token dies immediately, then write the audit record.
/// Bundled here so no credential-changing handler can forget either step.
pub(crate) fn after_credential_change(
    state: &Shared,
    username: &str,
    keep: Option<&str>,
    action: &str,
) {
    state.auth.revoke_user(username, keep);
    audit::record(username, action, username, true, "");
}

/// Assemble the `/api/me` view for a principal: identity + role + 2FA + profile
/// (full name / nickname / avatar) + first-run setup flag + the home directory
/// to open the file manager at. Owns the super-admin vs panel-user branch so
/// the handler stays a thin adapter.
pub(crate) fn me_view(state: &Shared, a: &Account) -> Value {
    let (full_name, nickname, avatar, must_setup) = if a.is_super {
        let s = state.settings.lock().unwrap();
        (
            s.full_name.clone(),
            s.nickname.clone(),
            s.avatar.clone(),
            s.pw_default || s.username.eq_ignore_ascii_case("admin"),
        )
    } else {
        match crate::web::users::find(&a.username) {
            Some(u) => (u.full_name, u.nickname, u.avatar, false),
            None => (String::new(), String::new(), String::new(), false),
        }
    };
    // Home directory to open the file manager at: the user's system home, or
    // the panel owner's home (root) for the super-admin.
    let home = match &a.system_user {
        Some(u) => crate::web::system_account::getpwnam(u)
            .map(|(_, h)| h)
            .unwrap_or_else(|| "/".to_string()),
        None => std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "/root".to_string()),
    };
    json!({
        "username": a.username,
        "is_admin": a.is_admin,
        "is_super": a.is_super,
        "role": a.role(),
        "full_name": full_name,
        "nickname": nickname,
        "avatar": avatar,
        "totp_enabled": a.totp_enabled,
        "must_setup": must_setup,
        "home": home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(is_super: bool, is_admin: bool) -> Account {
        Account {
            username: "u".into(),
            is_admin,
            is_super,
            system_user: None,
            totp_enabled: false,
        }
    }

    #[test]
    fn privilege_levels() {
        assert_eq!(account_level(&acct(true, true)), 2); // owner
        assert_eq!(account_level(&acct(false, true)), 1); // admin
        assert_eq!(account_level(&acct(false, false)), 0); // user
        assert_eq!(role_level("admin"), 1);
        assert_eq!(role_level("user"), 0);
        assert_eq!(role_level("anything-else"), 0);
    }

    #[test]
    fn management_matrix_only_strictly_below() {
        let owner = account_level(&acct(true, true)); // 2
        let admin = account_level(&acct(false, true)); // 1
        let user = account_level(&acct(false, false)); // 0
                                                       // Owner manages admins + users, but not another owner.
        assert!(can_manage(owner, role_level("admin")));
        assert!(can_manage(owner, role_level("user")));
        assert!(!can_manage(owner, owner));
        // Admin manages only users, never another admin or the owner.
        assert!(can_manage(admin, role_level("user")));
        assert!(!can_manage(admin, role_level("admin")));
        assert!(!can_manage(admin, owner));
        // Plain users manage nobody.
        assert!(!can_manage(user, role_level("user")));
        assert!(!can_manage(user, role_level("admin")));
    }
}
