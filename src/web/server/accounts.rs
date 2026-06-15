//! Account authorization model: privilege levels and the strictly-lower-
//! privilege management rule, shared by the account self-service and admin
//! user-management handlers so the policy lives in one place.
use super::*;

/// Privilege level: super-admin (owner) 2, admin (sudo) 1, plain user 0.
pub(crate) fn account_level(a: &Account) -> u8 {
    if a.is_super {
        2
    } else if a.is_admin {
        1
    } else {
        0
    }
}

/// Privilege level implied by a stored role string ("admin" = 1, else 0).
pub(crate) fn role_level(role: &str) -> u8 {
    if role == "admin" {
        1
    } else {
        0
    }
}

/// Whether an actor may create / modify / delete / assign an account at
/// `target_lvl`: only targets strictly lower in privilege than the actor.
/// Centralizes the rule the create/update/delete handlers each used to inline.
pub(crate) fn can_manage(actor_lvl: u8, target_lvl: u8) -> bool {
    actor_lvl > target_lvl
}

// ---------------------------------------------------------------------------
// Account use-case services
//
// The credential/2FA flows below own the domain sequence (verify → persist →
// OS sync → session revocation → audit) so the HTTP handlers stay thin and no
// entry point can forget the session/audit policy after a credential change.
// ---------------------------------------------------------------------------

/// Verify the caller's current password before allowing a change: their
/// `old_verifier` must equal the stored salted hash (super-admin → web.json,
/// else the panel user's record).
#[allow(clippy::result_large_err)]
pub(crate) fn verify_current_password(
    state: &Shared,
    a: &Account,
    old_verifier: &str,
) -> Result<(), Response> {
    let cur_hash = if a.is_super {
        state.settings.lock().unwrap().pw_hash.clone()
    } else {
        crate::web::users::find(&a.username)
            .map(|u| u.pw_hash)
            .unwrap_or_default()
    };
    if cur_hash.is_empty() || old_verifier.to_lowercase() != cur_hash {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "settings.bad_old_password",
        ));
    }
    Ok(())
}

/// Persist a new password verifier (super-admin → web.json, else the panel user
/// record) and, for system-backed users, sync the OS password. `plaintext` is
/// the cleartext new password (system users only); empty to skip the OS sync.
#[allow(clippy::result_large_err)]
pub(crate) async fn save_new_password(
    state: &Shared,
    a: &Account,
    salt: &str,
    hash_input: &str,
    plaintext: &str,
) -> Result<(), Response> {
    let hash = hash_input.to_lowercase();
    if a.is_super {
        let saved = {
            let mut s = state.settings.lock().unwrap();
            s.set_password_hashed(salt, &hash);
            s.clone()
        };
        if let Err(e) = settings::save(&saved) {
            return Err(api_err_detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "common.save_failed",
                e,
            ));
        }
    } else {
        let res = crate::web::users::update(&a.username, |u| {
            u.pw_salt = salt.to_string();
            u.pw_hash = hash.clone();
        });
        if let Err(e) = res {
            return Err(Json(op_err_body(e)).into_response());
        }
        // Sync the OS password to the new panel password.
        if !plaintext.is_empty() {
            if let Some(u) = &a.system_user {
                let _ = crate::web::users::set_system_password(u, plaintext).await;
            }
        }
    }
    Ok(())
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
