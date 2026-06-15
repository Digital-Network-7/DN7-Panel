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
