//! Authorization rules: privilege levels + the strictly-lower-privilege rule.
//! Pure — no I/O, no transport, no serde. This is the fine-grained authz
//! decision surface the web layer must call into (handlers never inline role
//! checks of their own).

/// Privilege level from identity flags: owner (super) = 2, admin = 1, user = 0.
pub(crate) fn level(is_super: bool, is_admin: bool) -> u8 {
    if is_super {
        2
    } else if is_admin {
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

/// Whether an actor at `actor_lvl` may create / modify / delete / assign an
/// account at `target_lvl`: only targets strictly lower in privilege.
pub(crate) fn can_manage(actor_lvl: u8, target_lvl: u8) -> bool {
    actor_lvl > target_lvl
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(level(true, true), 2); // owner
        assert_eq!(level(false, true), 1); // admin
        assert_eq!(level(false, false), 0); // user
        assert_eq!(role_level("admin"), 1);
        assert_eq!(role_level("user"), 0);
        assert_eq!(role_level("anything-else"), 0);
    }

    #[test]
    fn management_is_strictly_below() {
        // owner(2) manages admin(1) + user(0), not another owner.
        assert!(can_manage(2, role_level("admin")));
        assert!(can_manage(2, role_level("user")));
        assert!(!can_manage(2, 2));
        // admin(1) manages only users.
        assert!(can_manage(1, role_level("user")));
        assert!(!can_manage(1, role_level("admin")));
        // user(0) manages nobody.
        assert!(!can_manage(0, 0));
    }
}
