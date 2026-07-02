//! Identity rules: username + credential-format validation, and the panel-user
//! entity. Pure (no I/O).

use serde::{Deserialize, Serialize};

/// A system-account operation error — typed replacement for the
/// `anyhow!("ERR_CODE:users.*")` literals in `infra::system`. Domain owns the
/// semantic `users.*` code; the `ERR_CODE:` transport marker is added in infra
/// (§2/§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemUserError {
    NoSudoGroup,
    SetPwFailed,
    BadFullName,
}

impl SystemUserError {
    /// The stable, `users.`-namespaced semantic code (no transport prefix).
    pub(crate) fn code(self) -> &'static str {
        match self {
            SystemUserError::NoSudoGroup => "users.no_sudo_group",
            SystemUserError::SetPwFailed => "users.set_pw_failed",
            SystemUserError::BadFullName => "users.bad_full_name",
        }
    }
}

impl std::fmt::Display for SystemUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SystemUserError {}

/// A panel user, persisted in `users.json` and backed 1:1 by a Linux account.
///
/// NOTE: a persisted **domain entity** — the `serde` derive is a reviewed
/// exception to the "domain default-forbids serde" rule (see steering §2/§4),
/// not a transport DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PanelUser {
    /// Login name — identical to the system username.
    pub(crate) username: String,
    #[serde(default)]
    pub(crate) pw_salt: String,
    #[serde(default)]
    pub(crate) pw_hash: String,
    /// Key-derivation scheme for `pw_hash` (see `WebSettings::pw_kdf`): empty =
    /// legacy single `sha256(salt ":" pw)`; "s256:N" = N salted-SHA-256
    /// iterations. Migrates to "s256:N" when the password is next changed.
    #[serde(default)]
    pub(crate) pw_kdf: String,
    /// "admin" (sudo) | "user".
    #[serde(default)]
    pub(crate) role: String,
    #[serde(default)]
    pub(crate) full_name: String,
    #[serde(default)]
    pub(crate) nickname: String,
    /// Avatar as a base64 data URL (size-limited by the API).
    #[serde(default)]
    pub(crate) avatar: String,
    #[serde(default)]
    pub(crate) totp_secret: String,
    #[serde(default)]
    pub(crate) totp_enabled: bool,
    #[serde(default)]
    pub(crate) uid: u32,
}

impl PanelUser {
    pub(crate) fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// The authenticated actor of a use-case (resolved once from the session). A
/// pure value object — no transport, no storage.
#[derive(Debug, Clone)]
pub(crate) struct Principal {
    pub(crate) username: String,
    pub(crate) is_super: bool,
    /// System account to act as for OS-side effects (None for the super-admin).
    pub(crate) system_user: Option<String>,
}

/// A Linux username: lowercase start, then lowercase/digits/_/-; 1..=32 chars.
/// Conservative (NAME_REGEX-style) so it can't smuggle shell/flag characters.
pub(crate) fn valid_username(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        && s != "root"
}

/// Whether a client-computed credential pair is well-formed: a 32-hex salt and
/// a 64-hex (sha256) verifier. The cleartext password never reaches the server,
/// so this format is the only server-side credential check. Shared by every
/// password entry point (create / self-change / admin reset / settings).
pub(crate) fn valid_pw_format(salt: &str, hash: &str) -> bool {
    salt.len() == 32
        && salt.bytes().all(|b| b.is_ascii_hexdigit())
        && hash.len() == 64
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Minimum accepted client KDF iteration count (the JS client default is
/// `s256:30000`).
pub(crate) const MIN_PW_KDF_ITERS: u32 = 30_000;

/// Whether a client-supplied KDF descriptor is acceptable for a NEW credential:
/// it must be `s256:N` with `N >= MIN_PW_KDF_ITERS`. A tampered client could
/// otherwise persist a cheaply brute-forceable at-rest verifier (e.g. `s256:1`).
/// This gates only what the server newly stores — already-stored legacy creds
/// (empty kdf) still verify on login.
pub(crate) fn valid_pw_kdf(kdf: &str) -> bool {
    kdf.strip_prefix("s256:")
        .and_then(|n| n.parse::<u32>().ok())
        .is_some_and(|n| n >= MIN_PW_KDF_ITERS)
}

/// Whether a cleartext secret is safe to hand to a line-oriented OS tool
/// (`chpasswd`, which reads `user:password` records separated by newlines).
/// A control character — notably `\n`/`\r`/`\0` — would let the value forge an
/// extra record and rewrite another account's OS password, so any ASCII control
/// or DEL byte is rejected. An empty secret is "safe" (it is simply not synced).
pub(crate) fn valid_os_secret(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Name of the marker file DN7 drops in a home dir when it *creates* the backing
/// account, so a later create can tell a leftover DN7 account (safe to re-adopt)
/// apart from a foreign service account it must never touch.
pub(crate) const DN7_OWNED_MARKER: &str = ".dn7-owned";

/// A pre-existing system account's provenance, evaluated when a panel user is
/// created for a name that *already* resolves in `/etc/passwd`. Pure inputs so
/// the adoption decision is unit-testable without `getpwnam`/filesystem I/O.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AccountProvenance {
    /// A panel record with this name already exists in `users.json` — the panel
    /// created/owns it (e.g. a store entry whose OS side was half-provisioned).
    pub(crate) recorded_in_store: bool,
    /// The DN7 marker file (`DN7_OWNED_MARKER`) is present in the account's home
    /// dir — DN7 seeded this account.
    pub(crate) has_owned_marker: bool,
}

/// Whether a **pre-existing** system account may be *adopted* by a create. Only
/// a leftover DN7 account is adoptable — either already recorded in `users.json`
/// or carrying the DN7 marker file. A foreign service account (`postgres`,
/// `www-data`, `daemon`, …) matches neither, so it is refused: the panel must
/// never reset its password, add it to sudo, or later delete it + its home.
///
/// Callers only invoke this once `getpwnam` has confirmed the account exists;
/// for a name with no system account, provisioning creates a fresh DN7 account
/// and this check does not apply.
pub(crate) fn system_account_adoptable(p: AccountProvenance) -> bool {
    p.recorded_in_store || p.has_owned_marker
}

/// Bilingual (zh / en) message for refusing to adopt a foreign system account.
/// Surfaced as the `Persist` detail so the admin sees *why* the create failed
/// (a plain "name taken" would wrongly imply a panel-user collision).
pub(crate) fn foreign_account_refused_msg(username: &str) -> String {
    format!(
        "系统已存在同名账户「{username}」且非 DN7 创建，拒绝接管（避免改动/删除系统服务账户）。\
         A system account named \"{username}\" already exists and was not created by DN7; \
         refusing to adopt it (to avoid altering or deleting a real service account)."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_secret_rejects_control_chars() {
        assert!(valid_os_secret("hunter2!#%"));
        assert!(valid_os_secret("")); // empty = not synced, allowed
        assert!(valid_os_secret("a:b")); // ':' is fine — chpasswd splits on the first one
        assert!(!valid_os_secret("x\nroot:pwned")); // newline forges a 2nd record
        assert!(!valid_os_secret("x\rfoo"));
        assert!(!valid_os_secret("x\0foo"));
        assert!(!valid_os_secret("x\ty")); // tab (control) rejected
    }

    #[test]
    fn username_rules() {
        assert!(valid_username("alice"));
        assert!(valid_username("bob_2"));
        assert!(valid_username("_svc"));
        assert!(!valid_username("Alice")); // uppercase
        assert!(!valid_username("1abc")); // leading digit
        assert!(!valid_username("a b")); // space
        assert!(!valid_username("root")); // reserved
        assert!(!valid_username("")); // empty
        assert!(!valid_username("-x")); // leading dash
    }

    #[test]
    fn pw_format_rules() {
        let salt = "0123456789abcdef0123456789abcdef"; // 32 hex
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64 hex
        assert!(valid_pw_format(salt, hash));
        assert!(!valid_pw_format("short", hash));
        assert!(!valid_pw_format(salt, "xyz"));
        assert!(!valid_pw_format(&salt[..31], hash)); // wrong length
    }

    #[test]
    fn foreign_system_account_is_not_adoptable() {
        // A real service account (e.g. `postgres`/`www-data`): not in the store,
        // no DN7 marker → MUST be refused, never adopted.
        assert!(!system_account_adoptable(AccountProvenance {
            recorded_in_store: false,
            has_owned_marker: false,
        }));
    }

    #[test]
    fn leftover_dn7_account_is_adoptable() {
        // Already recorded in users.json (half-provisioned store entry).
        assert!(system_account_adoptable(AccountProvenance {
            recorded_in_store: true,
            has_owned_marker: false,
        }));
        // Carries the DN7 marker file (seeded by a prior DN7 create).
        assert!(system_account_adoptable(AccountProvenance {
            recorded_in_store: false,
            has_owned_marker: true,
        }));
    }

    #[test]
    fn foreign_refusal_message_is_bilingual() {
        let m = foreign_account_refused_msg("postgres");
        assert!(m.contains("postgres"));
        assert!(m.contains("拒绝接管")); // zh
        assert!(m.contains("refusing to adopt")); // en
    }
}
