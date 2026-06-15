//! Identity rules: username + credential-format validation. Pure (no I/O).

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
