//! The DN7 password credential KDF: the client-side `s256:N` verifier derivation,
//! the SINGLE byte-exact source of truth shared by the panel's first-run init
//! wizard (`src/platform/init_cli.rs`) and the `dn7` CLI (`dn7 user add|passwd`).
//!
//! It MUST stay identical to the browser's `core.js deriveVerifier`: the server
//! stores `Argon2id(verifier)` and a later login recomputes the same verifier, so
//! ANY drift here silently breaks login. The golden-vector tests below pin the
//! output — if they fail, fix the code, not the test.
//!
//! The cleartext password is never derived server-side; the panel only wraps the
//! received verifier in Argon2id at rest (that step lives in the panel, not here).

/// Iteration count for new credentials (must be >= the panel's `MIN_PW_KDF_ITERS`).
pub const KDF_ITERS: u32 = 30_000;

/// The `pw_kdf` string for a fresh credential: `"s256:30000"`.
pub fn kdf_string() -> String {
    format!("s256:{KDF_ITERS}")
}

/// SHA-256 of `s` as 64 lowercase hex chars.
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The `s256:N` verifier: `h` starts as the cleartext password and is replaced
/// each round by `sha256_hex(salt + ":" + h)`. Byte-identical to the browser path.
pub fn derive_verifier_s256(salt: &str, password: &str, n: u32) -> String {
    let mut h = password.to_string();
    for _ in 0..n {
        h = sha256_hex(&format!("{salt}:{h}"));
    }
    h
}

/// 16 random bytes as 32 lowercase hex chars (matches the browser's `randHex(16)`).
pub fn random_salt_hex() -> String {
    random_hex(16)
}

/// A fresh 256-bit secret as 64 lowercase hex chars — used for the root-only CLI
/// control token (`cli.token`) and its rotation.
pub fn random_token() -> String {
    random_hex(32)
}

/// `n` random bytes as `2*n` lowercase hex chars.
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors — computed independently (python hashlib) AND cross-checked
    // against a real panel login. A change here means login compatibility with the
    // browser/panel is BROKEN.
    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn one_round_is_salt_colon_pw() {
        assert_eq!(derive_verifier_s256("s", "p", 1), sha256_hex("s:p"));
        assert_eq!(
            derive_verifier_s256("s", "p", 1),
            "8598d4ac2c6bc139141e9c368fe37e94c240662266122e21bcba07254caa7379"
        );
    }

    #[test]
    fn two_rounds_chain_the_digest() {
        let one = sha256_hex("s:p");
        assert_eq!(
            derive_verifier_s256("s", "p", 2),
            sha256_hex(&format!("s:{one}"))
        );
        assert_eq!(
            derive_verifier_s256("s", "p", 2),
            "54226c71ab601a395ed0740451c0886403440a699f224c72241727afebcb2f02"
        );
    }

    #[test]
    fn full_30000_round_golden() {
        // This is the exact value a browser login recomputes; do not edit.
        assert_eq!(
            derive_verifier_s256("00112233445566778899aabbccddeeff", "hunter2", KDF_ITERS),
            "7610c6f0903f380bf79fd4b3427d7a686c574d98a86ad984af01e5ff38d8cf52"
        );
    }

    #[test]
    fn verifier_is_64_lowercase_hex() {
        let v = derive_verifier_s256("aa", "pw", KDF_ITERS);
        assert_eq!(v.len(), 64);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn salt_is_32_lowercase_hex_and_unique() {
        let a = random_salt_hex();
        let b = random_salt_hex();
        assert_eq!(a.len(), 32);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b, "two fresh salts must differ");
    }

    #[test]
    fn kdf_string_is_s256_30000() {
        assert_eq!(kdf_string(), "s256:30000");
    }

    #[test]
    fn random_token_is_64_lowercase_hex_and_unique() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 64);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b);
    }
}
