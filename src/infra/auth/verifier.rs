//! At-rest password verifier hashing (Argon2id).
//!
//! The console never sees the plaintext: the browser computes a `verifier`
//! (`deriveVerifier(salt, password, kdf)`) and sends THAT over the channel. To
//! stop a leaked data file from being replayed as a login credential, the server
//! stores `argon2id(verifier)` — a one-way, memory-hard hash — rather than the
//! verifier itself. A stolen `$argon2id$…` string can't be used to log in (you'd
//! need the verifier, which Argon2id doesn't reveal), which closes the
//! pass-the-hash gap the old "store the verifier directly" scheme had.
//!
//! Legacy installs stored the raw verifier (hex). [`verify_verifier`] still
//! accepts those (constant-time compare) and signals a `rehash` so the caller
//! transparently migrates the stored value to Argon2id on the next login.

use std::sync::OnceLock;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;

use super::password_matches;

/// Outcome of checking a presented verifier against the stored credential.
pub struct VerifierVerdict {
    /// Whether the verifier matched.
    pub ok: bool,
    /// When `ok` and the stored value was a legacy raw verifier, the Argon2id
    /// hash the caller should persist in its place (transparent migration).
    pub rehash: Option<String>,
}

/// Whether a stored credential is already an Argon2 PHC hash (vs a legacy raw
/// hex verifier). PHC strings always begin with `$argon2`.
fn is_argon2(stored: &str) -> bool {
    stored.starts_with("$argon2")
}

/// Argon2id-hash a client verifier for at-rest storage. Returns a self-describing
/// PHC string (`$argon2id$…` with a fresh random salt + params). `None` only on
/// the practically-impossible hashing error — callers must treat that as a hard
/// failure, never storing the verifier in the clear.
pub fn hash_verifier(verifier: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(verifier.as_bytes(), &salt)
        .ok()
        .map(|h| h.to_string())
}

/// A precomputed Argon2 hash of a fixed string, used only to spend comparable
/// CPU time when verifying against a non-existent account, so "account exists
/// (Argon2)" isn't trivially distinguishable from "no such account" by timing.
fn dummy_hash() -> &'static str {
    static D: OnceLock<String> = OnceLock::new();
    D.get_or_init(|| hash_verifier("dn7-anti-enumeration-dummy").unwrap_or_default())
}

/// Verify a presented `verifier` against the `stored` credential.
/// - `$argon2…` stored value → Argon2id verify.
/// - Legacy raw verifier → constant-time compare; on match, emit a `rehash` so
///   the caller migrates it to Argon2id.
/// - Empty stored value (non-existent account) → never matches, but still burns
///   Argon2 time against a dummy to blunt the timing oracle.
pub fn verify_verifier(stored: &str, verifier: &str) -> VerifierVerdict {
    if stored.is_empty() {
        if let Ok(p) = PasswordHash::new(dummy_hash()) {
            let _ = Argon2::default().verify_password(verifier.as_bytes(), &p);
        }
        return VerifierVerdict {
            ok: false,
            rehash: None,
        };
    }
    if is_argon2(stored) {
        let ok = PasswordHash::new(stored)
            .ok()
            .map(|p| {
                Argon2::default()
                    .verify_password(verifier.as_bytes(), &p)
                    .is_ok()
            })
            .unwrap_or(false);
        VerifierVerdict { ok, rehash: None }
    } else {
        // Legacy: the stored value IS the raw verifier. Constant-time compare,
        // then migrate to Argon2id on success.
        let ok = password_matches(stored, verifier);
        let rehash = if ok {
            hash_verifier(verifier)
        } else {
            // Burn comparable Argon2 time on a mismatch so an un-migrated account
            // isn't distinguishable from an Argon2 one by a fast reject.
            if let Ok(p) = PasswordHash::new(dummy_hash()) {
                let _ = Argon2::default().verify_password(verifier.as_bytes(), &p);
            }
            None
        };
        VerifierVerdict { ok, rehash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip_and_legacy_migration() {
        let verifier = "0123456789abcdef".repeat(4); // looks like a 64-hex verifier
        // Fresh hash verifies and is a PHC string.
        let stored = hash_verifier(&verifier).unwrap();
        assert!(stored.starts_with("$argon2id$"));
        let v = verify_verifier(&stored, &verifier);
        assert!(v.ok && v.rehash.is_none());
        // Wrong verifier fails.
        assert!(!verify_verifier(&stored, "wrong").ok);

        // Legacy raw verifier: matches by constant-time compare AND yields a
        // rehash (the Argon2id form), which itself verifies.
        let legacy = verify_verifier(&verifier, &verifier);
        assert!(legacy.ok);
        let migrated = legacy.rehash.expect("legacy match must produce a rehash");
        assert!(migrated.starts_with("$argon2id$"));
        assert!(verify_verifier(&migrated, &verifier).ok);
        // Legacy mismatch: no match, no rehash.
        let bad = verify_verifier(&verifier, "nope");
        assert!(!bad.ok && bad.rehash.is_none());
    }

    #[test]
    fn empty_stored_never_matches() {
        assert!(!verify_verifier("", "anything").ok);
    }
}
