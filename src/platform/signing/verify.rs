//! Release-signing verification.
//!
//! Every published panel binary is signed (Ed25519) by the holder of the
//! release private key (kept in CI secrets, never in the repo). The matching
//! public key(s) are embedded below; the self-updater verifies a downloaded
//! binary's detached signature against them BEFORE replacing the running
//! executable. Because the trust anchor is the embedded key — not the download
//! source — a compromised mirror cannot serve a binary the panel will accept.
//!
//! `TRUSTED_KEYS` is a list so a key can be rotated without orphaning
//! already-deployed panels: publish a build that adds the new key (still signed
//! by the current key), let it roll out, then start signing with the new key
//! and later drop the old one.

use ed25519_dalek::{Signature, VerifyingKey};

/// Trusted release-signing public keys (raw Ed25519, 32 bytes each).
///
/// Fingerprint (sha256[:16] of the raw key): 8c8792efabded96d
const TRUSTED_KEYS: &[[u8; 32]] = &[[
    24, 96, 10, 98, 35, 106, 5, 224, 130, 245, 114, 38, 92, 39, 8, 102, 52, 58, 166, 33, 214, 2,
    215, 254, 39, 181, 85, 232, 69, 126, 217, 94,
]];

/// Verify a detached Ed25519 signature (`sig`, raw 64 bytes) over `data`
/// against any trusted key. Returns true only on a strict, valid signature.
pub fn verify(data: &[u8], sig: &[u8]) -> bool {
    let sig: [u8; 64] = match sig.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig);
    TRUSTED_KEYS.iter().any(|k| {
        VerifyingKey::from_bytes(k)
            .map(|vk| vk.verify_strict(data, &signature).is_ok())
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_length_signature() {
        assert!(!verify(b"hello", &[0u8; 10]));
        assert!(!verify(b"hello", &[]));
    }

    #[test]
    fn rejects_bad_signature() {
        // A 64-byte all-zero signature must not verify against real data.
        assert!(!verify(b"hello dn7 panel binary", &[0u8; 64]));
    }

    #[test]
    fn accepts_openssl_signature_from_trusted_key() {
        // Signature produced by `openssl pkeyutl -sign -rawin` with the release
        // private key over the message "dn7-panel-signing-test". Proves the
        // embedded public key + verify_strict accept an OpenSSL Ed25519 sig
        // (the exact path CI uses to sign release binaries).
        const MSG: &[u8] = b"dn7-panel-signing-test";
        const SIG: [u8; 64] = [
            211, 133, 253, 20, 41, 65, 53, 133, 192, 5, 141, 183, 171, 14, 67, 104, 51, 101, 67,
            19, 119, 250, 153, 134, 141, 27, 153, 97, 137, 112, 38, 67, 214, 75, 236, 251, 138,
            202, 255, 32, 164, 4, 102, 36, 188, 21, 49, 159, 103, 216, 92, 170, 133, 159, 120, 126,
            39, 228, 60, 82, 73, 16, 62, 1,
        ];
        assert!(verify(MSG, &SIG));
        // Wrong message must fail.
        assert!(!verify(b"dn7-panel-signing-tesT", &SIG));
    }
}
