//! At-rest encryption for persisted secrets (the web console password).
//!
//! The web console password is stored encrypted at rest with AES-256-GCM —
//! both the auto-generated default and any user-set password. The stored value
//! is `nonce_hex:cipher_hex` with a fresh random 96-bit nonce per write.
//!
//! The key is *machine-bound*: it's derived (SHA-256) from a stable host
//! fingerprint (`/etc/machine-id`, the dbus machine-id, a persisted random key
//! file, or hostname as a last resort). So a token file copied to another host
//! can't be decrypted there.
//!
//! Backward compatibility: a legacy plaintext token has no `:` separator, so
//! `maybe_decrypt` returns it verbatim; the next write re-encrypts it.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

/// Domain-separation salt so this key can't be confused with any other use of
/// the same machine fingerprint.
const KEY_SALT: &[u8] = b"dn7-panel-secret-enc-v1";

/// Derive the machine-bound 32-byte AES key.
fn machine_key() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_SALT);
    hasher.update(machine_fingerprint());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// A stable per-host fingerprint used to derive the encryption key.
///
/// Preference order (most stable / least forgeable first):
///   1. `/etc/machine-id`         — set once at install, survives reboots.
///   2. `/var/lib/dbus/machine-id`— same value on most distros.
///   3. a persisted random key    — generated once and stored next to the
///      token, so encryption is still deterministic on hosts without a
///      machine-id (e.g. some containers).
///   4. the hostname              — last resort.
fn machine_fingerprint() -> Vec<u8> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if !s.is_empty() {
                return s.as_bytes().to_vec();
            }
        }
    }
    if let Some(k) = persisted_random_key() {
        return k;
    }
    let host = sysinfo::System::host_name().unwrap_or_default();
    if !host.is_empty() {
        return host.into_bytes();
    }
    // Truly nothing identifying — use a fixed value so encrypt/decrypt still
    // round-trips on this host (offers obfuscation but no real binding).
    b"dn7-panel-no-machine-id".to_vec()
}

/// Path of the fallback per-host random key (only used when no machine-id).
/// Lives in the persisted-data subdir alongside the token.
fn key_file_path() -> std::path::PathBuf {
    crate::paths::data_dir().join(".panel_key")
}

/// Read the persisted random key, generating + storing one on first use.
/// Returns None if it can't be read or created (then we fall back to hostname).
fn persisted_random_key() -> Option<Vec<u8>> {
    let path = key_file_path();
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Some(bytes);
        }
    }
    // Generate a fresh 32-byte key.
    let mut key = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut key);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // Create it ATOMICALLY (O_EXCL): if two roles race on first run, only one
    // writes its key; the loser reads the winner's so both derive the same key.
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            if f.write_all(&key).is_err() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Some(key.to_vec())
        }
        // Another process created it first — use theirs.
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::read(&path).ok().filter(|b| b.len() == 32)
        }
        Err(_) => None,
    }
}

/// Encrypt a plaintext value for at-rest storage. Returns `nonce_hex:cipher_hex`.
/// On the (unlikely) event of an encryption failure, returns the plaintext
/// unchanged so the token is never lost — `maybe_decrypt` reads it back as-is.
pub fn encrypt(plaintext: &str) -> String {
    match try_encrypt(&machine_key(), plaintext) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("token encryption failed ({e}); storing plaintext");
            plaintext.to_string()
        }
    }
}

/// Decrypt a stored value. A value without a `:` separator is treated as a
/// legacy plaintext token and returned verbatim. Returns None only when a
/// ciphertext-shaped value fails to decrypt (wrong host / corrupt file).
pub fn maybe_decrypt(stored: &str) -> Option<String> {
    let stored = stored.trim();
    if stored.is_empty() {
        return None;
    }
    // Legacy plaintext token (128 hex chars, no separator) — use as-is.
    if !stored.contains(':') {
        return Some(stored.to_string());
    }
    match try_decrypt(&machine_key(), stored) {
        Ok(pt) => Some(pt),
        Err(e) => {
            tracing::warn!("token decryption failed: {e}");
            None
        }
    }
}

fn try_encrypt(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("encrypt failed: {e}"))?;
    Ok(format!("{}:{}", to_hex(&nonce_bytes), to_hex(&ct)))
}

fn try_decrypt(key: &[u8; 32], stored: &str) -> Result<String, String> {
    let (nonce_hex, ct_hex) = stored
        .trim()
        .split_once(':')
        .ok_or_else(|| "malformed ciphertext".to_string())?;
    let nonce_bytes = from_hex(nonce_hex).ok_or_else(|| "bad nonce hex".to_string())?;
    let ct = from_hex(ct_hex).ok_or_else(|| "bad ciphertext hex".to_string())?;
    if nonce_bytes.len() != 12 {
        return Err("bad nonce length".into());
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| format!("decrypt failed: {e}"))?;
    String::from_utf8(pt).map_err(|e| format!("utf8 error: {e}"))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let token = "a".repeat(128);
        let enc = try_encrypt(&key, &token).unwrap();
        assert!(enc.contains(':'));
        assert!(!enc.contains(&token));
        assert_eq!(try_decrypt(&key, &enc).unwrap(), token);
    }

    #[test]
    fn wrong_key_fails() {
        let enc = try_encrypt(&[1u8; 32], "secret").unwrap();
        assert!(try_decrypt(&[2u8; 32], &enc).is_err());
    }

    #[test]
    fn nonce_is_random() {
        let key = [9u8; 32];
        let a = try_encrypt(&key, "same").unwrap();
        let b = try_encrypt(&key, "same").unwrap();
        assert_ne!(a, b, "each encryption should use a fresh nonce");
    }

    #[test]
    fn maybe_decrypt_passes_through_legacy_plaintext() {
        // A legacy 128-hex-char token has no ':' and must round-trip unchanged.
        let legacy = "f".repeat(128);
        assert_eq!(maybe_decrypt(&legacy).unwrap(), legacy);
    }

    #[test]
    fn maybe_decrypt_round_trips_real_ciphertext() {
        // encrypt() uses the live machine key; maybe_decrypt() must read it back.
        let token = "deadbeef".repeat(16);
        let enc = encrypt(&token);
        assert!(enc.contains(':'));
        assert_eq!(maybe_decrypt(&enc).unwrap(), token);
    }

    #[test]
    fn maybe_decrypt_empty_is_none() {
        assert!(maybe_decrypt("   ").is_none());
    }
}
