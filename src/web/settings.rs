//! Persisted web-console settings (`<data>/web.json`, 0600).
//!
//! The console password is stored **irreversibly**: only a random per-install
//! salt and `sha256(salt ":" password)` are kept — the plaintext is never
//! written to disk or logged and cannot be recovered. Login uses a
//! challenge-response over that hash (see `auth`/`server`), so the plaintext
//! never crosses the wire either.
//!
//! The auto-generated password is shown to the operator exactly once, in the
//! launch banner, at generation time. If it's forgotten, `dn7 panel reset`
//! (runnable only by the install owner / root) generates a new one.

use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSettings {
    /// Whether the console is served.
    pub enabled: bool,
    /// TCP port to bind (0.0.0.0:<port>).
    pub port: u16,
    /// Login account name (default "admin"; user-editable).
    #[serde(default = "default_username")]
    pub username: String,
    /// Random per-install salt (hex) for the password hash.
    #[serde(default)]
    pub pw_salt: String,
    /// `sha256_hex(salt ":" password)` — the irreversible password verifier and
    /// the shared secret for challenge-response login.
    #[serde(default)]
    pub pw_hash: String,
    /// True while the password is still the auto-generated default (the user
    /// hasn't set their own yet).
    #[serde(default = "default_true")]
    pub pw_default: bool,
    /// uid of the OS user that first initialized the console; `dn7 panel reset`
    /// is restricted to this user (or root).
    #[serde(default)]
    pub owner_uid: u32,
}

fn default_username() -> String {
    "admin".to_string()
}

fn default_true() -> bool {
    true
}

/// `sha256_hex(salt ":" plain)` — the stored verifier / challenge secret.
fn hash_password(salt: &str, plain: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(b":");
    h.update(plain.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a random hex salt (16 bytes → 32 hex chars).
fn gen_salt() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Current real uid (for the reset owner check).
fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it just reads the process's real uid.
    unsafe { libc::getuid() }
}

impl WebSettings {
    /// The challenge-response secret (the stored password hash).
    pub fn verifier(&self) -> &str {
        &self.pw_hash
    }

    /// Set a (user-chosen) password: fresh salt + hash, marked non-default.
    pub fn set_password(&mut self, plain: &str) {
        let salt = gen_salt();
        self.pw_hash = hash_password(&salt, plain);
        self.pw_salt = salt;
        self.pw_default = false;
    }

    /// Reset account + password to a freshly-generated default. Returns the new
    /// plaintext password (to show once). The install owner is left unchanged.
    pub fn reset(&mut self) -> String {
        let pw = gen_password();
        let salt = gen_salt();
        self.username = default_username();
        self.pw_hash = hash_password(&salt, &pw);
        self.pw_salt = salt;
        self.pw_default = true;
        pw
    }
}

fn settings_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("web.json")
}

/// Generate a strong, URL-safe random password (no shell/quote specials).
fn gen_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..20)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Load persisted settings, or seed a fresh file from the env-var defaults
/// (generating a password). On a fresh seed the generated plaintext password is
/// returned as `Some` so the caller can show it once (the launch banner); it is
/// never stored in plaintext or logged. Returns `None` for the plaintext when
/// an existing file was loaded.
pub fn load_or_init(default_enabled: bool, default_port: u16) -> (WebSettings, Option<String>) {
    if let Ok(raw) = std::fs::read_to_string(settings_path()) {
        if let Ok(s) = serde_json::from_str::<WebSettings>(&raw) {
            if !s.pw_hash.is_empty() {
                return (s, None);
            }
        }
    }
    let pw = gen_password();
    let salt = gen_salt();
    let s = WebSettings {
        enabled: default_enabled,
        port: default_port,
        username: default_username(),
        pw_hash: hash_password(&salt, &pw),
        pw_salt: salt,
        pw_default: true,
        owner_uid: current_uid(),
    };
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!(
        port = s.port,
        username = %s.username,
        "web console initialized (password shown once in the launch banner)"
    );
    (s, Some(pw))
}

/// Read persisted settings without seeding. None when not initialized.
pub fn load() -> Option<WebSettings> {
    let raw = std::fs::read_to_string(settings_path()).ok()?;
    serde_json::from_str::<WebSettings>(&raw).ok()
}

/// Persist settings to `<data>/web.json` with 0600 perms.
pub fn save(s: &WebSettings) -> Result<()> {
    let path = settings_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(s)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_hashed_irreversibly() {
        let mut s = WebSettings {
            enabled: true,
            port: 1080,
            username: "admin".into(),
            pw_salt: String::new(),
            pw_hash: String::new(),
            pw_default: true,
            owner_uid: 0,
        };
        s.set_password("mySecret!42");
        // Stored as salt + hash, never the plaintext.
        assert!(!s.pw_salt.is_empty());
        assert_eq!(s.pw_hash.len(), 64);
        assert!(!s.pw_hash.contains("mySecret"));
        assert!(!s.pw_default);
        // The verifier is reproducible from salt + plaintext.
        assert_eq!(s.verifier(), hash_password(&s.pw_salt, "mySecret!42"));
        assert_ne!(s.verifier(), hash_password(&s.pw_salt, "wrong"));
    }

    #[test]
    fn reset_regenerates_and_returns_plaintext() {
        let mut s = WebSettings {
            enabled: true,
            port: 1080,
            username: "bob".into(),
            pw_salt: "aa".into(),
            pw_hash: "bb".into(),
            pw_default: false,
            owner_uid: 1000,
        };
        let pw = s.reset();
        assert_eq!(s.username, "admin"); // account reset
        assert_eq!(s.owner_uid, 1000); // owner preserved
        assert!(s.pw_default);
        assert_eq!(s.verifier(), hash_password(&s.pw_salt, &pw));
    }

    #[test]
    fn salt_is_random() {
        assert_ne!(gen_salt(), gen_salt());
    }
}
