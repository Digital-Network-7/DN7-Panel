//! Persisted web-console settings (`<data>/web.json`, 0600).
//!
//! Holds the auto-generated access password and the user-adjustable port +
//! enabled flag. The env-var defaults seed the file on first run; thereafter
//! the file is authoritative so changes made in the console survive restarts.

use anyhow::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSettings {
    /// Whether the console is served.
    pub enabled: bool,
    /// TCP port to bind (0.0.0.0:<port>).
    pub port: u16,
    /// Login account name (default "admin"; user-editable).
    #[serde(default = "default_username")]
    pub username: String,
    /// Access password, stored at rest. The auto-generated **default** password
    /// is kept as plaintext (so the operator can read it from the daemon log /
    /// settings file); once the user changes it, it's stored **encrypted**
    /// (`nonce:cipher`, machine-bound via `crate::crypto`). Read it back with
    /// `password_plain()`, never this field directly.
    pub password: String,
    /// True while `password` is still the auto-generated default (plaintext).
    /// Cleared the moment the user sets their own password (then encrypted).
    #[serde(default = "default_true")]
    pub pw_default: bool,
}

fn default_username() -> String {
    "admin".to_string()
}

fn default_true() -> bool {
    true
}

impl WebSettings {
    /// The plaintext password for login comparison / display. Transparently
    /// decrypts a user-set (encrypted) password; returns a default/plaintext
    /// value verbatim.
    pub fn password_plain(&self) -> String {
        crate::crypto::maybe_decrypt(&self.password).unwrap_or_else(|| self.password.clone())
    }

    /// Set a user-chosen password: store it **encrypted** and mark it non-default.
    pub fn set_user_password(&mut self, plain: &str) {
        self.password = crate::crypto::encrypt(plain);
        self.pw_default = false;
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
/// (generating a password). The seeded password is logged once so the operator
/// can find it.
pub fn load_or_init(default_enabled: bool, default_port: u16) -> WebSettings {
    if let Ok(raw) = std::fs::read_to_string(settings_path()) {
        if let Ok(s) = serde_json::from_str::<WebSettings>(&raw) {
            return s;
        }
    }
    let s = WebSettings {
        enabled: default_enabled,
        port: default_port,
        username: default_username(),
        password: gen_password(),
        pw_default: true,
    };
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!(
        port = s.port,
        username = %s.username,
        password = %s.password,
        "web console initialized (account + password generated)"
    );
    s
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
    fn default_password_stays_plaintext() {
        let s = WebSettings {
            enabled: true,
            port: 1080,
            username: "admin".into(),
            password: "PlainDefault123".into(),
            pw_default: true,
        };
        // A default password is readable verbatim and isn't ciphertext-shaped.
        assert_eq!(s.password_plain(), "PlainDefault123");
        assert!(!s.password.contains(':'));
    }

    #[test]
    fn user_password_is_encrypted_and_roundtrips() {
        let mut s = WebSettings {
            enabled: true,
            port: 1080,
            username: "admin".into(),
            password: "PlainDefault123".into(),
            pw_default: true,
        };
        s.set_user_password("mySecret!42");
        // Stored encrypted (nonce:cipher), not the plaintext.
        assert_ne!(s.password, "mySecret!42");
        assert!(s.password.contains(':'));
        assert!(!s.pw_default);
        // But it decrypts back to the original for login comparison.
        assert_eq!(s.password_plain(), "mySecret!42");
    }
}
