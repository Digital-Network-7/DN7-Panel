//! Persisted web-console settings (`<data>/web.json`, 0600).
//!
//! Holds the access password and the user-adjustable port + enabled flag. The
//! password is **always stored encrypted** at rest (`nonce:cipher`, machine-
//! bound via `crate::crypto`), including the auto-generated default — it is
//! never written in plaintext to the file or the log. Read it back with
//! `password_plain()`; an operator who needs the current value runs
//! `dn7-panel password` on the host.

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
    /// Access password, stored **encrypted** at rest (`nonce:cipher`, machine-
    /// bound via `crate::crypto`) — both the auto-generated default and any
    /// user-set password. Read it back with `password_plain()`, never this
    /// field directly.
    pub password: String,
    /// True while `password` is still the auto-generated default (the user
    /// hasn't set their own yet). Cleared the moment the user sets a password.
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
/// (generating a password). The generated password is stored **encrypted**;
/// only a redacted notice is logged (the value is never logged). An operator
/// retrieves it with `dn7-panel password`.
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
        password: crate::crypto::encrypt(&gen_password()),
        pw_default: true,
    };
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!(
        port = s.port,
        username = %s.username,
        "web console initialized (account + password generated; run `dn7-panel password` to view it)"
    );
    s
}

/// Read persisted settings without seeding a new file. Returns None when the
/// console hasn't been initialized yet. Used by the `password` subcommand.
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
    fn legacy_plaintext_password_reads_verbatim() {
        let s = WebSettings {
            enabled: true,
            port: 1080,
            username: "admin".into(),
            password: "PlainDefault123".into(),
            pw_default: true,
        };
        // A legacy/plaintext-stored value (no ':') is read back verbatim.
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
