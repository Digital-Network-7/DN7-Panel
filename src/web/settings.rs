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
    /// Auto-generated access password (shown once in the daemon log; the user
    /// can also read it via an authenticated settings call).
    pub password: String,
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
        password: gen_password(),
    };
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!(
        port = s.port,
        password = %s.password,
        "web console initialized (access password generated)"
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
