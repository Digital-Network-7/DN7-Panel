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
    /// Super-admin profile (shown in the account menu). `full_name`/`nickname`
    /// are panel-side display fields; `avatar` is a base64 data URL.
    #[serde(default)]
    pub full_name: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub avatar: String,
    /// TOTP 2FA: base32 secret (empty = none). `totp_enabled` is set only after
    /// the operator verifies a live code during enrollment.
    #[serde(default)]
    pub totp_secret: String,
    #[serde(default)]
    pub totp_enabled: bool,
    /// Secret "safe entry" path that must prefix the URL to reach the login page
    /// (e.g. "/ab12cd"). "/" disables the gate. Generated random on first run.
    #[serde(default = "default_entry")]
    pub entry_path: String,
    /// Serve the console over HTTPS with a self-signed cert (default off).
    #[serde(default)]
    pub https: bool,
    /// Session inactivity timeout, in minutes (default 1440 = 24h). Applied
    /// live to the auth layer.
    #[serde(default = "default_timeout")]
    pub session_timeout: u32,
    /// Authorized client IPs / CIDRs allowed to reach the console. Empty = allow
    /// any address. Loopback is always allowed (avoids a self-lockout).
    #[serde(default)]
    pub allow_ips: Vec<String>,
}

fn default_username() -> String {
    "admin".to_string()
}

fn default_entry() -> String {
    "/".to_string()
}

fn default_true() -> bool {
    true
}

/// Default session inactivity timeout in minutes (24h).
fn default_timeout() -> u32 {
    1440
}

/// A random 6-char lowercase-alnum safe-entry path ("/xxxxxx").
pub fn gen_entry() -> String {
    const CS: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let tok: String = (0..6)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect();
    format!("/{tok}")
}

/// A random high TCP port (20000..=60000) for a fresh install.
pub fn gen_port() -> u16 {
    rand::thread_rng().gen_range(20000..=60000)
}

/// Validate/normalize a safe-entry path: "/" (disabled) or "/<token>" where the
/// token is 1..=32 of [A-Za-z0-9_-] and not a reserved route. Returns the
/// normalized "/<token>" (or "/"), or None if invalid.
pub fn normalize_entry(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches('/').trim_end_matches('/');
    if t.is_empty() {
        return Some("/".to_string());
    }
    if t.len() > 32
        || !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        || matches!(t, "api" | "ui")
    {
        return None;
    }
    Some(format!("/{t}"))
}

/// Validate + normalize an authorized-IP allow list: each non-empty entry must
/// be an IPv4/IPv6 address or CIDR. Returns the deduped list, or None if any
/// entry is invalid. An empty result means "allow any address".
pub fn normalize_allow_ips(raw: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for line in raw {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if !valid_ip_or_cidr(t) {
            return None;
        }
        if !out.iter().any(|x| x == t) {
            out.push(t.to_string());
        }
    }
    if out.len() > 200 {
        return None;
    }
    Some(out)
}

/// Whether `s` is a valid IPv4/IPv6 address or CIDR block.
fn valid_ip_or_cidr(s: &str) -> bool {
    if let Some((addr, pfx)) = s.split_once('/') {
        match (addr.parse::<std::net::IpAddr>(), pfx.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        }
    } else {
        s.parse::<std::net::IpAddr>().is_ok()
    }
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

    /// Set a password from a client-computed salt + hash (so the plaintext never
    /// crosses the wire). Marked non-default.
    pub fn set_password_hashed(&mut self, salt: &str, hash: &str) {
        self.pw_salt = salt.to_string();
        self.pw_hash = hash.to_string();
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
pub fn load_or_init(default_port: u16) -> (WebSettings, Option<String>) {
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
        // Fresh install: a random high port + secret entry path (printed once in
        // the banner). The provided default_port is only a fallback.
        port: gen_port(),
        username: default_username(),
        pw_hash: hash_password(&salt, &pw),
        pw_salt: salt,
        pw_default: true,
        owner_uid: current_uid(),
        full_name: String::new(),
        nickname: String::new(),
        avatar: String::new(),
        totp_secret: String::new(),
        totp_enabled: false,
        entry_path: gen_entry(),
        https: false,
        session_timeout: default_timeout(),
        allow_ips: Vec::new(),
    };
    let _ = default_port;
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

/// Persist settings to `<data>/web.json` with 0600 perms (atomic, no
/// create-then-chmod window).
pub fn save(s: &WebSettings) -> Result<()> {
    crate::json_store::save_private(&settings_path(), s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_hashed_irreversibly() {
        let mut s = WebSettings {
            port: 1080,
            username: "admin".into(),
            pw_salt: String::new(),
            pw_hash: String::new(),
            pw_default: true,
            owner_uid: 0,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            entry_path: "/".into(),
            https: false,
            session_timeout: 1440,
            allow_ips: Vec::new(),
        };
        let salt = "0123456789abcdef0123456789abcdef";
        s.set_password_hashed(salt, &hash_password(salt, "mySecret!42"));
        // Stored as salt + hash, never the plaintext.
        assert_eq!(s.pw_salt, salt);
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
            port: 1080,
            username: "bob".into(),
            pw_salt: "aa".into(),
            pw_hash: "bb".into(),
            pw_default: false,
            owner_uid: 1000,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            entry_path: "/".into(),
            https: false,
            session_timeout: 1440,
            allow_ips: Vec::new(),
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

    #[test]
    fn allow_ip_validation() {
        assert_eq!(
            normalize_allow_ips(&["1.2.3.4".into(), " 10.0.0.0/8 ".into(), "".into()]),
            Some(vec!["1.2.3.4".to_string(), "10.0.0.0/8".to_string()])
        );
        // Dedup.
        assert_eq!(
            normalize_allow_ips(&["1.2.3.4".into(), "1.2.3.4".into()]),
            Some(vec!["1.2.3.4".to_string()])
        );
        // Bad address / prefix → None.
        assert!(normalize_allow_ips(&["999.1.1.1".into()]).is_none());
        assert!(normalize_allow_ips(&["10.0.0.0/40".into()]).is_none());
        assert!(normalize_allow_ips(&["nonsense".into()]).is_none());
    }
}
