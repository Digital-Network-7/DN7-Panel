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

use rand::Rng;
use sha2::{Digest, Sha256};

/// The console settings entity now lives in the domain layer; re-exported so
/// call sites (`crate::web::settings::WebSettings`) stay stable while this
/// module keeps the credential/reset behaviour and validation. Persistence is
/// delegated to infra/store.
pub(crate) use crate::core::settings::{default_timeout, default_username, WebSettings};
pub(crate) use crate::infra::store::settings::{load, save};

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

/// A 32-char alphanumeric one-time init token, printed to the launch banner and
/// required (as `?init_token=`) to reach the first-run wizard.
pub fn gen_init_token() -> String {
    const CS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
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

    /// Set a password from a client-computed salt + hash + KDF scheme (so the
    /// plaintext never crosses the wire). Marked non-default.
    pub fn set_password_hashed(&mut self, salt: &str, hash: &str, kdf: &str) {
        self.pw_salt = salt.to_string();
        self.pw_hash = hash.to_string();
        self.pw_kdf = kdf.to_string();
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
        // Server-generated default uses the legacy single-hash scheme; it
        // migrates to a stretched KDF when the operator sets their own password.
        self.pw_kdf = String::new();
        self.pw_default = true;
        pw
    }
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
    if let Some(s) = load() {
        if !s.pw_hash.is_empty() {
            return (s, None);
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
        pw_kdf: String::new(), // legacy single-hash default; migrates on first change
        pw_default: true,
        owner_uid: current_uid(),
        full_name: String::new(),
        nickname: String::new(),
        avatar: String::new(),
        totp_secret: String::new(),
        totp_enabled: false,
        entry_path: gen_entry(),
        https: false,
        // Secure default: bind to loopback only. A fresh install is reachable
        // from the host (or via an SSH tunnel); the operator opts into public
        // exposure (all interfaces) in Settings — ideally with HTTPS on — rather
        // than a brand-new install sitting on 0.0.0.0 in cleartext by default.
        public_access: false,
        // Init-flow fields (Phase 3 rewrites this seeding to drop the random
        // port/entry/password above and lead with these).
        initialized: false,
        init_token: gen_init_token(),
        external_address: String::new(),
        https_mode: "none".to_string(),
        session_timeout: default_timeout(),
        allow_ips: Vec::new(),
        trusted_proxies: Vec::new(),
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
            pw_kdf: String::new(),
            pw_default: true,
            owner_uid: 0,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            entry_path: "/".into(),
            https: false,
            public_access: true,
            initialized: false,
            init_token: String::new(),
            external_address: String::new(),
            https_mode: "none".into(),
            session_timeout: 1440,
            allow_ips: Vec::new(),
            trusted_proxies: Vec::new(),
        };
        let salt = "0123456789abcdef0123456789abcdef";
        s.set_password_hashed(salt, &hash_password(salt, "mySecret!42"), "");
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
            pw_kdf: String::new(),
            pw_default: false,
            owner_uid: 1000,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            entry_path: "/".into(),
            https: false,
            public_access: true,
            initialized: false,
            init_token: String::new(),
            external_address: String::new(),
            https_mode: "none".into(),
            session_timeout: 1440,
            allow_ips: Vec::new(),
            trusted_proxies: Vec::new(),
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
