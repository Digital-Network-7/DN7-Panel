//! Persisted web-console settings (`<data>/web.json`, 0600).
//!
//! The console password is stored **irreversibly**: the client sends a per-
//! install salt + verifier (`sha256(salt ":" password)`) and the server keeps
//! `Argon2id(verifier)` at rest — the plaintext is never written to disk or
//! logged and cannot be recovered, and login is a challenge-response over the
//! verifier, so the plaintext never crosses the wire either.
//!
//! There is no auto-generated account: a fresh install is seeded UNINITIALIZED
//! with only a one-time `init_token` (printed to the launch banner), and the
//! operator sets the account + password through the token-gated first-run
//! wizard. `dn7 panel reset` (install owner / root only) clears the account and
//! re-arms a fresh init token so the wizard can be re-run.

use rand::Rng;

/// The console settings entity now lives in the domain layer; re-exported so
/// call sites (`crate::web::settings::WebSettings`) stay stable while this
/// module keeps the credential/reset behaviour and validation. Persistence is
/// delegated to infra/store.
pub(crate) use crate::core::settings::{default_timeout, WebSettings};
pub(crate) use crate::infra::store::settings::{load, save};

/// A 32-char alphanumeric one-time init token, printed to the launch banner and
/// required (as `?init_token=`) to reach the first-run wizard.
pub fn gen_init_token() -> String {
    const CS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CS[rng.gen_range(0..CS.len())] as char)
        .collect()
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

    /// Reset to the UNINITIALIZED state: clear the account/credentials + the
    /// external-address/HTTPS choice, and re-arm a fresh one-time init token
    /// (returned so `dn7 panel reset` can print it and the operator can re-run
    /// the wizard). `owner_uid` is preserved (the reset-authorization anchor).
    pub fn reset(&mut self) -> String {
        self.username = String::new();
        self.pw_hash = String::new();
        self.pw_salt = String::new();
        self.pw_kdf = String::new();
        self.pw_default = true;
        self.totp_secret = String::new();
        self.totp_enabled = false;
        self.initialized = false;
        self.external_address = String::new();
        self.https_mode = "none".to_string();
        let token = gen_init_token();
        self.init_token = token.clone();
        token
    }
}

/// Self-heal a freshly-loaded record into a SAFE init-gate state, returning
/// whether it changed (so the caller persists). Two unsafe states the init gate
/// would otherwise treat as "open the wizard to anyone" are repaired:
///   - a record that is `!initialized` with no token but DOES have credentials —
///     a pre-redesign install that predates the `initialized` flag: it is
///     already set up, so mark it initialized (else a routine upgrade would
///     re-expose a configured panel to unauthenticated remote takeover);
///   - a record that is `!initialized` with no token AND no credentials (a
///     hand-edited / truncated file): re-arm a token so the gate stays CLOSED.
///
/// A normal record (initialized, or uninitialized-with-token) is left untouched.
fn migrate_loaded(s: &mut WebSettings) -> bool {
    if s.initialized || !s.init_token.is_empty() {
        return false;
    }
    if !s.pw_hash.is_empty() {
        s.initialized = true;
    } else {
        s.init_token = gen_init_token();
    }
    true
}

/// Load persisted settings, or seed a fresh file from the env-var defaults
/// (generating a password). On a fresh seed the generated plaintext password is
/// returned as `Some` so the caller can show it once (the launch banner); it is
/// never stored in plaintext or logged. Returns `None` for the plaintext when
/// an existing file was loaded.
pub fn load_or_init(default_port: u16) -> (WebSettings, Option<String>) {
    // A persisted file (initialized or not) is returned — a seeded but
    // not-yet-initialized install keeps the SAME init token across reboots —
    // but FIRST self-heal two unsafe states the init gate would otherwise treat
    // as "open the wizard to anyone":
    if let Some(mut s) = load() {
        if migrate_loaded(&mut s) {
            if let Err(e) = save(&s) {
                tracing::warn!("could not persist settings self-heal: {e}");
            }
        }
        return (s, None);
    }
    let _ = default_port;
    // Fresh install: seed an UNINITIALIZED record. No account, password, secret
    // entry path, or random public port — the operator bootstraps through the
    // token-gated wizard the edge serves on :80. Only the one-time init token is
    // generated (and printed to the launch banner). The `port` field is now
    // vestigial (the console binds the fixed loopback const); kept for the model.
    let s = WebSettings {
        port: crate::edge::CONSOLE_LOOPBACK_PORT,
        username: String::new(),
        pw_hash: String::new(),
        pw_salt: String::new(),
        pw_kdf: String::new(),
        pw_default: true,
        owner_uid: current_uid(),
        full_name: String::new(),
        nickname: String::new(),
        avatar: String::new(),
        totp_secret: String::new(),
        totp_enabled: false,
        initialized: false,
        init_token: gen_init_token(),
        external_address: String::new(),
        https_mode: "none".to_string(),
        session_timeout: default_timeout(),
        allow_ips: Vec::new(),
        trusted_proxies: Vec::new(),
    };
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!("web console seeded (uninitialized — init token shown in the launch banner)");
    (s, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal WebSettings via serde (unspecified fields take their
    // serde defaults: initialized=false, init_token="").
    fn ws(v: serde_json::Value) -> WebSettings {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn migrate_legacy_credentialed_record_is_marked_initialized() {
        // A pre-redesign file: it has an account/verifier but no init flag/token.
        // The self-heal must treat it as already set up — NOT re-expose the
        // wizard (the upgrade-takeover hole this guards).
        let mut s = ws(serde_json::json!({
            "port": 1080, "username": "bob", "pw_hash": "deadbeef", "pw_default": false
        }));
        assert!(!s.initialized && s.init_token.is_empty());
        assert!(migrate_loaded(&mut s), "a legacy record needs healing");
        assert!(s.initialized, "credentialed legacy record -> initialized");
        assert!(
            s.init_token.is_empty(),
            "no token armed for a configured install"
        );
    }

    #[test]
    fn migrate_tokenless_uninitialized_rearms_a_token() {
        // No credentials, no token, not initialized (a truncated/hand-edited
        // file): re-arm a token so the gate stays CLOSED (requires the token).
        let mut s = ws(serde_json::json!({ "port": 1080 }));
        assert!(migrate_loaded(&mut s));
        assert!(!s.initialized);
        assert_eq!(s.init_token.len(), 32, "a fresh token is armed");
    }

    #[test]
    fn migrate_is_noop_for_initialized_or_tokened_records() {
        // An already-initialized record is untouched.
        let mut a = ws(serde_json::json!({ "port": 1080, "initialized": true }));
        assert!(!migrate_loaded(&mut a));
        // A normal uninitialized record that already carries its token is
        // untouched (the token must stay stable across reboots).
        let mut b = ws(serde_json::json!({ "port": 1080, "init_token": "tok123" }));
        assert!(!migrate_loaded(&mut b));
        assert_eq!(b.init_token, "tok123");
        assert!(!b.initialized);
    }

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
            initialized: false,
            init_token: String::new(),
            external_address: String::new(),
            https_mode: "none".into(),
            session_timeout: 1440,
            allow_ips: Vec::new(),
            trusted_proxies: Vec::new(),
        };
        // set_password_hashed stores the CLIENT-computed salt + verifier + KDF
        // verbatim (the server never sees/derives the plaintext) and clears the
        // default flag.
        let salt = "0123456789abcdef0123456789abcdef";
        let hash = "a".repeat(64);
        s.set_password_hashed(salt, &hash, "s256:30000");
        assert_eq!(s.pw_salt, salt);
        assert_eq!(s.pw_hash, hash);
        assert_eq!(s.pw_kdf, "s256:30000");
        assert_eq!(s.verifier(), hash);
        assert!(!s.pw_default);
    }

    #[test]
    fn reset_clears_creds_and_rearms_token() {
        let mut s = WebSettings {
            port: 1080,
            username: "bob".into(),
            pw_salt: "aa".into(),
            pw_hash: "bb".into(),
            pw_kdf: "s256:30000".into(),
            pw_default: false,
            owner_uid: 1000,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: "SECRET".into(),
            totp_enabled: true,
            initialized: true,
            init_token: String::new(),
            external_address: "panel.example.com".into(),
            https_mode: "le".into(),
            session_timeout: 1440,
            allow_ips: Vec::new(),
            trusted_proxies: Vec::new(),
        };
        let token = s.reset();
        // Credentials + setup state cleared; owner preserved; fresh 32-char token.
        assert!(s.username.is_empty() && s.pw_hash.is_empty() && s.totp_secret.is_empty());
        assert!(!s.initialized);
        assert!(s.external_address.is_empty());
        assert_eq!(s.https_mode, "none");
        assert_eq!(s.owner_uid, 1000);
        assert_eq!(token.len(), 32);
        assert_eq!(s.init_token, token);
    }

    #[test]
    fn init_token_is_random_and_32_chars() {
        let a = gen_init_token();
        assert_eq!(a.len(), 32);
        assert_ne!(a, gen_init_token());
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
