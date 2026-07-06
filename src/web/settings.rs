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

/// The console settings entity now lives in the domain layer; re-exported so
/// call sites (`crate::web::settings::WebSettings`) stay stable while this
/// module keeps the credential/reset behaviour and validation. Persistence is
/// delegated to infra/store.
pub(crate) use crate::core::settings::{default_timeout, WebSettings};
pub(crate) use crate::infra::store::settings::{load, load_strict, save};

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

/// Whether `s` is a usable security entry path: 1–64 chars of ASCII letters,
/// digits, `-` or `_` — no slashes, dots, or spaces (it becomes a single URL path
/// segment). Empty is "disabled" and is the caller's concern; this returns false
/// for empty. A leading `/` the operator may type is tolerated by the caller
/// (which trims it) — this validator sees the bare segment.
pub fn valid_entry_path(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A fresh 6-letter security entry path — the default when the operator turns the
/// entry gate on without choosing one.
pub fn random_entry_path() -> String {
    dn7_cred::random_alpha_lower(6)
}

/// Normalize an operator-typed entry path to the stored bare segment: trim, drop
/// a leading `/`. Returns `None` if the result is non-empty but invalid (so the
/// caller can reject it); `Some("")` means "disable the gate".
pub fn normalize_entry_path(raw: &str) -> Option<String> {
    let s = raw.trim().trim_start_matches('/').trim();
    if s.is_empty() {
        return Some(String::new());
    }
    if valid_entry_path(s) {
        Some(s.to_string())
    } else {
        None
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
    /// external-address/HTTPS choice. `owner_uid` is preserved (the
    /// reset-authorization anchor). The web init token is left EMPTY: re-init runs
    /// through the CLI mode menu on the next launch, which re-arms a token itself
    /// only if the operator picks UI-custom mode. Returns "" (kept so the caller's
    /// signature is stable).
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
        self.entry_path = String::new();
        // Leave no token armed: the next launch re-enters the CLI mode menu, which
        // re-arms one only if the operator chooses UI-custom mode.
        self.init_token = String::new();
        String::new()
    }
}

/// Load persisted settings, or seed a fresh UNINITIALIZED record (with a one-time
/// init token). The `Option<String>` return is vestigial (always `None` now — the
/// old auto-generated password is gone); kept so call sites stay stable.
pub fn load_or_init(default_port: u16) -> (WebSettings, Option<String>) {
    // Base-read STRICT so a corrupt web.json is NOT collapsed into "absent" and
    // then seeded-and-saved over: web.json holds the superadmin verifier + TOTP
    // secret + IP allow-list — the most sensitive store — so one disk
    // corruption / transient EIO must not silently erase the owner account.
    //   - Ok(Some(s)) → a persisted file (initialized or not) is returned
    //     verbatim; a seeded-but-not-initialized install keeps the SAME init
    //     token across reboots.
    //   - Ok(None)    → the file is genuinely ABSENT (fresh install) → seed.
    //   - Err(e)      → the file was present but UNPARSEABLE. load_strict has
    //     already QUARANTINED it aside to web.json.corrupt-<ts>; we must NOT
    //     resurrect an empty uninitialized default at web.json (that would enter
    //     the restart-as-uninitialized loop and bury the quarantined data). We
    //     return an UNINITIALIZED seed WITHOUT persisting it, so run_panel's
    //     `!initialized` gate refuses to serve and exits the process non-zero
    //     (the process exit is owned by the crate root, never the web layer) —
    //     the service shows failed and the operator can restore the quarantine
    //     copy or re-run the CLI wizard, far better than a silent clobber.
    let corrupt = match load_strict() {
        Ok(Some(s)) => return (s, None),
        Ok(None) => false,
        Err(e) => {
            tracing::error!(
                "web.json 已损坏且无法解析（已隔离备份，原文件已移到旁边）：{e:#} — \
                 拒绝以未初始化状态覆盖它。请恢复隔离副本或在终端运行 `dn7-panel` 重新初始化。 \
                 web.json is corrupt and unparseable (a quarantine copy was moved aside): \
                 refusing to overwrite it with a fresh uninitialized default. Restore the \
                 quarantine copy or run `dn7-panel` in a terminal to re-initialize."
            );
            true
        }
    };
    let _ = default_port;
    // Fresh install: seed an UNINITIALIZED record. No account, password, secret
    // entry path, or random public port — the operator bootstraps through the
    // token-gated wizard the edge serves on :80. Only the one-time init token is
    // generated (and printed to the launch banner). The `port` field is now
    // vestigial (the console binds the fixed loopback const); kept for the model.
    let s = WebSettings {
        port: dn7_edge::CONSOLE_LOOPBACK_PORT,
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
        init_token: String::new(),
        external_address: String::new(),
        https_mode: "none".to_string(),
        website_http_port: crate::core::settings::default_website_http_port(),
        website_https_port: crate::core::settings::default_website_https_port(),
        console_port: 0,
        entry_path: String::new(),
        language: String::new(),
        timezone: String::new(),
        session_timeout: default_timeout(),
        allow_ips: Vec::new(),
        trusted_proxies: Vec::new(),
    };
    if corrupt {
        // Base file was corrupt (now quarantined): return the uninitialized seed
        // but do NOT save over web.json. run_panel refuses to serve on
        // `!initialized` and exits non-zero; the quarantined owner credentials
        // stay recoverable.
        return (s, None);
    }
    if let Err(e) = save(&s) {
        tracing::warn!("could not persist web settings: {e}");
    }
    tracing::info!(
        "web console seeded (uninitialized — run `dn7-panel` in a terminal to initialize)"
    );
    (s, None)
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
            initialized: false,
            init_token: String::new(),
            external_address: String::new(),
            https_mode: "none".into(),
            website_http_port: 80,
            website_https_port: 443,
            console_port: 0,
            entry_path: String::new(),
            language: String::new(),
            timezone: String::new(),
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
    fn reset_clears_creds_and_token() {
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
            website_http_port: 80,
            website_https_port: 443,
            console_port: 0,
            entry_path: String::new(),
            language: String::new(),
            timezone: String::new(),
            session_timeout: 1440,
            allow_ips: Vec::new(),
            trusted_proxies: Vec::new(),
        };
        let token = s.reset();
        // Credentials + setup state cleared; owner preserved; no web init token
        // (first-run setup re-runs via the CLI).
        assert!(s.username.is_empty() && s.pw_hash.is_empty() && s.totp_secret.is_empty());
        assert!(!s.initialized);
        assert!(s.external_address.is_empty());
        assert_eq!(s.https_mode, "none");
        assert_eq!(s.owner_uid, 1000);
        assert!(token.is_empty());
        assert!(s.init_token.is_empty());
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
