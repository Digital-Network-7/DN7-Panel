//! Console settings entity (persisted to `web.json`).
//!
//! NOTE: a persisted **domain entity** — the `serde` derive is a reviewed
//! exception to the "domain default-forbids serde" rule (see steering §2/§4).
//! Pure data + serde defaults only; the credential/reset behaviour, validation
//! and persistence live in `web::settings` (and will move to infra later).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WebSettings {
    /// TCP port to bind (0.0.0.0:<port>).
    pub(crate) port: u16,
    /// Login account name (default "admin"; user-editable).
    #[serde(default = "default_username")]
    pub(crate) username: String,
    /// Random per-install salt (hex) for the password hash.
    #[serde(default)]
    pub(crate) pw_salt: String,
    /// The irreversible password verifier and shared secret for challenge-
    /// response login. Computed client-side per [`pw_kdf`](Self::pw_kdf).
    #[serde(default)]
    pub(crate) pw_hash: String,
    /// Key-derivation scheme used to compute `pw_hash` from the password, so
    /// login recomputes the same verifier. Empty (or "sha256") = legacy single
    /// `sha256(salt ":" password)`; "s256:N" = N salted-SHA-256 iterations (a
    /// key-stretch). Empty for accounts set before stretching existed; they
    /// migrate to "s256:N" the next time the password is changed.
    #[serde(default)]
    pub(crate) pw_kdf: String,
    /// True while the password is still the auto-generated default (the user
    /// hasn't set their own yet).
    #[serde(default = "default_true")]
    pub(crate) pw_default: bool,
    /// uid of the OS user that first initialized the console; `dn7 panel reset`
    /// is restricted to this user (or root).
    #[serde(default)]
    pub(crate) owner_uid: u32,
    /// Super-admin profile (shown in the account menu). `full_name`/`nickname`
    /// are panel-side display fields; `avatar` is a base64 data URL.
    #[serde(default)]
    pub(crate) full_name: String,
    #[serde(default)]
    pub(crate) nickname: String,
    #[serde(default)]
    pub(crate) avatar: String,
    /// TOTP 2FA: base32 secret (empty = none). `totp_enabled` is set only after
    /// the operator verifies a live code during enrollment.
    #[serde(default)]
    pub(crate) totp_secret: String,
    #[serde(default)]
    pub(crate) totp_enabled: bool,
    /// Secret "safe entry" path that must prefix the URL to reach the login page
    /// (e.g. "/ab12cd"). "/" disables the gate. Generated random on first run.
    #[serde(default = "default_entry")]
    pub(crate) entry_path: String,
    /// Serve the console over HTTPS with a self-signed cert (default off).
    #[serde(default)]
    pub(crate) https: bool,
    /// Allow the console to be reached directly from any address (bind
    /// `0.0.0.0`). When **off**, it binds loopback only (`127.0.0.1`) so it's
    /// reachable only through an nginx reverse proxy or an SSH tunnel on the
    /// host — the recommended hardening. Default on. Changing needs a restart.
    #[serde(default = "default_true")]
    pub(crate) public_access: bool,
    /// Session inactivity timeout, in minutes (default 1440 = 24h). Applied
    /// live to the auth layer.
    #[serde(default = "default_timeout")]
    pub(crate) session_timeout: u32,
    /// Authorized client IPs / CIDRs allowed to reach the console. Empty = allow
    /// any address. Loopback is always allowed (avoids a self-lockout).
    #[serde(default)]
    pub(crate) allow_ips: Vec<String>,
    /// Trusted front-proxy IPs / CIDRs. When the TCP peer matches one of these,
    /// the rightmost `X-Forwarded-For` entry is taken as the real client IP for
    /// rate-limiting and the allow-list. Empty = trust nothing (only the direct
    /// TCP peer, never a forwardable header) — the safe default.
    #[serde(default)]
    pub(crate) trusted_proxies: Vec<String>,
}

pub(crate) fn default_username() -> String {
    "admin".to_string()
}

fn default_entry() -> String {
    "/".to_string()
}

fn default_true() -> bool {
    true
}

/// Default session inactivity timeout in minutes (24h).
pub(crate) fn default_timeout() -> u32 {
    1440
}
