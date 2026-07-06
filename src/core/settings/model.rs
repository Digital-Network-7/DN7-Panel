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

    // --- Init-flow redesign: the console is fronted by the edge (:80/:443) and
    // bootstrapped via a token-gated wizard instead of a pre-generated
    // account/port/entry-path. `initialized` is the single source of truth. ---
    /// Whether the operator has completed first-run setup (chose an external
    /// address + HTTPS, set an account + password). The single authoritative
    /// "is this panel set up?" flag — replaces the old `pw_default`/`username`
    /// heuristics. A fresh / legacy file defaults `false` → the wizard runs.
    #[serde(default)]
    pub(crate) initialized: bool,
    /// One-time 32-char first-boot token. Printed to the launch banner and
    /// required (as `?init_token=`) to reach the init wizard. Cleared once
    /// `initialized` is set. Empty after setup.
    #[serde(default)]
    pub(crate) init_token: String,
    /// The operator-chosen external access address for the console — an IP (the
    /// detected default) or a domain. Becomes the console's `server_name` on the
    /// edge. Empty until the wizard's step 1.
    #[serde(default)]
    pub(crate) external_address: String,
    /// Console HTTPS mode at the edge: "none" (plain :80), "selfsigned", or "le"
    /// (Let's Encrypt — only when `external_address` is a domain).
    #[serde(default = "default_https_mode")]
    pub(crate) https_mode: String,
    /// Public HTTP port the edge serves hosted websites on (plain), default 80.
    /// Port 80 is ALSO always bound for ACME HTTP-01 issuance even when this
    /// differs — Let's Encrypt keeps working (see the edge listener).
    #[serde(default = "default_website_http_port")]
    pub(crate) website_http_port: u16,
    /// Public HTTPS port the edge serves hosted websites on (TLS), default 443.
    #[serde(default = "default_website_https_port")]
    pub(crate) website_https_port: u16,
    /// Client-facing port the console is reached on. `0` = "merged": the console
    /// shares a website listener by Host (today's behaviour) — used for a legacy
    /// file or when the operator keeps the console on a website port. A distinct
    /// non-zero value opens a DEDICATED console listener (the console is served
    /// ONLY there, plus loopback for SSH tunnels).
    #[serde(default)]
    pub(crate) console_port: u16,
    /// Security entry path (obscurity front door). When non-empty, the console is
    /// hidden: only a request that hits `/<entry_path>` (which returns the login
    /// page + sets a `dn7_entry` cookie) or carries the matching `X-DN7-Entry`
    /// header / `dn7_entry` cookie is served — everything else 404s. Empty =
    /// disabled (the console is served at `/`). A short string of letters/digits.
    #[serde(default)]
    pub(crate) entry_path: String,
    /// Default console UI language for browsers that haven't chosen one: one of
    /// "zh-CN" | "zh-TW" | "en" | "ja". Empty = follow the browser (legacy).
    #[serde(default)]
    pub(crate) language: String,
    /// IANA timezone (e.g. "Asia/Shanghai") the console displays times in. Empty =
    /// the viewer's browser-local time (legacy). Also written to the host
    /// (`/etc/localtime` + `/etc/timezone`) at init so server-side / container /
    /// journald times match.
    #[serde(default)]
    pub(crate) timezone: String,

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

fn default_true() -> bool {
    true
}

/// Default console HTTPS mode: plain HTTP until the wizard configures a cert.
fn default_https_mode() -> String {
    "none".to_string()
}

/// Default public website HTTP / HTTPS ports (the well-known web ports).
pub(crate) fn default_website_http_port() -> u16 {
    80
}
pub(crate) fn default_website_https_port() -> u16 {
    443
}

/// Default session inactivity timeout in minutes (24h).
pub(crate) fn default_timeout() -> u32 {
    1440
}
