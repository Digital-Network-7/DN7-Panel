//! Nginx domain: persisted entities (Site/Location/AccessList/…) plus the
//! tuning / default-site rules. The pure input validators live in the
//! `validate` submodule; all are re-exported so callers keep using
//! `crate::domain::nginx::*`.

mod validate;
pub(crate) use validate::*;

use serde::{Deserialize, Serialize};

/// An nginx capability error — a typed, exhaustive replacement for the scattered
/// `anyhow!("ERR_CODE:nginx.*")` string literals. Each variant owns its stable
/// `nginx.*` semantic code (aligned with the frontend `err.<code>` map) in one
/// place, so the code set can't drift or typo. Domain owns only the semantic
/// code; the `ERR_CODE:` transport marker the `op_err_body` boundary parses is
/// added in infra (per §2/§4). Transitional alongside the existing
/// [`TuningError`]; both flow through the `op_err_body` channel for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NginxError {
    AccessNotFound,
    BadAccessName,
    BadAuthPw,
    BadAuthUser,
    BadCertName,
    BadCertNameChars,
    BadClientAddr,
    BadContainer,
    BadContainerPort,
    BadDomain,
    BadFilePath,
    BadStaticDir,
    BadStaticDirName,
    BadTarget,
    BadTrustCidr,
    CertDomainExists,
    CertNotFound,
    DupAuthUser,
    DuplicateDomain,
    ExtraConfBad,
    ExtraConfTooLong,
    LeIssueTimeout,
    LeNeedDomainSpecific,
    LeNoHttp01,
    LeVerifyTimeout,
    LocalRootAbs,
    LocalRootDenied,
    LocalRootMissing,
    LocalRootNotDir,
    ManualNoRenew,
    MissingAccessId,
    MissingCertName,
    MissingFilePath,
    MissingSiteId,
    NeedAccessName,
    NeedAuthPw,
    NeedCertDomain,
    NeedCertKey,
    NeedContainer,
    NeedDomain,
    NeedRoot,
    NeedStaticDir,
    NeedTarget,
    NotSetup,
    SiteNotFound,
    TooManyRules,
    UnknownCertMode,
    UnknownSiteKind,
    UnknownUploadMode,
}

impl NginxError {
    /// The stable, `nginx.`-namespaced semantic code (no transport prefix).
    pub(crate) fn code(self) -> &'static str {
        use NginxError::*;
        match self {
            AccessNotFound => "nginx.access_not_found",
            BadAccessName => "nginx.bad_access_name",
            BadAuthPw => "nginx.bad_auth_pw",
            BadAuthUser => "nginx.bad_auth_user",
            BadCertName => "nginx.bad_cert_name",
            BadCertNameChars => "nginx.bad_cert_name_chars",
            BadClientAddr => "nginx.bad_client_addr",
            BadContainer => "nginx.bad_container",
            BadContainerPort => "nginx.bad_container_port",
            BadDomain => "nginx.bad_domain",
            BadFilePath => "nginx.bad_file_path",
            BadStaticDir => "nginx.bad_static_dir",
            BadStaticDirName => "nginx.bad_static_dir_name",
            BadTarget => "nginx.bad_target",
            BadTrustCidr => "nginx.bad_trust_cidr",
            CertDomainExists => "nginx.cert_domain_exists",
            CertNotFound => "nginx.cert_not_found",
            DupAuthUser => "nginx.dup_auth_user",
            DuplicateDomain => "nginx.duplicate_domain",
            ExtraConfBad => "nginx.extra_conf_bad",
            ExtraConfTooLong => "nginx.extra_conf_too_long",
            LeIssueTimeout => "nginx.le_issue_timeout",
            LeNeedDomainSpecific => "nginx.le_need_domain_specific",
            LeNoHttp01 => "nginx.le_no_http01",
            LeVerifyTimeout => "nginx.le_verify_timeout",
            LocalRootAbs => "nginx.local_root_abs",
            LocalRootDenied => "nginx.local_root_denied",
            LocalRootMissing => "nginx.local_root_missing",
            LocalRootNotDir => "nginx.local_root_not_dir",
            ManualNoRenew => "nginx.manual_no_renew",
            MissingAccessId => "nginx.missing_access_id",
            MissingCertName => "nginx.missing_cert_name",
            MissingFilePath => "nginx.missing_file_path",
            MissingSiteId => "nginx.missing_site_id",
            NeedAccessName => "nginx.need_access_name",
            NeedAuthPw => "nginx.need_auth_pw",
            NeedCertDomain => "nginx.need_cert_domain",
            NeedCertKey => "nginx.need_cert_key",
            NeedContainer => "nginx.need_container",
            NeedDomain => "nginx.need_domain",
            NeedRoot => "nginx.need_root",
            NeedStaticDir => "nginx.need_static_dir",
            NeedTarget => "nginx.need_target",
            NotSetup => "nginx.not_setup",
            SiteNotFound => "nginx.site_not_found",
            TooManyRules => "nginx.too_many_rules",
            UnknownCertMode => "nginx.unknown_cert_mode",
            UnknownSiteKind => "nginx.unknown_site_kind",
            UnknownUploadMode => "nginx.unknown_upload_mode",
        }
    }
}

impl std::fmt::Display for NginxError {
    /// Renders the semantic code only; the infra boundary adds the `ERR_CODE:`
    /// marker when building the wire error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for NginxError {}

/// A managed site, persisted in the manifest and regenerated into one conf file.
///
/// NOTE: a persisted **domain entity** — the `serde` derive is a reviewed
/// exception (see steering §2/§4). Fields are `pub(crate)` so the nginx
/// submodules (confgen/sites/access/…) can read/build them across modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Site {
    pub(crate) id: String,
    pub(crate) server_name: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) target_url: String,
    #[serde(default)]
    pub(crate) container: String,
    #[serde(default)]
    pub(crate) container_port: i64,
    #[serde(default)]
    pub(crate) root: String,
    /// Static site served from an existing absolute host directory (instead of
    /// the panel-managed `<www>/<root>` upload dir). Empty == upload mode.
    #[serde(default)]
    pub(crate) local_root: String,
    #[serde(default)]
    pub(crate) ssl: bool,
    #[serde(default)]
    pub(crate) cert_mode: String,
    /// When set, this site uses a standalone named cert from the cert manifest
    /// instead of a per-site `<id>.crt/.key`. Empty means per-site (legacy).
    #[serde(default)]
    pub(crate) cert_name: String,
    /// Upstream scheme for proxy kinds ("http" | "https"). Empty == http.
    #[serde(default)]
    pub(crate) scheme: String,
    /// Behaviour toggles (NPM-style): long-cache static assets, block common
    /// exploit patterns, and enable WebSocket upgrade headers on proxies.
    #[serde(default)]
    pub(crate) cache: bool,
    #[serde(default)]
    pub(crate) block_attacks: bool,
    #[serde(default)]
    pub(crate) websockets: bool,
    /// HTTPS feature toggles. `force_ssl` (HTTP→HTTPS redirect) and `http2`
    /// default on for backward compatibility; the rest default off.
    #[serde(default = "default_true")]
    pub(crate) force_ssl: bool,
    #[serde(default = "default_true")]
    pub(crate) http2: bool,
    #[serde(default)]
    pub(crate) hsts: bool,
    #[serde(default)]
    pub(crate) hsts_sub: bool,
    #[serde(default)]
    pub(crate) trust_proxy: bool,
    /// Trusted front-proxy sources for `real_ip` (comma/space/newline-separated
    /// IPs or CIDRs). Only honoured when `trust_proxy` is set. Empty means trust
    /// private/loopback ranges only — never the entire internet.
    #[serde(default)]
    pub(crate) trust_proxy_cidrs: String,
    /// Extra path rules layered on top of the main location (NPM "custom
    /// locations"): each forwards a path prefix to a host[:port].
    #[serde(default)]
    pub(crate) locations: Vec<Location>,
    /// Raw nginx directives, injected verbatim into the serving server block(s).
    /// Validated by `nginx -t` on save (invalid input rolls back).
    #[serde(default)]
    pub(crate) extra_conf: String,
    /// Access list id controlling this site (HTTP Basic Auth + IP allow/deny).
    /// Empty == publicly accessible.
    #[serde(default)]
    pub(crate) access_id: String,
}

fn default_true() -> bool {
    true
}

/// A custom path rule layered on a proxy site: forward a path prefix to a
/// host[:port] over http/https. Form-driven (no raw nginx config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct Location {
    /// The location prefix, e.g. "/api". Must start with '/'.
    pub(crate) path: String,
    /// Upstream scheme: "http" | "https". Empty == http.
    #[serde(default)]
    pub(crate) scheme: String,
    /// Upstream host[:port].
    #[serde(default)]
    pub(crate) target: String,
    /// Enable WebSocket upgrade headers for this path.
    #[serde(default)]
    pub(crate) websockets: bool,
    /// Upstream kind: "host" (target host:port) | "container" (docker
    /// container). Empty == host (backward compatible).
    #[serde(default)]
    pub(crate) kind: String,
    /// Docker container name (when `kind == "container"`).
    #[serde(default)]
    pub(crate) container: String,
    /// Container port to proxy to (when `kind == "container"`).
    #[serde(default)]
    pub(crate) container_port: i64,
}

// ---------------------------------------------------------------------------
// Persisted nginx domain entities (access lists, default-site, http tuning).
//
// NOTE: persisted **domain entities** — the `serde` derives are reviewed
// exceptions (see steering §2/§4). Fields are `pub(crate)` so the nginx
// submodules (access/store/confgen/htpasswd/…) read/build them across modules.
// Transport input (AccessUserInput) stays in the nginx module, not here.
// ---------------------------------------------------------------------------

/// A stored access list. Passwords are kept only as nginx-htpasswd hashes
/// (`{SHA}…`), never in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessList {
    pub(crate) id: String,
    pub(crate) name: String,
    /// "any" | "all" — how auth and IP rules combine (nginx `satisfy`).
    #[serde(default)]
    pub(crate) satisfy: String,
    /// Forward the client's Authorization header to the upstream (else strip).
    #[serde(default)]
    pub(crate) pass_auth: bool,
    #[serde(default)]
    pub(crate) users: Vec<AccessUser>,
    #[serde(default)]
    pub(crate) clients: Vec<AccessClient>,
}

/// A basic-auth credential: the username and its precomputed htpasswd hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccessUser {
    pub(crate) username: String,
    /// nginx-compatible hash, e.g. `{SHA}base64(sha1(password))`.
    #[serde(default)]
    pub(crate) hash: String,
}

/// An allow/deny rule against a client address (IP, CIDR, or "all").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AccessClient {
    /// "allow" | "deny".
    pub(crate) directive: String,
    /// IP / CIDR / "all".
    pub(crate) address: String,
}

/// Default-site behaviour for requests matching no managed server_name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DefaultSite {
    /// "404" | "welcome" | "444" | "redirect".
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) redirect_url: String,
}

impl Default for DefaultSite {
    fn default() -> Self {
        DefaultSite {
            mode: "404".to_string(),
            redirect_url: String::new(),
        }
    }
}

/// Global website settings (persisted in `websettings.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct WebGlobal {
    #[serde(default)]
    pub(crate) default_site: DefaultSite,
}

/// nginx http/server tuning knobs (persisted in `webtuning.json`). Values
/// mirror nginx's own defaults. The server-context ones are injected into each
/// managed site's server block (so they override per-site without clashing with
/// the distro nginx.conf's http-level directives); `server_names_hash_bucket_size`
/// is http-only and written to a guarded http include.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HttpTuning {
    #[serde(default = "d_snhbs")]
    pub(crate) server_names_hash_bucket_size: u32,
    #[serde(default = "d_gzip_on")]
    pub(crate) gzip: bool,
    #[serde(default = "d_ghdr")]
    pub(crate) client_header_buffer_size: String,
    #[serde(default = "d_gmin")]
    pub(crate) gzip_min_length: u32,
    #[serde(default = "d_cmbs")]
    pub(crate) client_max_body_size: String,
    #[serde(default = "d_gcl")]
    pub(crate) gzip_comp_level: u8,
    #[serde(default = "d_kat")]
    pub(crate) keepalive_timeout: u32,
}
fn d_snhbs() -> u32 {
    64
}
fn d_ghdr() -> String {
    "32k".to_string()
}
fn d_gmin() -> u32 {
    20
}
fn d_cmbs() -> String {
    "50m".to_string()
}
fn d_gcl() -> u8 {
    1
}
fn d_kat() -> u32 {
    60
}
fn d_gzip_on() -> bool {
    true
}
impl Default for HttpTuning {
    fn default() -> Self {
        HttpTuning {
            server_names_hash_bucket_size: d_snhbs(),
            gzip: true,
            client_header_buffer_size: d_ghdr(),
            gzip_min_length: d_gmin(),
            client_max_body_size: d_cmbs(),
            gzip_comp_level: d_gcl(),
            keepalive_timeout: d_kat(),
        }
    }
}

/// Optional http/server tuning inputs from a `set_tuning` request. `None` means
/// "keep the current value". Pure transport-free shape consumed by
/// [`merge_http_tuning`].
#[derive(Default)]
pub(crate) struct HttpTuningInput {
    pub(crate) server_names_hash_bucket_size: Option<u32>,
    pub(crate) gzip: Option<bool>,
    pub(crate) client_header_buffer_size: Option<String>,
    pub(crate) gzip_min_length: Option<u32>,
    pub(crate) client_max_body_size: Option<String>,
    pub(crate) gzip_comp_level: Option<u8>,
    pub(crate) keepalive_timeout: Option<u32>,
}

/// A nginx tuning / default-site validation failure. A **semantic** value (no
/// transport or frontend `err.*` string — per architecture §2 the domain must
/// not carry protocol content). The app boundary maps each variant to the
/// transitional `ERR_CODE:` channel (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuningError {
    HashBucket,
    CompLevel,
    MinLength,
    Keepalive,
    SizeValue,
    DefaultMode,
    RedirectUrl,
}

/// Validate a tuning request against fixed bounds and merge it over the current
/// values (any omitted field keeps its current value). Returns the merged
/// entity, or a semantic [`TuningError`]. Pure rule, unit-testable.
pub(crate) fn merge_http_tuning(
    cur: &HttpTuning,
    input: &HttpTuningInput,
) -> Result<HttpTuning, TuningError> {
    let snhbs = input
        .server_names_hash_bucket_size
        .unwrap_or(cur.server_names_hash_bucket_size);
    if ![32u32, 64, 128, 256, 512].contains(&snhbs) {
        return Err(TuningError::HashBucket);
    }
    let gcl = input.gzip_comp_level.unwrap_or(cur.gzip_comp_level);
    if !(1..=9).contains(&gcl) {
        return Err(TuningError::CompLevel);
    }
    let gmin = input.gzip_min_length.unwrap_or(cur.gzip_min_length);
    if gmin > 10_000_000 {
        return Err(TuningError::MinLength);
    }
    let kat = input.keepalive_timeout.unwrap_or(cur.keepalive_timeout);
    if kat > 86_400 {
        return Err(TuningError::Keepalive);
    }
    let chdr = input
        .client_header_buffer_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_header_buffer_size)
        .to_string();
    let cmbs = input
        .client_max_body_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_max_body_size)
        .to_string();
    if !valid_size_value(&chdr) || !valid_size_value(&cmbs) {
        return Err(TuningError::SizeValue);
    }
    Ok(HttpTuning {
        server_names_hash_bucket_size: snhbs,
        gzip: input.gzip.unwrap_or(cur.gzip),
        client_header_buffer_size: chdr,
        gzip_min_length: gmin,
        client_max_body_size: cmbs,
        gzip_comp_level: gcl,
        keepalive_timeout: kat,
    })
}

/// Validate a default-site (catch-all) request and build the persisted entity.
/// `mode` must be one of `404`/`welcome`/`444`/`redirect`; a `redirect` mode
/// requires a valid http(s) URL. Returns a semantic [`TuningError`] on failure.
/// Pure rule.
pub(crate) fn build_default_site(
    mode_input: &str,
    redirect_url_input: &str,
) -> Result<WebGlobal, TuningError> {
    let mode = match mode_input {
        m @ ("404" | "welcome" | "444" | "redirect") => m.to_string(),
        _ => return Err(TuningError::DefaultMode),
    };
    let redirect_url = redirect_url_input.trim().to_string();
    if mode == "redirect" && !valid_redirect_url(&redirect_url) {
        return Err(TuningError::RedirectUrl);
    }
    Ok(WebGlobal {
        default_site: DefaultSite { mode, redirect_url },
    })
}

#[cfg(test)]
mod nginx_error_tests {
    use super::*;

    #[test]
    fn codes_namespaced_snake_case_and_wire_stable() {
        // A representative code matches the exact frontend `err.*` string.
        assert_eq!(NginxError::DuplicateDomain.code(), "nginx.duplicate_domain");
        // Display is the semantic code only (no transport prefix in domain).
        assert_eq!(NginxError::SiteNotFound.to_string(), "nginx.site_not_found");
        // Exhaustive shape check across every variant.
        for e in [
            NginxError::AccessNotFound,
            NginxError::BadAccessName,
            NginxError::BadAuthPw,
            NginxError::BadAuthUser,
            NginxError::BadCertName,
            NginxError::BadCertNameChars,
            NginxError::BadClientAddr,
            NginxError::BadContainer,
            NginxError::BadContainerPort,
            NginxError::BadDomain,
            NginxError::BadFilePath,
            NginxError::BadStaticDir,
            NginxError::BadStaticDirName,
            NginxError::BadTarget,
            NginxError::BadTrustCidr,
            NginxError::CertDomainExists,
            NginxError::CertNotFound,
            NginxError::DupAuthUser,
            NginxError::DuplicateDomain,
            NginxError::ExtraConfBad,
            NginxError::ExtraConfTooLong,
            NginxError::LeIssueTimeout,
            NginxError::LeNeedDomainSpecific,
            NginxError::LeNoHttp01,
            NginxError::LeVerifyTimeout,
            NginxError::LocalRootAbs,
            NginxError::LocalRootDenied,
            NginxError::LocalRootMissing,
            NginxError::LocalRootNotDir,
            NginxError::ManualNoRenew,
            NginxError::MissingAccessId,
            NginxError::MissingCertName,
            NginxError::MissingFilePath,
            NginxError::MissingSiteId,
            NginxError::NeedAccessName,
            NginxError::NeedAuthPw,
            NginxError::NeedCertDomain,
            NginxError::NeedCertKey,
            NginxError::NeedContainer,
            NginxError::NeedDomain,
            NginxError::NeedRoot,
            NginxError::NeedStaticDir,
            NginxError::NeedTarget,
            NginxError::NotSetup,
            NginxError::SiteNotFound,
            NginxError::TooManyRules,
            NginxError::UnknownCertMode,
            NginxError::UnknownSiteKind,
            NginxError::UnknownUploadMode,
        ] {
            let c = e.code();
            assert!(c.starts_with("nginx."), "{c} not namespaced");
            assert!(
                c[6..]
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{c} not snake_case"
            );
        }
    }
}

#[cfg(test)]
mod tuning_tests {
    use super::*;

    #[test]
    fn merge_keeps_current_when_omitted() {
        let cur = HttpTuning::default();
        let merged = merge_http_tuning(&cur, &HttpTuningInput::default()).unwrap();
        assert_eq!(
            merged.server_names_hash_bucket_size,
            cur.server_names_hash_bucket_size
        );
        assert_eq!(merged.keepalive_timeout, cur.keepalive_timeout);
        assert_eq!(merged.client_max_body_size, cur.client_max_body_size);
    }

    #[test]
    fn merge_rejects_out_of_bounds() {
        let cur = HttpTuning::default();
        let bad_bucket = HttpTuningInput {
            server_names_hash_bucket_size: Some(100),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_bucket).unwrap_err(),
            TuningError::HashBucket
        );
        let bad_level = HttpTuningInput {
            gzip_comp_level: Some(10),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_level).unwrap_err(),
            TuningError::CompLevel
        );
        let bad_size = HttpTuningInput {
            client_max_body_size: Some("50x".to_string()),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_size).unwrap_err(),
            TuningError::SizeValue
        );
    }

    #[test]
    fn merge_accepts_valid_override() {
        let cur = HttpTuning::default();
        let input = HttpTuningInput {
            server_names_hash_bucket_size: Some(128),
            gzip_comp_level: Some(6),
            client_max_body_size: Some("100m".to_string()),
            keepalive_timeout: Some(75),
            ..Default::default()
        };
        let merged = merge_http_tuning(&cur, &input).unwrap();
        assert_eq!(merged.server_names_hash_bucket_size, 128);
        assert_eq!(merged.gzip_comp_level, 6);
        assert_eq!(merged.client_max_body_size, "100m");
        assert_eq!(merged.keepalive_timeout, 75);
    }

    #[test]
    fn redirect_url_validation() {
        assert!(valid_redirect_url("https://example.com/path"));
        assert!(valid_redirect_url("http://a.test"));
        assert!(!valid_redirect_url("ftp://x"));
        assert!(!valid_redirect_url("https://a b.com"));
        assert!(!valid_redirect_url("javascript:alert(1)"));
    }

    #[test]
    fn default_site_rules() {
        assert!(build_default_site("bogus", "").is_err());
        assert!(build_default_site("welcome", "").is_ok());
        assert_eq!(
            build_default_site("redirect", "not-a-url").unwrap_err(),
            TuningError::RedirectUrl
        );
        let g = build_default_site("redirect", " https://x.test ").unwrap();
        assert_eq!(g.default_site.mode, "redirect");
        assert_eq!(g.default_site.redirect_url, "https://x.test");
    }
}
