//! State-dir layout + on-disk stores (sites, named certs) (split from nginx.rs).
use super::*;

// ---------------------------------------------------------------------------
// State directory layout (persisted under the panel runtime dir).
//
//   <base>/nginx/setup_done    marker that host nginx setup completed
//   <base>/nginx/sites.json    the site manifest
//   <base>/nginx/certs/        per-site + named certs (nginx reads from here)
//   <base>/nginx/www/          static webroots (nginx reads from here)
//
// Generated conf files go directly into the host's /etc/nginx/conf.d.
// ---------------------------------------------------------------------------

pub(crate) fn base_dir() -> std::path::PathBuf {
    crate::platform::paths::default_base_dir().join("nginx")
}
pub(crate) fn setup_marker() -> std::path::PathBuf {
    base_dir().join("setup_done")
}
pub(crate) fn sites_file() -> std::path::PathBuf {
    base_dir().join("sites.json")
}
pub(crate) fn certs_dir() -> std::path::PathBuf {
    base_dir().join("certs")
}
pub(crate) fn www_dir() -> std::path::PathBuf {
    base_dir().join("www")
}

/// Host nginx config drop-in directory.
pub(crate) const HOST_CONFD: &str = "/etc/nginx/conf.d";

/// Where we write HTTP Basic Auth htpasswd files. This MUST live under
/// `/etc/nginx` (not the panel's private `/var/dn7/...` tree): the nginx
/// *worker* opens `auth_basic_user_file` at request time as its run-user
/// (www-data / nginx), so the file and every parent directory must be
/// traversable by that account — and on SELinux systems the file needs an
/// nginx-readable context, which `/etc/nginx/*` already carries. Keeping it
/// under the panel dir made the worker hit EACCES and return 500 for every
/// request (correct password or not).
pub(crate) const HOST_ACCESS_DIR: &str = "/etc/nginx/dn7-access";

/// Whether host nginx setup has been completed (marker file present).
pub(crate) fn is_setup() -> bool {
    setup_marker().exists()
}

pub(crate) fn mark_setup() -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(setup_marker(), "host")?;
    Ok(())
}

/// Serializes nginx state read-modify-write ops (the sites + access manifests)
/// so two concurrent admin requests can't clobber each other's writes (lost
/// update) or interleave a load/save around the await-heavy validate+reload.
/// A tokio Mutex (it's held across `.await`); nginx ops are admin-only and
/// low-frequency, so the serialization cost is negligible. **Non-reentrant** —
/// a locked op must not call another locked op while holding the guard.
pub(crate) fn state_lock() -> &'static tokio::sync::Mutex<()> {
    static L: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) fn load_sites() -> Vec<Site> {
    // Cached (mtime+len-validated): read repeatedly during conf generation.
    crate::infra::json_store::load_or_default_cached(&sites_file())
}

pub(crate) fn save_sites(sites: &[Site]) -> Result<()> {
    crate::infra::json_store::save_pretty(&sites_file(), sites)
}

// ---------------------------------------------------------------------------
// Standalone named-certificate store.
//
// Certs can be created independently of any site (manifest `certs.json`) and
// then referenced by one or more sites. Each named cert is stored as
//   <cert_store>/cert-<name>.crt   and   cert-<name>.key
// so a site that references it just points its conf at those files.
// ---------------------------------------------------------------------------

/// A standalone, named certificate. The PEM files live in the cert store; this
/// manifest just records its name, the domain it was issued for, and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NamedCert {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) domain: String,
    #[serde(default)]
    pub(crate) cert_mode: String, // "self" | "le" | "manual"
}

pub(crate) fn certs_manifest_file() -> std::path::PathBuf {
    base_dir().join("certs.json")
}

pub(crate) fn load_named_certs() -> Vec<NamedCert> {
    crate::infra::json_store::load_or_default(&certs_manifest_file())
}

pub(crate) fn save_named_certs(certs: &[NamedCert]) -> Result<()> {
    crate::infra::json_store::save_pretty(&certs_manifest_file(), certs)
}

pub(crate) fn named_crt_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.crt"))
}
pub(crate) fn named_key_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.key"))
}
/// Derive a filesystem-safe cert manifest key from a domain. Certs are keyed by
/// (unique) domain now — there's no separate user-chosen name. `*` (wildcard)
/// is replaced so the result stays a valid cert name / filename token.
pub(crate) fn cert_name_from_domain(domain: &str) -> String {
    domain
        .trim()
        .to_ascii_lowercase()
        .replace('*', "_wildcard_")
        .chars()
        .take(64)
        .collect()
}
