//! State-dir layout + on-disk stores (sites, named certs) (split from nginx.rs).
use super::*;

// ---------------------------------------------------------------------------
// State directory layout (persisted under the panel runtime dir).
//
//   <base>/nginx/setup_done    marker that website (edge) setup completed
//   <base>/nginx/sites.json    the site manifest
//   <base>/nginx/certs/        per-site + named certs (the edge reads from here)
//   <base>/nginx/www/          static webroots (the edge reads from here)
//
// The edge server builds its route table from these manifests directly — there
// are no generated nginx config files.
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

/// Whether the website (edge server) setup has been completed (marker present).
pub(crate) fn is_setup() -> bool {
    setup_marker().exists()
}

pub(crate) fn mark_setup() -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(setup_marker(), "host")?;
    Ok(())
}

/// Serializes website state read-modify-write ops (the sites + access manifests)
/// so two concurrent admin requests can't clobber each other's writes (lost
/// update) or interleave a load/save around the await-heavy validate+reload.
/// A tokio Mutex (it's held across `.await`); website ops are admin-only and
/// low-frequency, so the serialization cost is negligible. **Non-reentrant** —
/// a locked op must not call another locked op while holding the guard.
pub(crate) fn state_lock() -> &'static tokio::sync::Mutex<()> {
    static L: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(crate) fn load_sites() -> Vec<Site> {
    // Cached (mtime+len-validated): read repeatedly during conf generation.
    crate::infra::support::json_store::load_or_default_cached(&sites_file())
}

/// Strict load for the read-modify-write path: `Err` (and the bad file is
/// quarantined) when sites.json is present but unparseable, so an add/remove/
/// update REFUSES to save rather than clobbering the whole manifest with an
/// empty default. `Ok(Vec::new())` only when the file is genuinely absent.
pub(crate) fn load_sites_strict() -> Result<Vec<Site>> {
    Ok(crate::infra::support::json_store::load_strict(&sites_file())?.unwrap_or_default())
}

pub(crate) fn save_sites(sites: &[Site]) -> Result<()> {
    crate::infra::support::json_store::save_pretty(&sites_file(), sites)
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
    /// Key algorithm for auto-generated certs, persisted for renewal:
    /// "" (=ecdsa-p256) | "ecdsa-p256" | "ecdsa-p384".
    #[serde(default)]
    pub(crate) key_type: String,
}

pub(crate) fn certs_manifest_file() -> std::path::PathBuf {
    base_dir().join("certs.json")
}

pub(crate) fn load_named_certs() -> Vec<NamedCert> {
    // Cached: read during list/conf generation; the save path busts the cache.
    crate::infra::support::json_store::load_or_default_cached(&certs_manifest_file())
}

pub(crate) fn save_named_certs(certs: &[NamedCert]) -> Result<()> {
    crate::infra::support::json_store::save_pretty(&certs_manifest_file(), certs)
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
