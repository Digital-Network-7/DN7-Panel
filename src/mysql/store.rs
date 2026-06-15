//! MySQL engine catalog + on-disk manifest store (split from mysql.rs).
use super::*;

// ---------------------------------------------------------------------------
// Supported engines + versions (curated). 8.0 is the default in the UI.
// ---------------------------------------------------------------------------

/// Curated version list per engine, newest first. The UI defaults to "8.0".
pub(crate) fn supported_versions(engine: &str) -> &'static [&'static str] {
    match engine {
        "mysql" => &["8.4", "8.0", "5.7"],
        "mariadb" => &["11.4", "10.11", "10.6"],
        _ => &[],
    }
}

/// Validate an engine name.
pub(crate) fn valid_engine(e: &str) -> bool {
    e == "mysql" || e == "mariadb"
}

/// Validate a version against the curated list for the engine (prevents an
/// arbitrary tag / injection into the image reference).
pub(crate) fn valid_version(engine: &str, version: &str) -> bool {
    supported_versions(engine).contains(&version)
}

/// The Docker image reference for an engine+version (official images only).
pub(crate) fn image_ref(engine: &str, version: &str) -> String {
    // Both `mysql` and `mariadb` are official Docker Hub images.
    format!("{engine}:{version}")
}

// ---------------------------------------------------------------------------
// Manifest store: <data>/mysql/<id>.json, 0600.
// ---------------------------------------------------------------------------

pub(crate) fn mysql_dir() -> std::path::PathBuf {
    crate::paths::data_dir().join("mysql")
}

pub(crate) fn manifest_path(id: &str) -> std::path::PathBuf {
    mysql_dir().join(format!("{id}.json"))
}

pub(crate) fn save_manifest(m: &Manifest) -> Result<()> {
    crate::json_store::save_private(&manifest_path(&m.id), m)
}

pub(crate) fn load_manifest(id: &str) -> Result<Manifest> {
    let raw = std::fs::read_to_string(manifest_path(id))
        .map_err(|_| anyhow!("ERR_CODE:mysql.instance_not_found"))?;
    let m: Manifest = serde_json::from_str(&raw).map_err(|e| anyhow!("实例清单损坏：{e}"))?;
    Ok(m)
}

pub(crate) fn delete_manifest(id: &str) {
    let _ = std::fs::remove_file(manifest_path(id));
}

pub(crate) fn all_manifests() -> Vec<Manifest> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(mysql_dir()) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(raw) = std::fs::read_to_string(&p) {
                    if let Ok(m) = serde_json::from_str::<Manifest>(&raw) {
                        out.push(m);
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    out
}

/// Generate a strong random root password (no shell-special chars so it's safe
/// to pass as a separate argv entry / env value; length 24).
pub(crate) fn gen_password() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
