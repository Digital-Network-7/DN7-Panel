//! MySQL on-disk manifest store: a pure persistence adapter (per-instance
//! `<data>/mysql/<id>.json` at 0600). Engine catalog + credential generation
//! live in `catalog`.
use super::*;

pub(crate) fn mysql_dir() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("mysql")
}

pub(crate) fn manifest_path(id: &str) -> std::path::PathBuf {
    mysql_dir().join(format!("{id}.json"))
}

pub(crate) fn save_manifest(m: &Manifest) -> Result<()> {
    crate::infra::support::json_store::save_private(&manifest_path(&m.id), m)
}

pub(crate) fn load_manifest(id: &str) -> Result<Manifest> {
    let raw = std::fs::read_to_string(manifest_path(id))
        .map_err(|_| mysql_err(MysqlError::InstanceNotFound))?;
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
    out.sort_by_key(|m| m.created_at);
    out
}
