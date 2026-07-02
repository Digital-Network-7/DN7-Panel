//! `commit`: capture a container's overlay upper (its filesystem changes) as a
//! new image layer on top of its parent image. MVP scope: additions +
//! modifications — overlay-whiteout *deletions* (char-dev 0:0 markers in the
//! upper) need translation to OCI `.wh.` entries, which is deferred. The whole
//! upper is held in memory while tarring (fine for typical commits).

use std::io::Write;
use std::path::Path;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::image::reference::Reference;
use crate::image::store::Store;
use crate::image::ImageRecord;

/// Commit the container at `bundle_dir` (which must hold `parent.json` + `upper/`)
/// as the new image `new_ref`. Returns the new image's record.
pub fn commit(store: &Store, bundle_dir: &Path, new_ref: &str) -> Result<ImageRecord> {
    let r = Reference::parse(new_ref)?;

    let parent_path = bundle_dir.join("parent.json");
    let parent: ImageRecord =
        serde_json::from_slice(&std::fs::read(&parent_path).map_err(Error::io(&parent_path))?)?;

    let upper = bundle_dir.join("upper");
    if !upper.is_dir() {
        return Err(Error::Other(
            "container has no overlay upper to commit".into(),
        ));
    }

    // Tar the upper (uncompressed) → diff_id; gzip it → the layer blob digest.
    let mut tar_buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_buf);
        b.append_dir_all("", &upper)
            .map_err(|e| Error::Other(format!("tar upper: {e}")))?;
        b.finish()
            .map_err(|e| Error::Other(format!("tar finish: {e}")))?;
    }
    let diff_id = format!("sha256:{}", hex(&Sha256::digest(&tar_buf)));

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_buf)
        .map_err(|e| Error::Other(format!("gzip layer: {e}")))?;
    let gzipped = gz
        .finish()
        .map_err(|e| Error::Other(format!("gzip finish: {e}")))?;
    let layer_digest = format!("sha256:{}", hex(&Sha256::digest(&gzipped)));
    store.save_blob(&layer_digest, |w| {
        w.write_all(&gzipped)
            .map_err(|e| Error::Other(format!("write layer: {e}")))
    })?;

    // New config = parent config with the new diff_id appended to rootfs.diff_ids.
    let cfg_bytes = store.read_blob(&parent.config_digest)?;
    let mut cfg: Value = serde_json::from_slice(&cfg_bytes)?;
    let diff_ids = cfg
        .get_mut("rootfs")
        .and_then(|r| r.get_mut("diff_ids"))
        .and_then(|d| d.as_array_mut())
        .ok_or_else(|| Error::Other("parent config missing rootfs.diff_ids".into()))?;
    diff_ids.push(Value::String(diff_id));
    let new_cfg_bytes = serde_json::to_vec(&cfg)?;
    let new_cfg_digest = format!("sha256:{}", hex(&Sha256::digest(&new_cfg_bytes)));
    store.save_blob(&new_cfg_digest, |w| {
        w.write_all(&new_cfg_bytes)
            .map_err(|e| Error::Other(format!("write config: {e}")))
    })?;

    let mut layers = parent.layers.clone();
    layers.push(layer_digest);
    let rec = ImageRecord {
        reference: r.canonical(),
        config_digest: new_cfg_digest,
        layers,
    };
    store.write_image_json(&r.store_key(), &serde_json::to_vec_pretty(&rec)?)?;
    Ok(rec)
}

fn hex(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
