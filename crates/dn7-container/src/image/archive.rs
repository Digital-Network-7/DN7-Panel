//! Export/import images as OCI image-layout tar archives (`dn7crun save`/`load`).
//! Moves images between hosts without a registry — e.g. `save` on a connected
//! machine, copy the tar across a filtered network, `load` on the target.
//!
//! The archive is a plain tar containing `oci-layout`, `index.json`, and
//! `blobs/sha256/<hex>` for the manifest, config, and each (already-gzipped)
//! layer. The manifest is reconstructed from the stored `ImageRecord`.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::image::manifest::Manifest;
use crate::image::reference::Reference;
use crate::image::store::{split_digest, Store};
use crate::image::ImageRecord;

const OCI_LAYOUT: &str = "{\"imageLayoutVersion\":\"1.0.0\"}";
const MT_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MT_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const MT_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const MT_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// Write `reference`'s image to `out` as an OCI image-layout tar.
pub fn save(store: &Store, reference: &str, out: &Path) -> Result<()> {
    let r = Reference::parse(reference)?;
    let rec = ImageRecord::load(store, &r.store_key())?;

    // Reconstruct the manifest from the record + on-disk blob sizes.
    let mut layers_json = Vec::with_capacity(rec.layers.len());
    for d in &rec.layers {
        layers_json.push(json!({"mediaType": MT_LAYER, "digest": d, "size": blob_size(store, d)?}));
    }
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MT_MANIFEST,
        "config": {
            "mediaType": MT_CONFIG,
            "digest": rec.config_digest,
            "size": blob_size(store, &rec.config_digest)?,
        },
        "layers": layers_json,
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = format!("sha256:{}", hex_sha256(&manifest_bytes));

    let index = json!({
        "schemaVersion": 2,
        "mediaType": MT_INDEX,
        "manifests": [{
            "mediaType": MT_MANIFEST,
            "digest": manifest_digest,
            "size": manifest_bytes.len(),
            "annotations": { "org.opencontainers.image.ref.name": rec.reference },
        }],
    });
    let index_bytes = serde_json::to_vec(&index)?;

    // Open the output symlink-safely: O_EXCL refuses to follow a pre-planted
    // symlink (a local low-priv user can't redirect the export onto a file they
    // couldn't otherwise write), and 0600 keeps the tar private while in flight.
    // `create_new` also means we never silently clobber an existing target.
    let file = create_out(out)?;
    let mut tar = tar::Builder::new(file);
    append_bytes(&mut tar, "oci-layout", OCI_LAYOUT.as_bytes())?;
    append_bytes(&mut tar, "index.json", &index_bytes)?;
    append_bytes(&mut tar, &blob_tar_path(&manifest_digest)?, &manifest_bytes)?;
    for d in std::iter::once(&rec.config_digest).chain(rec.layers.iter()) {
        let data = store.read_blob(d)?;
        append_bytes(&mut tar, &blob_tar_path(d)?, &data)?;
    }
    tar.finish()
        .map_err(|e| Error::Other(format!("finish tar: {e}")))
}

/// Hard caps for a loaded archive. Layer blobs stream straight into the CAS
/// store (verified during the copy) so they never sit whole in RAM; only the
/// tiny metadata (index.json) is buffered. The caps stop a hostile/oversized
/// archive from exhausting memory, inodes, or the data volume.
const MAX_ENTRIES: usize = 8192; // tar entries we'll iterate before bailing
const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024 * 1024; // ≤ 32 GiB per blob (layer)
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024; // ≤ 64 GiB across all blobs
const MAX_META_BYTES: u64 = 8 * 1024 * 1024; // ≤ 8 MiB for index.json (buffered)

/// Import an OCI image-layout tar into the store, tagging it `reference`.
///
/// Blobs are streamed entry-by-entry through the CAS store's hashing writer, so
/// even a multi-GB layer is verified during the copy without being held in RAM.
/// The manifest + config are read back from the store afterwards to reconstruct
/// the `ImageRecord`. A digest mismatch, a missing blob, or any cap breach
/// rejects the whole load.
pub fn load(store: &Store, input: &Path, reference: &str) -> Result<ImageRecord> {
    let r = Reference::parse(reference)?;
    let file = File::open(input).map_err(Error::io(input))?;
    let mut ar = tar::Archive::new(file);

    // Stream every blob into the store (verified as it copies); buffer only the
    // tiny index.json. Track which blob digests we actually stored so we can
    // reject a manifest/config/layer the archive references but never shipped.
    let mut index_bytes: Option<Vec<u8>> = None;
    let mut stored: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut entries = 0usize;
    let mut total: u64 = 0;
    for entry in ar.entries().map_err(terr)? {
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(Error::Other("archive has too many entries".into()));
        }
        let mut e = entry.map_err(terr)?;
        let path = e.path().map_err(terr)?.to_string_lossy().into_owned();
        if path == "index.json" {
            let mut data = Vec::new();
            e.take(MAX_META_BYTES + 1)
                .read_to_end(&mut data)
                .map_err(terr)?;
            if data.len() as u64 > MAX_META_BYTES {
                return Err(Error::Other(
                    "archive index.json is implausibly large".into(),
                ));
            }
            index_bytes = Some(data);
        } else if let Some(hex) = path.strip_prefix("blobs/sha256/") {
            let digest = format!("sha256:{hex}");
            // Reject the digest shape up front (also guards the store key).
            split_digest(&digest)?;
            let entry_cap = MAX_BLOB_BYTES.min(MAX_TOTAL_BYTES.saturating_sub(total));
            store.save_blob_from_reader(&digest, &mut e, entry_cap)?;
            // Charge the stored size against the running total (blobs already
            // present short-circuit save_blob with no write, so re-derive size).
            total = total.saturating_add(blob_size(store, &digest)? as u64);
            if total > MAX_TOTAL_BYTES {
                return Err(Error::Other("archive exceeds total size cap".into()));
            }
            stored.insert(digest);
        }
        // Other paths (oci-layout, stray files) are ignored — we reconstruct
        // everything from the index + manifest, not from arbitrary tar members.
    }

    let index: Value = serde_json::from_slice(&index_bytes.ok_or_else(no_index)?)?;
    let manifest_digest = index["manifests"][0]["digest"]
        .as_str()
        .ok_or_else(|| Error::Other("archive index has no manifest digest".into()))?
        .to_string();
    if !stored.contains(&manifest_digest) {
        return Err(Error::Other("archive missing the manifest blob".into()));
    }
    // Read the (verified) manifest back from the CAS store to reconstruct the
    // record — it's tiny and its digest was already checked on the way in.
    let manifest_bytes = store.read_blob(&manifest_digest)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

    let config_digest = manifest.config.digest.clone();
    if !stored.contains(&config_digest) {
        return Err(Error::Other(format!(
            "archive missing blob {config_digest}"
        )));
    }
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for l in &manifest.layers {
        if !stored.contains(&l.digest) {
            return Err(Error::Other(format!("archive missing blob {}", l.digest)));
        }
        layers.push(l.digest.clone());
    }

    let rec = ImageRecord {
        reference: r.canonical(),
        config_digest,
        layers,
    };
    store.write_image_json(&r.store_key(), &serde_json::to_vec_pretty(&rec)?)?;
    Ok(rec)
}

/// Create the export output file with `O_CREAT | O_EXCL` (never follow/clobber
/// an existing path or symlink) and mode 0600. Callers pass either a random
/// staging name (web export) or a fresh timestamped name (backup / CLI), so the
/// exclusive create won't spuriously collide in normal use.
fn create_out(out: &Path) -> Result<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_CREAT | O_EXCL
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(out).map_err(Error::io(out))
}

fn blob_tar_path(digest: &str) -> Result<String> {
    let (_, hex) = split_digest(digest)?;
    Ok(format!("blobs/sha256/{hex}"))
}

fn blob_size(store: &Store, digest: &str) -> Result<i64> {
    let p = store.blob_path(digest)?;
    Ok(std::fs::metadata(&p).map_err(Error::io(&p))?.len() as i64)
}

fn append_bytes<W: Write>(b: &mut tar::Builder<W>, path: &str, data: &[u8]) -> Result<()> {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_data(&mut h, path, data)
        .map_err(|e| Error::Other(format!("tar write {path}: {e}")))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for x in digest {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn no_index() -> Error {
    Error::Other("archive has no index.json".into())
}

fn terr(e: std::io::Error) -> Error {
    Error::Other(format!("archive tar: {e}"))
}
