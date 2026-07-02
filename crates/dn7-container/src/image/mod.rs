//! Image subsystem: resolve a reference, pull its manifest/config/layers from a
//! registry into the content store, and (P2b) assemble a runnable rootfs.

pub mod archive;
pub mod commit;
pub mod layer;
pub mod manifest;
pub mod reference;
pub mod registry;
pub mod spec_gen;
pub mod store;
pub mod volume;

pub use reference::Reference;
pub use store::Store;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::image::manifest::{ImageConfig, Index, Manifest};
use crate::image::registry::Registry;

/// What a successful pull leaves behind: the resolved reference, the config blob
/// digest, and the ordered layer digests — enough to assemble + run the image
/// without touching the network again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecord {
    pub reference: String,
    pub config_digest: String,
    pub layers: Vec<String>,
}

impl ImageRecord {
    /// Load a previously-pulled image's record from the store.
    pub fn load(store: &Store, key: &str) -> Result<ImageRecord> {
        let bytes = store.read_image_json(key)?;
        serde_json::from_slice(&bytes).map_err(Error::Json)
    }

    /// The image's config blob, parsed (container defaults + rootfs diff_ids).
    pub fn config(&self, store: &Store) -> Result<ImageConfig> {
        let bytes = store.read_blob(&self.config_digest)?;
        serde_json::from_slice(&bytes).map_err(Error::Json)
    }
}

/// A summary of a stored image, for listing.
#[derive(Debug, Clone)]
pub struct ImageSummary {
    pub reference: String,
    pub config_digest: String,
    /// Total on-disk size (config + all layer blobs), bytes.
    pub size: u64,
    /// When the image was stored locally (image.json mtime), Unix seconds.
    pub created_ts: i64,
}

/// List every image in the store (scans `images/*/image.json`).
pub fn list_summaries(store: &Store) -> Result<Vec<ImageSummary>> {
    let dir = store.root().join("images");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Error::Io {
                path: dir,
                source: e,
            })
        }
    };
    let mut out = Vec::new();
    for ent in entries.flatten() {
        let key = ent.file_name().to_string_lossy().into_owned();
        let Ok(rec) = ImageRecord::load(store, &key) else {
            continue;
        };
        let size = blob_size(store, &rec.config_digest)
            + rec.layers.iter().map(|d| blob_size(store, d)).sum::<u64>();
        let created_ts = std::fs::metadata(store.image_dir(&key).join("image.json"))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        out.push(ImageSummary {
            reference: rec.reference,
            config_digest: rec.config_digest,
            size,
            created_ts,
        });
    }
    out.sort_by(|a, b| a.reference.cmp(&b.reference));
    Ok(out)
}

fn blob_size(store: &Store, digest: &str) -> u64 {
    store
        .blob_path(digest)
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

/// Remove an image record (by reference), then ref-count-sweep the blobs it
/// pulled in: any config/layer digest of the removed image that no *remaining*
/// image (or live container's `parent.json`) still references is deleted from
/// `blobs/`, and — when no remaining image shares the removed image's config
/// digest — its extracted `rootfs-cache/<hex>` entry is reclaimed too. A blob a
/// surviving image still uses is never touched (a shared base layer stays).
pub fn remove_image(store: &Store, reference: &str) -> Result<()> {
    let r = Reference::parse(reference)?;
    let key = r.store_key();
    // Read the record first so we know which blobs it introduced. If it's absent,
    // fall through to the remove_dir_all's NotFound → "no such image".
    let removed = ImageRecord::load(store, &key).ok();

    let dir = store.image_dir(&key);
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Other(format!("no such image: {reference}")));
        }
        Err(e) => return Err(Error::io(&dir)(e)),
    }

    // Best-effort GC (never fail the delete over a stray blob we couldn't reap).
    if let Some(removed) = removed {
        let still = referenced_digests(store);
        for d in gc_candidates(&removed, &still) {
            let _ = store.remove_blob(&d);
        }
        // The rootfs cache is keyed by config digest; reclaim it only if no
        // surviving image shares that config (else another image still needs it).
        if !still.contains(&removed.config_digest) {
            let _ = store.remove_rootfs_cache(&removed.config_digest);
        }
    }
    Ok(())
}

/// Every blob digest (config + layers) still referenced after a delete: by any
/// remaining stored image, plus any live container's committed base image
/// (`parent.json` under its bundle). Cheap enough to run inline on each delete.
fn referenced_digests(store: &Store) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    // Remaining stored images (scan images/*/image.json directly for their records).
    let images = store.root().join("images");
    if let Ok(entries) = std::fs::read_dir(&images) {
        for ent in entries.flatten() {
            let key = ent.file_name().to_string_lossy().into_owned();
            if let Ok(rec) = ImageRecord::load(store, &key) {
                set.insert(rec.config_digest);
                set.extend(rec.layers);
            }
        }
    }
    // Live containers pin their source image's blobs via the bundle's parent.json.
    for pj in bundle_parent_records() {
        set.insert(pj.config_digest);
        set.extend(pj.layers);
    }
    set
}

/// The `parent.json` (source [`ImageRecord`]) of every assembled container bundle,
/// so a container built from an image keeps that image's blobs alive even if the
/// image record itself is deleted. Best-effort: a missing/unreadable bundles dir
/// yields nothing.
fn bundle_parent_records() -> Vec<ImageRecord> {
    let dir = std::path::Path::new(crate::container::BUNDLES_DIR);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for ent in entries.flatten() {
            let pj = ent.path().join("parent.json");
            if let Ok(bytes) = std::fs::read(&pj) {
                if let Ok(rec) = serde_json::from_slice::<ImageRecord>(&bytes) {
                    out.push(rec);
                }
            }
        }
    }
    out
}

/// The blobs of `removed` that are now unreferenced (safe to delete): its config
/// digest + every layer digest NOT present in `still` (the surviving reference
/// set). Pure + order-stable for testing. A digest a surviving image still uses is
/// filtered out, so a shared base layer is never deleted.
fn gc_candidates(removed: &ImageRecord, still: &std::collections::HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for d in std::iter::once(&removed.config_digest).chain(removed.layers.iter()) {
        if !still.contains(d) && seen.insert(d.clone()) {
            out.push(d.clone());
        }
    }
    out
}

/// Tag an image: write a new reference pointing at the same content (config +
/// layers) as `src`. Overwrites any record already at the new reference.
pub fn tag_image(store: &Store, src: &str, new_ref: &str) -> Result<()> {
    let sr = Reference::parse(src)?;
    let nr = Reference::parse(new_ref)?;
    let mut rec = ImageRecord::load(store, &sr.store_key())?;
    rec.reference = nr.canonical();
    store.write_image_json(&nr.store_key(), &serde_json::to_vec_pretty(&rec)?)
}

// Lives here (next to `list_summaries`) rather than at file end; `pull` etc.
// follow it, so silence the items-after-test-module style lint.
#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod summary_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn write_blob(store: &Store, data: &[u8]) -> String {
        let digest = format!("sha256:{}", {
            let mut s = String::new();
            for b in Sha256::digest(data) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        });
        store
            .save_blob(&digest, |w| {
                w.write_all(data).map_err(|e| Error::Other(e.to_string()))
            })
            .unwrap();
        digest
    }

    #[test]
    fn list_summaries_scans_the_store() {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "dn7img-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let store = Store::with_root(&root).unwrap();
        let cfg = br#"{"rootfs":{"diff_ids":[]}}"#;
        let layer = b"layer-bytes";
        let rec = ImageRecord {
            reference: "registry-1.docker.io/library/alpine:latest".into(),
            config_digest: write_blob(&store, cfg),
            layers: vec![write_blob(&store, layer)],
        };
        store
            .write_image_json("alpine_key", &serde_json::to_vec(&rec).unwrap())
            .unwrap();

        let sums = list_summaries(&store).unwrap();
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].reference, rec.reference);
        assert_eq!(sums[0].size, (cfg.len() + layer.len()) as u64);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn blob_cap_shrinks_to_the_remaining_total_budget() {
        // Fresh pull: the per-blob ceiling applies (nothing spent yet).
        assert_eq!(blob_cap(0), store::MAX_BLOB_BYTES);
        // Mid-pull, plenty of budget left → still bounded by the per-blob ceiling.
        let spent = store::MAX_TOTAL_BYTES - store::MAX_BLOB_BYTES - 1;
        assert_eq!(blob_cap(spent), store::MAX_BLOB_BYTES);
        // Almost exhausted: the remaining budget (< per-blob ceiling) is the cap.
        let near = store::MAX_TOTAL_BYTES - 10;
        assert_eq!(blob_cap(near), 10);
        // Budget fully spent (or overshot via saturating math) → 0, so the next
        // blob's CapReader rejects the very first byte.
        assert_eq!(blob_cap(store::MAX_TOTAL_BYTES), 0);
        assert_eq!(blob_cap(u64::MAX), 0);
    }

    #[test]
    fn gc_candidates_selects_only_unreferenced_digests() {
        let removed = ImageRecord {
            reference: "x".into(),
            config_digest: "sha256:cfg-a".into(),
            layers: vec![
                "sha256:shared".into(),
                "sha256:only-a".into(),
                "sha256:shared".into(), // duplicate within the same image
            ],
        };
        // A surviving image still references the shared layer (and some other cfg).
        let still: std::collections::HashSet<String> =
            ["sha256:shared".to_string(), "sha256:cfg-b".to_string()]
                .into_iter()
                .collect();
        let cands = gc_candidates(&removed, &still);
        // config + only-a are reaped; the shared layer is kept; no duplicates.
        assert_eq!(cands, vec!["sha256:cfg-a", "sha256:only-a"]);
    }

    #[test]
    fn remove_image_sweeps_orphans_but_keeps_shared_layers() {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "dn7gc-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let store = Store::with_root(&root).unwrap();

        // A shared base layer used by BOTH images, plus per-image config + top layer.
        let shared = write_blob(&store, b"shared-base-layer");
        let cfg_a = write_blob(&store, br#"{"a":1}"#);
        let top_a = write_blob(&store, b"top-of-a");
        let cfg_b = write_blob(&store, br#"{"b":2}"#);
        let top_b = write_blob(&store, b"top-of-b");

        let write_rec = |reference: &str, cfg: &str, layers: Vec<String>| {
            let key = Reference::parse(reference).unwrap().store_key();
            let rec = ImageRecord {
                reference: Reference::parse(reference).unwrap().canonical(),
                config_digest: cfg.to_string(),
                layers,
            };
            store
                .write_image_json(&key, &serde_json::to_vec(&rec).unwrap())
                .unwrap();
        };
        write_rec("alpine:a", &cfg_a, vec![shared.clone(), top_a.clone()]);
        write_rec("alpine:b", &cfg_b, vec![shared.clone(), top_b.clone()]);

        // Seed a rootfs-cache entry for image A's config; it must be reclaimed.
        let cache_a = store.image_rootfs_base(&cfg_a).unwrap();
        std::fs::create_dir_all(&cache_a).unwrap();

        remove_image(&store, "alpine:a").unwrap();

        // A's private blobs + rootfs cache are gone; the shared layer + B's blobs stay.
        assert!(!store.has_blob(&cfg_a), "A's config should be swept");
        assert!(!store.has_blob(&top_a), "A's top layer should be swept");
        assert!(!cache_a.exists(), "A's rootfs cache should be reclaimed");
        assert!(store.has_blob(&shared), "shared base layer must be kept");
        assert!(store.has_blob(&cfg_b), "B's config must be kept");
        assert!(store.has_blob(&top_b), "B's top layer must be kept");

        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Pull `reference` into `store`: resolve a multi-arch index to this host's
/// platform, fetch + verify the config and every layer, and persist a record.
/// Re-pulling is cheap — blobs already present are skipped.
pub fn pull(reference: &str, store: &Store) -> Result<ImageRecord> {
    let r = Reference::parse(reference)?;
    let mut reg = Registry::new(&r.registry, &r.repository);
    let (arch, os) = host_platform();
    log(&format!("resolving {} ({os}/{arch})", r.canonical()));

    // Top-level manifest: may be a single-platform manifest or a multi-arch index.
    let (top_bytes, top_ct) = reg.get_manifest(&r.reference)?;
    let manifest_bytes = if manifest::media::is_index(&top_ct) || is_index_json(&top_bytes) {
        let index: Index = serde_json::from_slice(&top_bytes)?;
        let desc = index.select(arch, os).ok_or_else(|| {
            Error::Other(format!("image has no {os}/{arch} variant in its index"))
        })?;
        log(&format!(
            "index → {os}/{arch} manifest {}",
            short(&desc.digest)
        ));
        reg.get_manifest(&desc.digest)?.0
    } else {
        top_bytes
    };

    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

    // Blobs stream through the store's size-capped reader path so a hostile or
    // compromised registry can't fill the data volume with an unbounded layer:
    // each blob is capped at MAX_BLOB_BYTES, and a running total caps the whole
    // pull at MAX_TOTAL_BYTES. A cap breach (or digest mismatch) aborts the pull.
    let mut total: u64 = 0;

    // Config blob.
    let config_digest = manifest.config.digest.clone();
    log(&format!("config {}", short(&config_digest)));
    pull_blob(store, &mut reg, &config_digest, &mut total)?;

    // Layer blobs (ordered).
    let mut layers = Vec::with_capacity(manifest.layers.len());
    for (i, layer) in manifest.layers.iter().enumerate() {
        let d = layer.digest.clone();
        if store.has_blob(&d) {
            log(&format!(
                "layer {}/{} {} (cached)",
                i + 1,
                manifest.layers.len(),
                short(&d)
            ));
        } else {
            log(&format!(
                "layer {}/{} {} ({} bytes)",
                i + 1,
                manifest.layers.len(),
                short(&d),
                layer.size
            ));
            pull_blob(store, &mut reg, &d, &mut total)?;
        }
        layers.push(d);
    }

    let record = ImageRecord {
        reference: r.canonical(),
        config_digest,
        layers,
    };
    store.write_image_json(&r.store_key(), &serde_json::to_vec_pretty(&record)?)?;
    log("pull complete");
    Ok(record)
}

/// Stream one blob from the registry into the store, size-capped. `total` is the
/// running sum of bytes already pulled for this image; the per-blob cap is the
/// smaller of [`store::MAX_BLOB_BYTES`] and the remaining total budget, so a
/// single huge blob and a swarm of medium blobs are both bounded. The stored
/// size is charged against `total` afterwards (the CapReader guarantees it's
/// within the passed cap, so the total can't run away). A cap breach or digest
/// mismatch surfaces as an error and aborts the pull.
fn pull_blob(store: &Store, reg: &mut Registry, digest: &str, total: &mut u64) -> Result<()> {
    let mut rdr = reg.blob_reader(digest)?;
    store.save_blob_from_reader(digest, &mut rdr, blob_cap(*total))?;
    // A blob already present short-circuits the write, so re-derive its on-disk
    // size rather than assuming we streamed it.
    *total = total.saturating_add(blob_size(store, digest));
    if *total > store::MAX_TOTAL_BYTES {
        return Err(Error::Other("image exceeds total size cap".into()));
    }
    Ok(())
}

/// The per-blob byte cap given `total` bytes already pulled for this image: the
/// smaller of the per-blob ceiling and the remaining whole-image budget, so once
/// the budget is spent the next blob's cap is 0 and any further byte is rejected.
fn blob_cap(total: u64) -> u64 {
    store::MAX_BLOB_BYTES.min(store::MAX_TOTAL_BYTES.saturating_sub(total))
}

/// Ensure the image's merged rootfs is extracted into the shared store cache
/// (the read-only overlay lower), returning its path. Idempotent: extracted once
/// per image config digest, then reused by every container of that image.
pub fn ensure_image_rootfs(store: &Store, record: &ImageRecord) -> Result<std::path::PathBuf> {
    let base = store.image_rootfs_base(&record.config_digest)?;
    let rootfs = base.join("rootfs");
    let ready = base.join(".ready");
    if ready.is_file() {
        return Ok(rootfs);
    }
    // Partial/aborted prior extraction — start clean.
    if base.exists() {
        std::fs::remove_dir_all(&base).map_err(Error::io(&base))?;
    }
    std::fs::create_dir_all(&rootfs).map_err(Error::io(&rootfs))?;
    log(&format!(
        "extracting {} layer(s) → shared cache {}",
        record.layers.len(),
        rootfs.display()
    ));
    layer::apply_layers(store, &record.layers, &rootfs)?;
    std::fs::write(&ready, b"").map_err(Error::io(&ready))?;
    Ok(rootfs)
}

/// OCI platform for this host. The container target is always Linux; map the Rust
/// arch name to the OCI/Docker spelling.
pub fn host_platform() -> (&'static str, &'static str) {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => other,
    };
    (arch, "linux")
}

/// Best-effort "is this JSON an index?" fallback when the Content-Type is absent
/// or generic (some registries serve `application/json`).
fn is_index_json(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("manifests").map(|m| m.is_array()))
        .unwrap_or(false)
}

fn short(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .map(|h| h[..h.len().min(12)].to_string())
        .unwrap_or_else(|| digest.to_string())
}

/// Progress line (stderr, so stdout stays machine-readable).
fn log(msg: &str) {
    eprintln!("pull: {msg}");
}
