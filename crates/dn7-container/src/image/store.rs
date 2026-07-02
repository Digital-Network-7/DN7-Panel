//! Content-addressable on-disk store for image blobs (config + layers), plus a
//! small per-image metadata area. Blobs are keyed by their `sha256:…` digest and
//! verified on write, so a corrupted or truncated download never lands.
//!
//! Layout under the store root (default `/var/lib/dn7-container`):
//! ```text
//!   blobs/sha256/<hex>     # raw config + layer blobs (verified)
//!   images/<key>/image.json
//!   layers/<diffid>/       # extracted layer cache (P4 overlay; reserved)
//! ```

use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const DEFAULT_ROOT: &str = "/var/lib/dn7-container";

/// Hard caps for pulling/loading blobs into the store. A single blob (config or
/// layer) may not exceed [`MAX_BLOB_BYTES`], and the sum of all blobs pulled for
/// one image may not exceed [`MAX_TOTAL_BYTES`] — so a hostile/compromised
/// registry can't stream an unbounded layer (or a swarm of layers) to fill the
/// data volume. Enforced by [`Store::save_blob_from_reader`]'s `CapReader`
/// (per-blob) plus a running total the caller charges each stored blob against.
/// Mirrors the OCI-tar load path's caps in `archive.rs`.
pub const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024 * 1024; // ≤ 32 GiB per blob (layer)
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024; // ≤ 64 GiB across all blobs

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store> {
        Self::with_root(DEFAULT_ROOT)
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Result<Store> {
        let root = root.into();
        for sub in ["blobs/sha256", "images", "layers"] {
            let p = root.join(sub);
            fs::create_dir_all(&p).map_err(Error::io(&p))?;
        }
        Ok(Store { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Filesystem path for a `sha256:<hex>` blob.
    pub fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        let (algo, hex) = split_digest(digest)?;
        Ok(self.root.join("blobs").join(algo).join(hex))
    }

    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).map(|p| p.is_file()).unwrap_or(false)
    }

    /// Download a blob via `fill` into a temp file while hashing it, verify the
    /// digest, then atomically move it into place. A no-op if already present.
    pub fn save_blob(
        &self,
        digest: &str,
        fill: impl FnOnce(&mut dyn Write) -> Result<()>,
    ) -> Result<()> {
        if self.has_blob(digest) {
            return Ok(());
        }
        let (_, want_hex) = split_digest(digest)?;
        let final_path = self.blob_path(digest)?;
        let tmp = final_path.with_extension("tmp");

        let mut hw = HashingWriter {
            inner: BufWriter::new(File::create(&tmp).map_err(Error::io(&tmp))?),
            hasher: Sha256::new(),
        };
        let res = fill(&mut hw).and_then(|()| hw.flush().map_err(Error::io(&tmp)));
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        let got_hex = hex_encode(&hw.hasher.finalize());

        if got_hex != want_hex {
            let _ = fs::remove_file(&tmp);
            return Err(Error::Other(format!(
                "blob digest mismatch: wanted {want_hex}, got {got_hex}"
            )));
        }
        fs::rename(&tmp, &final_path).map_err(Error::io(&final_path))
    }

    /// Stream `reader` into a blob, hashing + verifying the digest incrementally
    /// so a layer never has to be buffered whole in RAM. `max_bytes` caps the
    /// copy (a lying/oversized entry is rejected before it can fill the disk).
    /// A no-op if the blob is already present. Mirrors [`Self::save_blob`]'s
    /// verify-then-atomic-rename, but sources bytes from a `Read` instead of a
    /// caller-supplied `fill` closure.
    pub fn save_blob_from_reader(
        &self,
        digest: &str,
        reader: &mut dyn Read,
        max_bytes: u64,
    ) -> Result<()> {
        self.save_blob(digest, |w| {
            let mut capped = CapReader {
                inner: reader,
                remaining: max_bytes,
            };
            std::io::copy(&mut capped, w)
                .map(|_| ())
                .map_err(|e| Error::Other(format!("stream blob {digest}: {e}")))
        })
    }

    pub fn read_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let p = self.blob_path(digest)?;
        fs::read(&p).map_err(Error::io(&p))
    }

    /// Delete a blob by digest. Absent is OK (idempotent GC). Only call once the
    /// caller has confirmed no remaining image/container references the digest.
    pub fn remove_blob(&self, digest: &str) -> Result<()> {
        let p = self.blob_path(digest)?;
        match fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&p)(e)),
        }
    }

    /// Delete the extracted rootfs cache for a config digest (the overlay lower),
    /// reclaimed when the last image with that config digest is removed. Absent is OK.
    pub fn remove_rootfs_cache(&self, config_digest: &str) -> Result<()> {
        let base = self.image_rootfs_base(config_digest)?;
        match fs::remove_dir_all(&base) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(&base)(e)),
        }
    }

    /// Open a blob for streaming (e.g. piping a layer through gunzip+tar).
    pub fn open_blob(&self, digest: &str) -> Result<File> {
        let p = self.blob_path(digest)?;
        File::open(&p).map_err(Error::io(&p))
    }

    /// Per-image metadata directory.
    pub fn image_dir(&self, key: &str) -> PathBuf {
        self.root.join("images").join(key)
    }

    /// The shared, extracted rootfs cache directory for an image config digest
    /// (the read-only overlay lower). Layout: `rootfs-cache/<hex>/{rootfs,.ready}`.
    pub fn image_rootfs_base(&self, config_digest: &str) -> Result<PathBuf> {
        let (_, hex) = split_digest(config_digest)?;
        Ok(self.root.join("rootfs-cache").join(hex))
    }

    pub fn write_image_json(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.image_dir(key);
        fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
        let p = dir.join("image.json");
        fs::write(&p, bytes).map_err(Error::io(&p))
    }

    pub fn read_image_json(&self, key: &str) -> Result<Vec<u8>> {
        let p = self.image_dir(key).join("image.json");
        let mut buf = Vec::new();
        File::open(&p)
            .map_err(Error::io(&p))?
            .read_to_end(&mut buf)
            .map_err(Error::io(&p))?;
        Ok(buf)
    }
}

/// Split `sha256:<hex>` into `("sha256", "<hex>")`, validating shape.
pub fn split_digest(digest: &str) -> Result<(&str, &str)> {
    match digest.split_once(':') {
        Some((algo, hex)) if algo == "sha256" && hex.len() == 64 && hex.bytes().all(is_hex) => {
            Ok((algo, hex))
        }
        _ => Err(Error::Other(format!("malformed digest: {digest}"))),
    }
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A `Read` adapter that fails once more than `remaining` bytes are pulled — so
/// a tar entry claiming a modest size but streaming forever can't blow the cap.
struct CapReader<'a> {
    inner: &'a mut dyn Read,
    remaining: u64,
}

impl Read for CapReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            // Budget spent — probe one byte to tell "exactly at cap" (EOF, fine)
            // apart from "over cap" (more data waiting → reject).
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "blob exceeds size cap",
                )),
            };
        }
        let want = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..want])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// A `Write` that hashes everything written through it.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_digest_validates() {
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(split_digest(d).unwrap().0, "sha256");
        assert!(split_digest("sha256:short").is_err());
        assert!(split_digest("md5:abc").is_err());
        assert!(split_digest("noselector").is_err());
    }

    #[test]
    fn hex_encode_is_lowercase_padded() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    // A private store rooted under the system temp dir (unique per test).
    fn temp_store() -> (Store, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "dn7-store-test-{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                ^ (std::process::id() as u128)
        ));
        (Store::with_root(root.clone()).unwrap(), root)
    }

    // sha256("hello"), lowercase hex.
    const HELLO_DIGEST: &str =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn save_blob_from_reader_streams_and_verifies() {
        let (store, root) = temp_store();
        let mut src = &b"hello"[..];
        store
            .save_blob_from_reader(HELLO_DIGEST, &mut src, 1024)
            .expect("correct-digest stream should store");
        assert!(store.has_blob(HELLO_DIGEST));
        assert_eq!(store.read_blob(HELLO_DIGEST).unwrap(), b"hello");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn save_blob_from_reader_accepts_exactly_at_cap() {
        let (store, root) = temp_store();
        // cap == payload length must succeed (boundary, not over-cap).
        let mut src = &b"hello"[..];
        store
            .save_blob_from_reader(HELLO_DIGEST, &mut src, 5)
            .expect("payload exactly at cap should store");
        assert!(store.has_blob(HELLO_DIGEST));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn save_blob_from_reader_rejects_over_cap() {
        let (store, root) = temp_store();
        let mut src = &b"hello"[..];
        let err = store
            .save_blob_from_reader(HELLO_DIGEST, &mut src, 4)
            .unwrap_err();
        assert!(err.to_string().contains("cap"), "got: {err}");
        // Nothing lands when the cap trips.
        assert!(!store.has_blob(HELLO_DIGEST));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn save_blob_from_reader_rejects_digest_mismatch() {
        let (store, root) = temp_store();
        // Claim the "hello" digest but stream different bytes.
        let mut src = &b"goodbye"[..];
        let err = store
            .save_blob_from_reader(HELLO_DIGEST, &mut src, 1024)
            .unwrap_err();
        assert!(err.to_string().contains("mismatch"), "got: {err}");
        assert!(!store.has_blob(HELLO_DIGEST));
        let _ = fs::remove_dir_all(&root);
    }
}
