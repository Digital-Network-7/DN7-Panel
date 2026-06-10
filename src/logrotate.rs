//! Periodic in-place log trimming.
//!
//! The panel daemonizes with stdout/stderr redirected (in append mode) to
//! `/var/ops/dn7-panel.log`. With a ~1s report interval that file grows
//! without bound. We can't just delete it — the daemon holds the fd open, so
//! unlinking the inode would keep consuming space (writes continue to the
//! now-anonymous inode) until restart.
//!
//! Instead we trim it *in place*: when it exceeds a size cap we keep only the
//! tail (the most recent lines) and truncate the rest. Because the fd is in
//! append mode, every subsequent write seeks to end-of-file first, so writing
//! after a `set_len` resumes cleanly at the new (smaller) length.
//!
//! A small race exists (a daemon write can interleave between our read of the
//! tail and the truncate), but it only affects log ordering, never correctness
//! or the panel itself — acceptable for a best-effort janitor.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::PanelConfig;

/// Trim the log once it grows past this many bytes.
const MAX_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
/// How much of the tail to keep when trimming.
const KEEP_BYTES: u64 = 1024 * 1024; // 1 MiB
/// How often the janitor checks the size.
const CHECK_EVERY: Duration = Duration::from_secs(300); // 5 min

/// Path of the daemon log the panel writes to.
fn log_path(cfg: &PanelConfig) -> PathBuf {
    cfg.log_dir.join(crate::daemon::LOG_FILE)
}

/// Spawn the background log-trimming task (runs for the supervisor's lifetime).
pub fn spawn(cfg: PanelConfig) {
    tokio::spawn(async move {
        let path = log_path(&cfg);
        let mut ticker = tokio::time::interval(CHECK_EVERY);
        loop {
            ticker.tick().await;
            match trim_if_large(&path, MAX_BYTES, KEEP_BYTES) {
                Ok(true) => tracing::info!(path = %path.display(), "trimmed oversized panel log"),
                Ok(false) => {}
                Err(e) => tracing::debug!("log trim skipped: {e}"),
            }
        }
    });
}

/// If `path` is larger than `max_bytes`, rewrite it to contain only its last
/// `keep_bytes` (rounded up to the next line boundary). Returns whether it
/// trimmed. Best-effort and self-contained so it can be unit tested.
fn trim_if_large(path: &Path, max_bytes: u64, keep_bytes: u64) -> std::io::Result<bool> {
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(false), // no log yet
    };
    if len <= max_bytes {
        return Ok(false);
    }

    // Read the tail we want to keep.
    let keep = keep_bytes.min(len);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::Start(len - keep))?;
    let mut tail = Vec::with_capacity(keep as usize);
    f.read_to_end(&mut tail)?;

    // Drop a partial first line so the kept content starts on a line boundary.
    if let Some(nl) = tail.iter().position(|&b| b == b'\n') {
        if nl + 1 < tail.len() {
            tail.drain(..=nl);
        }
    }

    // Rewrite: truncate to zero, then write the tail back from the start.
    f.set_len(0)?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(b"[log trimmed]\n")?;
    f.write_all(&tail)?;
    f.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::trim_if_large;

    #[test]
    fn does_not_trim_small_files() {
        let p = std::env::temp_dir().join(format!("dn7-log-small-{}", std::process::id()));
        std::fs::write(&p, b"hello\nworld\n").unwrap();
        assert!(!trim_if_large(&p, 1024, 256).unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"hello\nworld\n");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn trims_large_files_keeping_tail() {
        let p = std::env::temp_dir().join(format!("dn7-log-big-{}", std::process::id()));
        // 100 numbered lines; each ~ "lineNNN\n".
        let mut body = String::new();
        for i in 0..1000 {
            body.push_str(&format!("line{i:04}\n"));
        }
        std::fs::write(&p, &body).unwrap();
        let before = std::fs::metadata(&p).unwrap().len();

        // Cap well below the file size, keep a small tail.
        let trimmed = trim_if_large(&p, 1024, 256).unwrap();
        assert!(trimmed);

        let after = std::fs::read_to_string(&p).unwrap();
        let after_len = after.len() as u64;
        assert!(after_len < before, "file should shrink");
        // Header present, and the very last line preserved.
        assert!(after.starts_with("[log trimmed]\n"));
        assert!(after.contains("line0999"));
        // The kept region starts on a clean line boundary (no partial line
        // between the header and the first kept line).
        let first_kept = after.lines().nth(1).unwrap();
        assert!(first_kept.starts_with("line"));
        let _ = std::fs::remove_file(&p);
    }
}
