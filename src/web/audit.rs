//! Append-only audit log of privileged panel actions (Owner-visible).
//!
//! Every security-relevant action — logins, account/user management, settings
//! changes, and Docker/Nginx/MySQL mutations — appends one JSON line to
//! `<data>/audit.log` (0600). The file is size-capped (trimmed in place,
//! keeping the most recent tail) so it can't grow without bound. Only the
//! super-admin (Owner) can read it via the web console.
//!
//! Records are best-effort: a logging failure never blocks the underlying
//! action. Read-only/poll operations are intentionally NOT recorded (the
//! caller decides) to keep the log meaningful.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// File name under the data dir.
const FILE: &str = "audit.log";
/// Trim once the log exceeds this size.
const MAX_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB
/// Tail to keep when trimming.
const KEEP_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unix epoch seconds.
    pub ts: i64,
    /// Acting account (panel username), or "?" when unknown.
    pub actor: String,
    /// Stable action key, e.g. "auth.login", "user.create", "mysql.install".
    pub action: String,
    /// Optional target (username / instance / domain / …).
    #[serde(default)]
    pub target: String,
    /// Whether the action succeeded.
    pub ok: bool,
    /// Short human detail (error text, or extra context). May be empty.
    #[serde(default)]
    pub detail: String,
    /// Source IP when known (logins). May be empty.
    #[serde(default)]
    pub ip: String,
}

fn path() -> PathBuf {
    crate::paths::data_dir().join(FILE)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Record an action (no source IP).
pub fn record(actor: &str, action: &str, target: &str, ok: bool, detail: &str) {
    record_ip(actor, action, target, ok, detail, "");
}

/// Record an action with a source IP (used by login).
pub fn record_ip(actor: &str, action: &str, target: &str, ok: bool, detail: &str, ip: &str) {
    let entry = Entry {
        ts: now_secs(),
        actor: if actor.is_empty() {
            "?".into()
        } else {
            clip(actor, 64)
        },
        action: clip(action, 64),
        target: clip(target, 96),
        ok,
        detail: clip(detail, 240),
        ip: clip(ip, 64),
    };
    let line = match serde_json::to_string(&entry) {
        Ok(s) => s,
        Err(_) => return,
    };
    let p = path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let _ = writeln!(f, "{line}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    let _ = trim_if_large(&p, MAX_BYTES, KEEP_BYTES);
}

/// Read up to `limit` most-recent entries, newest first.
pub fn read(limit: usize) -> Vec<Entry> {
    let limit = limit.clamp(1, 5000);
    let raw = match std::fs::read_to_string(path()) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Entry> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .collect();
    out.reverse(); // newest first
    out.truncate(limit);
    out
}

/// Erase the audit log.
pub fn clear() -> std::io::Result<()> {
    std::fs::write(path(), b"")
}

/// Trim the log in place to its last `keep_bytes` (line-aligned) when it grows
/// past `max_bytes`. Mirrors the daemon-log janitor in `logrotate`.
fn trim_if_large(path: &std::path::Path, max_bytes: u64, keep_bytes: u64) -> std::io::Result<bool> {
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return Ok(false),
    };
    if len <= max_bytes {
        return Ok(false);
    }
    let keep = keep_bytes.min(len);
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::Start(len - keep))?;
    let mut tail = Vec::with_capacity(keep as usize);
    f.read_to_end(&mut tail)?;
    if let Some(nl) = tail.iter().position(|&b| b == b'\n') {
        if nl + 1 < tail.len() {
            tail.drain(..=nl);
        }
    }
    f.set_len(0)?;
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&tail)?;
    f.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_roundtrips() {
        let e = Entry {
            ts: 100,
            actor: "owner".into(),
            action: "user.create".into(),
            target: "bob".into(),
            ok: true,
            detail: String::new(),
            ip: String::new(),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: Entry = serde_json::from_str(&s).unwrap();
        assert_eq!(back.actor, "owner");
        assert_eq!(back.action, "user.create");
        assert!(back.ok);
    }

    #[test]
    fn trim_keeps_tail() {
        let p = std::env::temp_dir().join(format!("dn7-audit-{}", std::process::id()));
        let mut body = String::new();
        for i in 0..2000 {
            body.push_str(&format!("{{\"line\":{i}}}\n"));
        }
        std::fs::write(&p, &body).unwrap();
        let before = std::fs::metadata(&p).unwrap().len();
        assert!(trim_if_large(&p, 1024, 256).unwrap());
        let after = std::fs::metadata(&p).unwrap().len();
        assert!(after < before);
        let _ = std::fs::remove_file(&p);
    }
}
