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
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Serializes the log's append + in-place trim so two concurrent writers can't
/// interleave an append with another's `set_len(0)` + rewrite (which would
/// corrupt or drop lines). Held only inside the synchronous file work — never
/// across an `.await` — and poison-recovered.
static LOG_LOCK: Mutex<()> = Mutex::new(());

/// File name under the data dir.
const FILE: &str = "audit.log";
/// Trim once the log exceeds this size.
const MAX_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB
/// Tail to keep when trimming.
const KEEP_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

tokio::task_local! {
    /// Per-request context (client IP + sanitized request headers), set by the
    /// entry-gate middleware so any audit record made while handling the request
    /// can attach them without threading them through every handler signature.
    static REQ_CTX: RequestCtx;
}

/// Per-request audit context.
#[derive(Clone, Default)]
pub struct RequestCtx {
    pub ip: String,
    pub headers: String,
}

/// Run `fut` with the given request context bound (so `record*` can read the
/// client IP + sanitized headers from any depth without extra parameters).
pub async fn scope<F>(ctx: RequestCtx, fut: F) -> F::Output
where
    F: std::future::Future,
{
    REQ_CTX.scope(ctx, fut).await
}

fn ctx_ip() -> String {
    REQ_CTX.try_with(|c| c.ip.clone()).unwrap_or_default()
}

fn ctx_headers() -> String {
    REQ_CTX.try_with(|c| c.headers.clone()).unwrap_or_default()
}

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
    /// Source IP when known. May be empty.
    #[serde(default)]
    pub ip: String,
    /// Sanitized request headers (one "Name: value" per line). May be empty.
    #[serde(default)]
    pub headers: String,
    /// Sanitized response snapshot (JSON, secrets redacted, truncated). Empty
    /// for failures (the error goes in `detail`) and for non-op records.
    #[serde(default)]
    pub response: String,
}

fn path() -> PathBuf {
    crate::platform::paths::data_dir().join(FILE)
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

/// Inputs for one audit line. Bundled into a struct so `write_entry` stays
/// within the param-count limit; the public `record*` wrappers are the
/// ergonomic facade and fill the optional `ip` / `response`.
struct EntryArgs<'a> {
    actor: &'a str,
    action: &'a str,
    target: &'a str,
    ok: bool,
    detail: &'a str,
    ip: &'a str,
    response: &'a str,
}

/// Record an action. Client IP + request headers are taken from the per-request
/// context (set by the entry-gate middleware) when available.
pub fn record(actor: &str, action: &str, target: &str, ok: bool, detail: &str) {
    write_entry(EntryArgs {
        actor,
        action,
        target,
        ok,
        detail,
        ip: "",
        response: "",
    });
}

/// Record an action with an explicit source IP (login, where the IP is computed
/// from the connection / proxy headers). Falls back to the context IP if empty.
pub fn record_ip(actor: &str, action: &str, target: &str, ok: bool, detail: &str, ip: &str) {
    write_entry(EntryArgs {
        actor,
        action,
        target,
        ok,
        detail,
        ip,
        response: "",
    });
}

/// Record a channel op (docker/nginx/mysql) including a sanitized response.
pub fn record_op(actor: &str, action: &str, target: &str, ok: bool, detail: &str, response: &str) {
    write_entry(EntryArgs {
        actor,
        action,
        target,
        ok,
        detail,
        ip: "",
        response,
    });
}

fn write_entry(a: EntryArgs) {
    let ip = if a.ip.is_empty() {
        ctx_ip()
    } else {
        a.ip.to_string()
    };
    let entry = Entry {
        ts: now_secs(),
        actor: if a.actor.is_empty() {
            "?".into()
        } else {
            clip(a.actor, 64)
        },
        action: clip(a.action, 64),
        target: clip(a.target, 96),
        ok: a.ok,
        detail: clip(a.detail, 240),
        ip: clip(&ip, 64),
        headers: clip(&ctx_headers(), 2000),
        response: clip(a.response, 4000),
    };
    let line = match serde_json::to_string(&entry) {
        Ok(s) => s,
        Err(_) => return,
    };
    // The entry is built synchronously (so its timestamp/context are accurate),
    // but the file append + size-trim are blocking I/O. Offload them to the
    // blocking pool when we're on a runtime worker (the common case: a request
    // handler) so the worker isn't stalled; fall back to inline off-runtime
    // (startup / tests). Best-effort, matching the module's logging contract.
    match tokio::runtime::Handle::try_current() {
        Ok(h) => {
            h.spawn_blocking(move || append_and_trim(&line));
        }
        Err(_) => append_and_trim(&line),
    }
}

/// Append one already-serialized line to the log and trim it if oversized.
/// Serialized across writers by [`LOG_LOCK`]; runs on the blocking pool.
fn append_and_trim(line: &str) {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let p = path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    // Set 0600 AT creation so the file (and its first line) is never world-
    // readable, even briefly, before the set_permissions below re-asserts it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(&p) {
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

/// Erase the audit log. Serialized against the append path via [`LOG_LOCK`] so
/// a concurrent `spawn_blocking` append can't interleave with the truncate and
/// corrupt or resurrect partial content.
pub fn clear() -> std::io::Result<()> {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
            headers: String::new(),
            response: String::new(),
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
