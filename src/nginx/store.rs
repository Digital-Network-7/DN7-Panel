//! Access-list + global website settings store (split from nginx.rs).
use super::*;

// Access-list store + global website settings.
// ---------------------------------------------------------------------------

pub(crate) fn access_file() -> std::path::PathBuf {
    base_dir().join("access.json")
}
pub(crate) fn access_dir() -> std::path::PathBuf {
    base_dir().join("access")
}
pub(crate) fn htpasswd_path(id: &str) -> std::path::PathBuf {
    std::path::Path::new(HOST_ACCESS_DIR).join(format!("{id}.htpasswd"))
}
pub(crate) fn websettings_file() -> std::path::PathBuf {
    base_dir().join("websettings.json")
}

pub(crate) fn load_access() -> Vec<AccessList> {
    std::fs::read_to_string(access_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<AccessList>>(&s).ok())
        .unwrap_or_default()
}
pub(crate) fn save_access(lists: &[AccessList]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(access_file(), serde_json::to_string_pretty(lists)?)?;
    Ok(())
}
pub(crate) fn load_webglobal() -> WebGlobal {
    std::fs::read_to_string(websettings_file())
        .ok()
        .and_then(|s| serde_json::from_str::<WebGlobal>(&s).ok())
        .unwrap_or_default()
}
pub(crate) fn save_webglobal(g: &WebGlobal) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(websettings_file(), serde_json::to_string_pretty(g)?)?;
    Ok(())
}

pub(crate) fn webtuning_file() -> std::path::PathBuf {
    base_dir().join("webtuning.json")
}
/// Load tuning, or `None` when never configured (so we don't override the
/// distro's http defaults on managed sites until the operator opts in).
pub(crate) fn load_tuning_opt() -> Option<HttpTuning> {
    let raw = std::fs::read_to_string(webtuning_file()).ok()?;
    serde_json::from_str::<HttpTuning>(&raw).ok()
}
pub(crate) fn save_tuning(t: &HttpTuning) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(webtuning_file(), serde_json::to_string_pretty(t)?)?;
    Ok(())
}

/// Validate a size value like "1m", "512k", "0" (bytes default). Bounded.
pub(crate) fn valid_size_value(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.len() <= 12 && {
        let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
        !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit())
            && matches!(unit, "" | "k" | "K" | "m" | "M" | "g" | "G")
    }
}

/// The server-context tuning directives, emitted into each managed server
/// block. Returns "" until the operator configures tuning.
pub(crate) fn render_tuning_block() -> String {
    let t = match load_tuning_opt() {
        Some(t) => t,
        None => return String::new(),
    };
    let mut s = String::new();
    s.push_str(&format!(
        "    client_max_body_size {};\n",
        t.client_max_body_size
    ));
    s.push_str(&format!(
        "    client_header_buffer_size {};\n",
        t.client_header_buffer_size
    ));
    s.push_str(&format!("    keepalive_timeout {};\n", t.keepalive_timeout));
    if t.gzip {
        s.push_str("    gzip on;\n");
        s.push_str(&format!("    gzip_min_length {};\n", t.gzip_min_length));
        s.push_str(&format!("    gzip_comp_level {};\n", t.gzip_comp_level));
        s.push_str("    gzip_vary on;\n");
        s.push_str("    gzip_proxied any;\n");
        s.push_str("    gzip_types text/plain text/css application/json application/javascript application/x-javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;\n");
    } else {
        s.push_str("    gzip off;\n");
    }
    s
}

/// Whether nginx.conf already sets a directive at http level (uncommented), so
/// we don't emit a duplicate (which fails `nginx -t`).
pub(crate) fn nginx_conf_has_active(directive: &str) -> bool {
    std::fs::read_to_string("/etc/nginx/nginx.conf")
        .map(|c| {
            c.lines().any(|l| {
                let t = l.trim();
                !t.starts_with('#') && t.split_whitespace().next() == Some(directive)
            })
        })
        .unwrap_or(false)
}

pub(crate) fn tuning_conf_path() -> std::path::PathBuf {
    std::path::Path::new(HOST_CONFD).join("00-dn7-tuning.conf")
}

/// Write (or remove) the http-context tuning include — currently just
/// `server_names_hash_bucket_size` (http-only). Skipped when nginx.conf already
/// sets it (avoids a duplicate-directive failure) or tuning isn't configured.
pub(crate) fn write_tuning_conf() {
    let path = tuning_conf_path();
    let t = match load_tuning_opt() {
        Some(t) => t,
        None => {
            let _ = std::fs::remove_file(&path);
            return;
        }
    };
    if nginx_conf_has_active("server_names_hash_bucket_size") {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let body = format!(
        "server_names_hash_bucket_size {};\n",
        t.server_names_hash_bucket_size
    );
    let _ = std::fs::create_dir_all(HOST_CONFD);
    let _ = std::fs::write(&path, body);
}

/// An access-list id (random, filesystem-safe).
pub(crate) fn new_access_id() -> String {
    format!("al{:08x}", rand::random::<u32>())
}

// Access-list validators live in the `validate` submodule.

/// Compute a salted password hash for nginx HTTP Basic Auth in the Apache
/// `$apr1$` (salted MD5) format. nginx implements this scheme internally
/// (`ngx_crypt_apr1`) and never delegates to the host's libc `crypt()`, so it
/// verifies reliably on every distro. (bcrypt `$2b$` depends on libxcrypt and
/// makes nginx return 500 wherever the host `crypt()` can't parse it — for both
/// correct and incorrect passwords.)
pub(crate) fn htpasswd_hash(password: &str) -> String {
    apr1_with_salt(password, &apr1_salt())
}

/// The 64-char alphabet used by crypt-style base64 (`to64`).
pub(crate) const APR1_ITOA64: &[u8] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A fresh random 8-character apr1 salt.
pub(crate) fn apr1_salt() -> String {
    (0..8)
        .map(|_| APR1_ITOA64[(rand::random::<u8>() & 0x3f) as usize] as char)
        .collect()
}

/// Encode the low `n` six-bit groups of `v` (LSB first) with the crypt base64
/// alphabet — the apr1 output encoding.
pub(crate) fn apr1_to64(mut v: u32, n: usize) -> String {
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        s.push(APR1_ITOA64[(v & 0x3f) as usize] as char);
        v >>= 6;
    }
    s
}

/// Apache apr1 (salted MD5, 1000 rounds) password hash for the given salt.
/// Mirrors `ngx_crypt_apr1` / Apache's `apr_md5_encode`.
pub(crate) fn apr1_with_salt(password: &str, salt: &str) -> String {
    use md5::{Digest, Md5};
    let pw = password.as_bytes();
    let salt = salt.as_bytes();

    // Primary digest: password + magic + salt.
    let mut ctx = Md5::new();
    ctx.update(pw);
    ctx.update(b"$apr1$");
    ctx.update(salt);

    // Alternate digest of password+salt+password, folded into the primary one
    // `password.len()` bytes at a time.
    let mut alt = Md5::new();
    alt.update(pw);
    alt.update(salt);
    alt.update(pw);
    let alt = alt.finalize();
    let mut pl = pw.len() as i64;
    while pl > 0 {
        let take = if pl > 16 { 16 } else { pl as usize };
        ctx.update(&alt[..take]);
        pl -= 16;
    }

    // Mix in 0-bytes / first password byte based on the bits of the length.
    let mut i = pw.len();
    while i != 0 {
        if i & 1 != 0 {
            ctx.update([0u8]);
        } else {
            ctx.update(&pw[..1]);
        }
        i >>= 1;
    }
    let mut digest = ctx.finalize();

    // 1000 stretching rounds.
    for i in 0..1000 {
        let mut c = Md5::new();
        if i & 1 != 0 {
            c.update(pw);
        } else {
            c.update(&digest[..]);
        }
        if i % 3 != 0 {
            c.update(salt);
        }
        if i % 7 != 0 {
            c.update(pw);
        }
        if i & 1 != 0 {
            c.update(&digest[..]);
        } else {
            c.update(pw);
        }
        digest = c.finalize();
    }

    // Final base64 encoding with apr1's byte interleaving.
    let f = &digest;
    let g =
        |a: usize, b: usize, c: usize| ((f[a] as u32) << 16) | ((f[b] as u32) << 8) | f[c] as u32;
    let mut out = String::from("$apr1$");
    out.push_str(std::str::from_utf8(salt).unwrap_or(""));
    out.push('$');
    out.push_str(&apr1_to64(g(0, 6, 12), 4));
    out.push_str(&apr1_to64(g(1, 7, 13), 4));
    out.push_str(&apr1_to64(g(2, 8, 14), 4));
    out.push_str(&apr1_to64(g(3, 9, 15), 4));
    out.push_str(&apr1_to64(g(4, 10, 5), 4));
    out.push_str(&apr1_to64(f[11] as u32, 2));
    out
}

/// Write (or remove) an access list's htpasswd file from its stored hashes.
pub(crate) fn write_htpasswd(list: &AccessList) -> Result<()> {
    let path = htpasswd_path(&list.id);
    // Remove any stale copy left in the panel's private tree by older builds
    // (that location 500s — the nginx worker can't read it).
    let _ = std::fs::remove_file(access_dir().join(format!("{}.htpasswd", list.id)));
    if list.users.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    std::fs::create_dir_all(HOST_ACCESS_DIR)?;
    // The directory must be traversable by the nginx worker user (it opens the
    // file at request time), so force 0755 even under a restrictive umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(HOST_ACCESS_DIR, std::fs::Permissions::from_mode(0o755));
    }
    let mut body = String::new();
    for u in &list.users {
        body.push_str(&format!("{}:{}\n", u.username, u.hash));
    }
    std::fs::write(&path, body)?;
    harden_htpasswd_perms(&path);
    Ok(())
}

/// Tighten an htpasswd file to the minimum the nginx worker still needs:
/// owned by nginx's run-user at 0640 when that user can be determined, else
/// fall back to 0644 (world-readable) so auth never silently breaks. The hashes
/// are salted apr1, so even the 0644 fallback isn't trivially crackable.
pub(crate) fn harden_htpasswd_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some((uid, gid)) = nginx_run_uid_gid() {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                // SAFETY: `c` is a valid NUL-terminated path; chown just sets
                // ownership and returns an error code we check.
                let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
                if rc == 0 {
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
                    return;
                }
            }
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The nginx worker's run-user from `nginx.conf` (`user <name>;`), resolved to
/// (uid, gid). Workers read auth_basic_user_file, so the htpasswd file must be
/// readable by this account. Returns None when it can't be determined.
#[cfg(unix)]
pub(crate) fn nginx_run_uid_gid() -> Option<(u32, u32)> {
    let conf = std::fs::read_to_string("/etc/nginx/nginx.conf").ok()?;
    let mut user = None;
    for line in conf.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("user ") {
            let name = rest
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .next()?;
            if !name.is_empty() && name != "root" {
                user = Some(name.to_string());
            }
            break;
        }
    }
    let user = user?;
    let c = std::ffi::CString::new(user).ok()?;
    // SAFETY: getpwnam reads the passwd db for a valid C string and returns a
    // pointer we immediately copy out of (no retention).
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(((*pw).pw_uid, (*pw).pw_gid))
    }
}
