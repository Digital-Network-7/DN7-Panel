//! HTTP Basic Auth credential domain: the Apache `$apr1$` (salted MD5) hash
//! algorithm plus writing/hardening the per-access-list `htpasswd` files nginx
//! reads. Split out of the store so the store stays a pure persistence adapter
//! and the crypto/file-permission logic lives in one auditable place.
use super::*;

pub(crate) fn htpasswd_path(id: &str) -> std::path::PathBuf {
    std::path::Path::new(HOST_ACCESS_DIR).join(format!("{id}.htpasswd"))
}

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
