//! HTTP Basic Auth credential domain: the Apache `$apr1$` (salted MD5) hash
//! algorithm used to hash a new password into the stored AccessList model, plus
//! the verification the edge server's request-time Basic-Auth check uses. The
//! edge reads the hashes from the model directly — there are no htpasswd files.

/// Compute a salted password hash for HTTP Basic Auth in the Apache
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

/// Verify a plaintext password against a stored htpasswd hash. Supports the
/// apr1 (`$apr1$<salt>$<digest>`) format the panel writes (recomputed with the
/// embedded salt) and the legacy `{SHA}` (`{SHA}base64(sha1(pw))`) format. Any
/// other/empty format returns false. Used by the in-process edge server's
/// request-time Basic-Auth check (the runtime counterpart of nginx reading
/// `auth_basic_user_file`).
pub(crate) fn verify_htpasswd_hash(hash: &str, password: &str) -> bool {
    if let Some(rest) = hash.strip_prefix("$apr1$") {
        // rest == "<salt>$<digest>"; recompute apr1 with the same salt.
        let salt = rest.split('$').next().unwrap_or("");
        if salt.is_empty() {
            return false;
        }
        return constant_eq(apr1_with_salt(password, salt).as_bytes(), hash.as_bytes());
    }
    if let Some(b64) = hash.strip_prefix("{SHA}") {
        use base64::Engine;
        use sha1::{Digest, Sha1};
        let want = base64::engine::general_purpose::STANDARD.encode(Sha1::digest(password.as_bytes()));
        return constant_eq(want.as_bytes(), b64.as_bytes());
    }
    false
}

/// Length-aware constant-time byte comparison (avoids leaking the hash via
/// early-exit timing on a per-request auth check).
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}
