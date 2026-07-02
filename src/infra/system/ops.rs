//! System (OS) account provisioning — PURE RUST, no `useradd`/`userdel`/
//! `usermod`/`chpasswd`/`gpasswd` shell-outs. Edits `/etc/passwd`, `/etc/shadow`,
//! `/etc/group` (+ `/etc/gshadow`) directly under an exclusive `/etc/.pwd.lock`
//! flock, with atomic temp-file-then-rename writes that preserve each file's
//! mode/owner. Reads use the libc NSS FFI (`getpwnam_r`/`getgrnam`) — in-process,
//! not a shell-out. Passwords are hashed with pure-Rust SHA-512 crypt.
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{anyhow, Result};

use crate::core::identity::{
    foreign_account_refused_msg, system_account_adoptable, AccountProvenance, SystemUserError,
    DN7_OWNED_MARKER,
};

/// Build the transitional `anyhow` error for a typed [`SystemUserError`].
fn users_err(e: SystemUserError) -> anyhow::Error {
    anyhow!("ERR_CODE:{}", e.code())
}

const PASSWD: &str = "/etc/passwd";
const SHADOW: &str = "/etc/shadow";
const GROUP: &str = "/etc/group";
const GSHADOW: &str = "/etc/gshadow";
const LOCK: &str = "/etc/.pwd.lock";

// ---------------------------------------------------------------------------
// Reads (libc NSS FFI — in-process, no shell-out).
// ---------------------------------------------------------------------------

/// Look up a system account's uid + home dir (None if it doesn't exist). Uses
/// the reentrant `getpwnam_r` (no shared static buffer → thread-safe).
pub fn getpwnam(name: &str) -> Option<(u32, String)> {
    let cname = CString::new(name).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 1024];
    loop {
        // SAFETY: `getpwnam_r` fills `pwd` + `buf` and sets `result` to `&pwd` on
        // success (or null when absent). Reentrant; we copy fields out while alive.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 65536 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let uid = pwd.pw_uid;
        let dir = if pwd.pw_dir.is_null() {
            format!("/home/{name}")
        } else {
            // SAFETY: `pw_dir` points into `buf`, still alive here.
            unsafe { CStr::from_ptr(pwd.pw_dir) }
                .to_string_lossy()
                .to_string()
        };
        return Some((uid, dir));
    }
}

fn group_exists(group: &str) -> bool {
    CString::new(group)
        .ok()
        // SAFETY: getgrnam reads a valid NUL-terminated C string we own; the
        // returned pointer is only null-checked, never dereferenced/retained.
        .map(|g| unsafe { !libc::getgrnam(g.as_ptr()).is_null() })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// /etc editing primitives (locked + atomic).
// ---------------------------------------------------------------------------

/// Hold an exclusive flock on `/etc/.pwd.lock` for the duration of an edit (the
/// same lock `useradd`/`passwd` use). Released when the returned file drops.
fn lock_etc() -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(LOCK)
        .map_err(|e| anyhow!("锁定 /etc 失败：{e}"))?;
    // SAFETY: flock on a valid owned fd; blocks until acquired.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(anyhow!("flock /etc 失败"));
    }
    Ok(f)
}

/// Atomically replace `path` with `content`, preserving the original mode + owner
/// (critical for /etc/shadow's 0640 root:shadow).
fn write_atomic(path: &str, content: &str) -> Result<()> {
    let meta = std::fs::metadata(path).ok();
    let tmp = format!("{path}.dn7.tmp");
    std::fs::write(&tmp, content).map_err(|e| anyhow!("写 {path} 失败：{e}"))?;
    if let Some(m) = &meta {
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m.mode()));
        if let Ok(c) = CString::new(tmp.as_str()) {
            // SAFETY: chown a path we own; ignore failure (best-effort owner copy).
            unsafe { libc::chown(c.as_ptr(), m.uid(), m.gid()) };
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        // Don't leave the .dn7.tmp scratch file behind (it would carry a copy of
        // /etc/shadow content) when the atomic replace fails.
        let _ = std::fs::remove_file(&tmp);
        anyhow!("替换 {path} 失败：{e}")
    })
}

/// Read a colon-table file's lines (empty string when absent).
fn read_lines(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

/// The first unused id in `[lo, hi)` looking at column 3 (index 2) of `path`, or
/// `None` if the range is exhausted (fail closed — never reuse a colliding id).
fn next_free_id(path: &str, lo: u32, hi: u32) -> Option<u32> {
    let used: HashSet<u32> = read_lines(path)
        .iter()
        .filter_map(|l| l.split(':').nth(2))
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();
    (lo..hi).find(|id| !used.contains(id))
}

fn days_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

fn chown_path(path: &Path, uid: u32, gid: u32) {
    if let Some(c) = path.to_str().and_then(|s| CString::new(s).ok()) {
        // SAFETY: chown a path; best-effort.
        unsafe { libc::chown(c.as_ptr(), uid, gid) };
    }
}

/// Recursively copy `src` into `dst`, chowning every created entry to uid:gid.
fn copy_tree(src: &Path, dst: &Path, uid: u32, gid: u32) {
    let entries = match std::fs::read_dir(src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let from = ent.path();
        let to = dst.join(ent.file_name());
        match ent.file_type() {
            Ok(t) if t.is_dir() => {
                let _ = std::fs::create_dir_all(&to);
                chown_path(&to, uid, gid);
                copy_tree(&from, &to, uid, gid);
            }
            Ok(_) => {
                if std::fs::copy(&from, &to).is_ok() {
                    chown_path(&to, uid, gid);
                }
            }
            Err(_) => {}
        }
    }
}

/// Append `line` (a complete row) to a colon-table file, ensuring a trailing NL.
fn append_line(path: &str, line: &str) -> Result<()> {
    let mut lines = read_lines(path);
    lines.push(line.to_string());
    write_atomic(path, &(lines.join("\n") + "\n"))
}

/// Remove every row of `path` whose first field equals `name`.
fn remove_named(path: &str, name: &str) -> Result<()> {
    let kept: Vec<String> = read_lines(path)
        .into_iter()
        .filter(|l| l.split(':').next() != Some(name))
        .collect();
    write_atomic(path, &(kept.join("\n") + "\n"))
}

// ---------------------------------------------------------------------------
// Account operations (pure Rust).
// ---------------------------------------------------------------------------

/// Create a login account: a private group, the passwd/shadow/group rows, and a
/// home dir seeded from /etc/skel. Locked password (`!`) until `set_passwd`.
fn add_user_sync(name: &str, gecos: &str, shell: &str) -> Result<()> {
    let _lock = lock_etc()?;
    if getpwnam(name).is_some() {
        return Ok(()); // adopt an existing account, idempotent
    }
    let uid = next_free_id(PASSWD, 1000, 60_000)
        .ok_or_else(|| anyhow!("uid 空间已耗尽（1000..60000），无法创建账户"))?;
    let gid = next_free_id(GROUP, 1000, 60_000)
        .ok_or_else(|| anyhow!("gid 空间已耗尽（1000..60000），无法创建账户"))?;
    let home = format!("/home/{name}");

    append_line(
        PASSWD,
        &format!("{name}:x:{uid}:{gid}:{gecos}:{home}:{shell}"),
    )?;
    append_line(
        SHADOW,
        &format!("{name}:!:{}:0:99999:7:::", days_since_epoch()),
    )?;
    append_line(GROUP, &format!("{name}:x:{gid}:"))?;
    if Path::new(GSHADOW).exists() {
        append_line(GSHADOW, &format!("{name}:!::"))?;
    }

    let home_p = Path::new(&home);
    std::fs::create_dir_all(home_p).map_err(|e| anyhow!("创建家目录失败：{e}"))?;
    if Path::new("/etc/skel").is_dir() {
        copy_tree(Path::new("/etc/skel"), home_p, uid, gid);
    }
    chown_path(home_p, uid, gid);
    let _ = std::fs::set_permissions(home_p, std::fs::Permissions::from_mode(0o755));
    // Drop the DN7 ownership marker so a later create can tell this account is a
    // leftover DN7 account (safe to re-adopt) rather than a foreign one.
    write_owned_marker(home_p, uid, gid);
    Ok(())
}

/// Write the DN7 ownership marker into `home`, chowned to the account. Best
/// effort: adoption still works via the `users.json` record if this fails.
fn write_owned_marker(home: &Path, uid: u32, gid: u32) {
    let marker = home.join(DN7_OWNED_MARKER);
    if std::fs::write(&marker, b"dn7-panel\n").is_ok() {
        chown_path(&marker, uid, gid);
        let _ = std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600));
    }
}

/// Whether the DN7 ownership marker file is present in `home`.
fn home_has_owned_marker(home: &str) -> bool {
    Path::new(home).join(DN7_OWNED_MARKER).exists()
}

/// Provenance of a *pre-existing* system account named `name` sitting at `home`:
/// combine "already recorded in users.json" with "carries the DN7 marker file".
/// Feeds [`system_account_adoptable`] to decide whether a create may adopt it.
fn provenance_of(name: &str, home: &str) -> AccountProvenance {
    let recorded_in_store = crate::infra::store::users::load()
        .iter()
        .any(|u| u.username == name);
    AccountProvenance {
        recorded_in_store,
        has_owned_marker: home_has_owned_marker(home),
    }
}

/// Remove the account: its rows from passwd/shadow/(private)group/gshadow, drop
/// it from any supplementary groups, and delete its home dir.
fn del_user_sync(name: &str) -> Result<()> {
    let _lock = lock_etc()?;
    let home = getpwnam(name).map(|(_, h)| h);
    remove_named(PASSWD, name)?;
    remove_named(SHADOW, name)?;
    remove_named(GROUP, name)?; // the user-private group
    if Path::new(GSHADOW).exists() {
        remove_named(GSHADOW, name)?;
    }
    // Drop from supplementary groups (member lists).
    strip_from_all_groups(name)?;
    if let Some(h) = home {
        if h.starts_with("/home/") {
            let _ = std::fs::remove_dir_all(&h);
        }
    }
    Ok(())
}

/// Set the account's password field in /etc/shadow to a SHA-512 crypt hash.
fn set_passwd_sync(name: &str, password: &str) -> Result<()> {
    use sha_crypt::{sha512_simple, Sha512Params};
    let _lock = lock_etc()?;
    let params = Sha512Params::new(5_000).map_err(|_| users_err(SystemUserError::SetPwFailed))?;
    let hash =
        sha512_simple(password, &params).map_err(|_| users_err(SystemUserError::SetPwFailed))?;
    let day = days_since_epoch().to_string();
    let mut found = false;
    let lines: Vec<String> = read_lines(SHADOW)
        .into_iter()
        .map(|l| {
            let mut f: Vec<&str> = l.split(':').collect();
            if f.first() == Some(&name) && f.len() >= 3 {
                f[1] = &hash;
                f[2] = &day;
                found = true;
                f.join(":")
            } else {
                l
            }
        })
        .collect();
    if !found {
        return Err(users_err(SystemUserError::SetPwFailed));
    }
    write_atomic(SHADOW, &(lines.join("\n") + "\n"))
}

/// Add `name` to group `group`'s member list (the 4th /etc/group field).
fn add_to_group_sync(name: &str, group: &str) -> Result<()> {
    let _lock = lock_etc()?;
    let mut found = false;
    let lines: Vec<String> = read_lines(GROUP)
        .into_iter()
        .map(|l| {
            let mut f: Vec<String> = l.split(':').map(String::from).collect();
            if f.first().map(String::as_str) == Some(group) && f.len() >= 4 {
                found = true;
                let mut members: Vec<&str> = f[3].split(',').filter(|m| !m.is_empty()).collect();
                if !members.contains(&name) {
                    members.push(name);
                }
                f[3] = members.join(",");
                f.join(":")
            } else {
                l
            }
        })
        .collect();
    if !found {
        return Err(users_err(SystemUserError::NoSudoGroup));
    }
    write_atomic(GROUP, &(lines.join("\n") + "\n"))
}

/// Remove `name` from group `group`'s member list (no error if absent).
fn remove_from_group_sync(name: &str, group: &str) -> Result<()> {
    let _lock = lock_etc()?;
    let lines: Vec<String> = read_lines(GROUP)
        .into_iter()
        .map(|l| {
            let mut f: Vec<String> = l.split(':').map(String::from).collect();
            if f.first().map(String::as_str) == Some(group) && f.len() >= 4 {
                let members: Vec<&str> = f[3]
                    .split(',')
                    .filter(|m| !m.is_empty() && *m != name)
                    .collect();
                f[3] = members.join(",");
                f.join(":")
            } else {
                l
            }
        })
        .collect();
    write_atomic(GROUP, &(lines.join("\n") + "\n"))
}

/// Remove `name` from EVERY group's member list (used on account deletion).
fn strip_from_all_groups(name: &str) -> Result<()> {
    let lines: Vec<String> = read_lines(GROUP)
        .into_iter()
        .map(|l| {
            let mut f: Vec<String> = l.split(':').map(String::from).collect();
            if f.len() >= 4 {
                let members: Vec<&str> = f[3]
                    .split(',')
                    .filter(|m| !m.is_empty() && *m != name)
                    .collect();
                f[3] = members.join(",");
                f.join(":")
            } else {
                l
            }
        })
        .collect();
    write_atomic(GROUP, &(lines.join("\n") + "\n"))
}

/// Set the account's GECOS (full-name) field in /etc/passwd.
fn set_gecos_sync(name: &str, gecos: &str) -> Result<()> {
    let _lock = lock_etc()?;
    let lines: Vec<String> = read_lines(PASSWD)
        .into_iter()
        .map(|l| {
            let mut f: Vec<&str> = l.split(':').collect();
            if f.first() == Some(&name) && f.len() >= 5 {
                f[4] = gecos;
                f.join(":")
            } else {
                l
            }
        })
        .collect();
    write_atomic(PASSWD, &(lines.join("\n") + "\n"))
}

/// The admin group present on this distro (Debian `sudo` / RHEL `wheel`).
fn admin_group() -> Option<&'static str> {
    ["sudo", "wheel"].into_iter().find(|g| group_exists(g))
}

// ---------------------------------------------------------------------------
// Public async API (unchanged signatures; the work runs on the blocking pool).
// ---------------------------------------------------------------------------

/// Create (or adopt) the backing system account, grant the admin group for
/// admins, and sync the OS password to the panel password (SSH/console login).
pub async fn provision(username: &str, full_name: &str, admin: bool, password: &str) -> Result<()> {
    let gecos = if !full_name.is_empty() && gecos_ok(full_name) {
        full_name.to_string()
    } else {
        String::new()
    };
    let (u, pw) = (username.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || -> Result<()> {
        match getpwnam(&u) {
            // Fresh account — create it (drops the DN7 ownership marker).
            None => add_user_sync(&u, &gecos, "/bin/bash")?,
            // The name already resolves in /etc/passwd. Adopt ONLY a leftover
            // DN7 account; refuse a foreign service account (`postgres`, …) so we
            // never reset its password, add it to sudo, or later delete it.
            Some((_, home)) => {
                if !system_account_adoptable(provenance_of(&u, &home)) {
                    return Err(anyhow!("{}", foreign_account_refused_msg(&u)));
                }
                if !gecos.is_empty() {
                    let _ = set_gecos_sync(&u, &gecos);
                }
            }
        }
        if admin {
            match admin_group() {
                Some(g) => add_to_group_sync(&u, g)?,
                None => return Err(users_err(SystemUserError::NoSudoGroup)),
            }
        }
        if !pw.is_empty() {
            set_passwd_sync(&u, &pw)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| anyhow!("{e}"))?
}

/// Remove the system account and its home directory. No-op when absent. Refuses
/// to delete a *foreign* account: only a DN7-owned account (adoptable) is torn
/// down, so a store entry that somehow collided with a real service account can
/// never destroy that account + its home.
pub async fn remove(username: &str) -> Result<()> {
    let u = username.to_string();
    tokio::task::spawn_blocking(move || match getpwnam(&u) {
        Some((_, home)) => {
            if !system_account_adoptable(provenance_of(&u, &home)) {
                return Err(anyhow!("{}", foreign_account_refused_msg(&u)));
            }
            del_user_sync(&u)
        }
        None => Ok(()),
    })
    .await
    .map_err(|e| anyhow!("{e}"))?
}

/// Set the system account's password to match the panel password. No-op when the
/// system account doesn't exist.
pub async fn set_system_password(username: &str, password: &str) -> Result<()> {
    if getpwnam(username).is_none() {
        return Ok(());
    }
    if !crate::core::identity::valid_os_secret(password) {
        return Err(users_err(SystemUserError::SetPwFailed));
    }
    let (u, pw) = (username.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || set_passwd_sync(&u, &pw))
        .await
        .map_err(|e| anyhow!("{e}"))?
}

/// Grant or revoke the system admin group (sudo/wheel) for a user.
pub async fn set_sudo(username: &str, on: bool) -> Result<()> {
    let u = username.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        if on {
            match admin_group() {
                Some(g) => add_to_group_sync(&u, g),
                None => Err(users_err(SystemUserError::NoSudoGroup)),
            }
        } else {
            // De-escalation is the dangerous direction: if the /etc/group edit
            // fails we MUST surface it, or the panel would report "user" while the
            // OS account still holds sudo/wheel (privilege NOT actually dropped).
            // Capture the first removal error and return it instead of swallowing.
            let mut first_err: Option<anyhow::Error> = None;
            for g in ["sudo", "wheel"] {
                if group_exists(g) {
                    if let Err(e) = remove_from_group_sync(&u, g) {
                        first_err.get_or_insert(e);
                    }
                }
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    })
    .await
    .map_err(|e| anyhow!("{e}"))?
}

/// Whether a GECOS (full-name) value is safe to write into /etc/passwd: no ASCII
/// control char (a newline would forge a passwd line) and no ':' (the separator).
fn gecos_ok(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b':')
}

/// Set the system account's GECOS full-name field. A field-forging value is
/// refused (not written).
pub async fn set_full_name(username: &str, full_name: &str) -> Result<()> {
    if !gecos_ok(full_name) {
        return Err(users_err(SystemUserError::BadFullName));
    }
    if getpwnam(username).is_none() {
        return Ok(());
    }
    let (u, n) = (username.to_string(), full_name.to_string());
    tokio::task::spawn_blocking(move || set_gecos_sync(&u, &n))
        .await
        .map_err(|e| anyhow!("{e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha512_crypt_is_a_valid_shadow_field() {
        use sha_crypt::{sha512_simple, Sha512Params};
        let h = sha512_simple("hunter2", &Sha512Params::new(5_000).unwrap()).unwrap();
        assert!(h.starts_with("$6$"), "expected SHA-512 crypt, got {h}");
        assert!(h.matches('$').count() >= 3, "well-formed $6$salt$hash");
    }

    #[test]
    fn gecos_safety() {
        assert!(gecos_ok("Jane Doe"));
        assert!(!gecos_ok("a:b")); // field separator
        assert!(!gecos_ok("a\nroot:x:0")); // line forge
    }

    #[test]
    fn owned_marker_round_trips_in_home() {
        // A foreign home (no marker) → not detected; after write_owned_marker it
        // is, so a leftover DN7 account is distinguishable from a service account.
        let dir = std::env::temp_dir().join(format!("dn7-marker-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let home = dir.to_str().unwrap();
        assert!(
            !home_has_owned_marker(home),
            "foreign home has no DN7 marker"
        );
        write_owned_marker(&dir, unsafe { libc::getuid() }, unsafe { libc::getgid() });
        assert!(
            home_has_owned_marker(home),
            "DN7-seeded home carries the marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Real /etc account lifecycle — gated to root (DN7_ROOT_USERTEST=1) since it
    // edits the live passwd/shadow/group. Run: sudo DN7_ROOT_USERTEST=1 <testbin>
    // --exact ...root_user_lifecycle.
    #[test]
    fn root_user_lifecycle() {
        if std::env::var("DN7_ROOT_USERTEST").is_err() {
            return;
        }
        let name = "dn7tst9";
        let _ = del_user_sync(name);
        add_user_sync(name, "Test User", "/bin/bash").unwrap();
        let (uid, home) = getpwnam(name).expect("account created");
        assert!(uid >= 1000);
        assert_eq!(home, format!("/home/{name}"));
        assert!(std::path::Path::new(&home).is_dir(), "home created");
        // A DN7-created account carries the ownership marker → adoptable.
        assert!(home_has_owned_marker(&home), "DN7 marker written");
        assert!(system_account_adoptable(provenance_of(name, &home)));
        set_passwd_sync(name, "s3cret-pw").unwrap();
        let sh = std::fs::read_to_string(SHADOW).unwrap();
        assert!(
            sh.lines().any(|l| l.starts_with(&format!("{name}:$6$"))),
            "shadow has a SHA-512 hash"
        );
        del_user_sync(name).unwrap();
        assert!(getpwnam(name).is_none(), "account removed");
        assert!(!std::path::Path::new(&home).exists(), "home removed");
    }
}
