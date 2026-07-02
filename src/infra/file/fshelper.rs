//! Privilege-dropping file helper — the PURE-RUST replacement for `su`. The panel
//! (running as root) re-execs its own binary as `dn7-panel __fshelper <op> <user>
//! <path>`; this fresh, single-threaded process drops to the target user
//! (`initgroups` + `setgid` + `setuid`) and then performs ONE file operation in
//! Rust, so the OS enforces that user's permissions. No `su`, no `/bin/sh`.
//!
//! Dropping privileges inside the re-exec'd child (rather than the multithreaded
//! panel) is what makes `initgroups`/`setgid`/`setuid` safe here: the process has
//! a single thread and a clean address space.
use std::ffi::CString;
use std::io::Write;
use std::path::Path;

/// Entry point dispatched from `main` when argv[1] == `__fshelper`. Returns the
/// process exit code (the caller passes it to `std::process::exit`).
/// argv: `[exe, "__fshelper", op, user, path]`.
pub(crate) fn run_fs_helper_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        return 2;
    }
    let (op, user, path) = (args[2].as_str(), args[3].as_str(), args[4].as_str());
    if drop_privileges(user).is_err() {
        return 111; // could not become the target user → do nothing
    }
    match op {
        "list" => op_list(path),
        "mkdir" => op_mkdir(path),
        "remove" => op_remove(path),
        "read" => op_read(path),
        "write" => op_write(path),
        "stat" => op_stat(path),
        "rename" => op_rename(path),
        _ => 2,
    }
}

/// Entry point dispatched from `main` when argv[1] == `__webshell` — the
/// PURE-RUST replacement for the web terminal's old `su - <user>`. Re-exec'd
/// from the (multithreaded) panel so the credential drop runs in a fresh
/// single-threaded process, then `exec`s the user's login shell.
/// argv: `[exe, "__webshell", user]`.
pub(crate) fn run_web_shell_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return 2;
    }
    let user = args[2].as_str();
    // Resolve home + login shell as root, BEFORE dropping privileges.
    let (home, shell) = pw_home_shell(user).unwrap_or_else(|| ("/".into(), "/bin/sh".into()));
    if drop_privileges(user).is_err() {
        return 111;
    }
    // Mirror `su -`: a login shell in the user's home with a clean identity env.
    let _ = std::env::set_current_dir(&home);
    std::env::set_var("HOME", &home);
    std::env::set_var("USER", user);
    std::env::set_var("LOGNAME", user);
    std::env::set_var("SHELL", &shell);
    let Ok(shell_c) = CString::new(shell.as_str()) else {
        return 2;
    };
    // argv[0] = "-<base>" requests a login shell (reads /etc/profile, ~/.profile).
    let base = Path::new(&shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("sh");
    let arg0 = CString::new(format!("-{base}")).unwrap_or_else(|_| CString::new("-sh").unwrap());
    let argv = [arg0.as_ptr(), std::ptr::null()];
    // SAFETY: execv with a valid NUL-terminated program path + NULL-terminated
    // argv; keeps the (post-set_var) environment. Only returns on failure.
    unsafe { libc::execv(shell_c.as_ptr(), argv.as_ptr()) };
    127
}

/// The target user's home directory + login shell (reentrant `getpwnam_r`),
/// looked up as root before the credential drop.
fn pw_home_shell(user: &str) -> Option<(String, String)> {
    let cname = CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: getpwnam_r fills pwd/buf and points result at pwd (or null).
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: pw_dir / pw_shell are NUL-terminated C strings backed by `buf`.
    let read = |p: *const libc::c_char| -> String {
        if p.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned()
        }
    };
    let home = read(pwd.pw_dir);
    let shell = read(pwd.pw_shell);
    Some((
        if home.is_empty() { "/".into() } else { home },
        if shell.is_empty() {
            "/bin/sh".into()
        } else {
            shell
        },
    ))
}

/// Resolve `user`'s uid+gid (reentrant `getpwnam_r`).
fn pw_uid_gid(user: &str) -> Option<(libc::uid_t, libc::gid_t)> {
    let cname = CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: getpwnam_r fills pwd/buf and points result at pwd (or null).
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some((pwd.pw_uid, pwd.pw_gid))
}

/// Become `user`: supplementary groups, then gid, then uid — and verify root can
/// no longer be regained (defense in depth).
fn drop_privileges(user: &str) -> Result<(), ()> {
    let cname = CString::new(user).map_err(|_| ())?;
    let (uid, gid) = pw_uid_gid(user).ok_or(())?;
    // SAFETY: standard credential drop on a single-threaded process. Order is
    // mandatory: groups + gid BEFORE uid (after setuid we'd lack the privilege).
    unsafe {
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            return Err(());
        }
        if libc::setgid(gid) != 0 {
            return Err(());
        }
        if libc::setuid(uid) != 0 {
            return Err(());
        }
        // If we are non-root now, regaining root MUST fail; if it succeeds the
        // drop didn't take — refuse to run the op.
        if uid != 0 && libc::setuid(0) == 0 {
            return Err(());
        }
    }
    Ok(())
}

/// List a directory as tab-delimited `<d|f|ld|lf>\t<size>\t<mtime>\t<mode>\t<name>`
/// lines (the format [`super::parse_list_output`] expects; `l` prefix marks a
/// symlink, mode is the octal permission bits, mtime unix secs). Exit 7 when
/// the dir can't be read.
fn op_list(path: &str) -> i32 {
    use std::os::unix::fs::MetadataExt;
    let rd = match std::fs::read_dir(path) {
        Ok(r) => r,
        Err(_) => return 7,
    };
    let mut out = String::new();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if name.contains('\n') || name.contains('\t') {
            continue; // a name with our delimiters would corrupt the row
        }
        // DirEntry::metadata is no-follow (lstat): mode/mtime/link flag describe
        // the entry itself; symlinks resolve once more (running as the target
        // user, so the OS still enforces access) so a link to a directory lists
        // as a directory. A broken link keeps its lstat and reads as a file.
        let lmd = ent.metadata().ok();
        let is_link = lmd
            .as_ref()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let fmd = if is_link {
            std::fs::metadata(ent.path()).ok()
        } else {
            None
        };
        let eff = fmd.as_ref().or(lmd.as_ref());
        let is_dir = eff.map(|m| m.is_dir()).unwrap_or(false);
        let size = if is_dir {
            0
        } else {
            eff.map(|m| m.len()).unwrap_or(0)
        };
        let mtime = lmd.as_ref().map(|m| m.mtime()).unwrap_or(0);
        let mode = lmd
            .as_ref()
            .map(|m| format!("{:o}", m.mode() & 0o7777))
            .unwrap_or_default();
        let t = match (is_link, is_dir) {
            (true, true) => "ld",
            (true, false) => "lf",
            (false, true) => "d",
            (false, false) => "f",
        };
        out.push_str(&format!("{t}\t{size}\t{mtime}\t{mode}\t{name}\n"));
    }
    write_stdout(out.as_bytes())
}

fn op_mkdir(path: &str) -> i32 {
    match std::fs::create_dir_all(path) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `rm -rf`: recursive for dirs, unlink for files, success when already absent.
fn op_remove(path: &str) -> i32 {
    let p = Path::new(path);
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            if std::fs::remove_dir_all(p).is_ok() {
                0
            } else {
                1
            }
        }
        Ok(_) => {
            if std::fs::remove_file(p).is_ok() {
                0
            } else {
                1
            }
        }
        Err(_) => 0, // already gone (rm -f semantics)
    }
}

/// Stream a regular file to stdout (`cat`). Exit 9 for a missing file or a dir.
fn op_read(path: &str) -> i32 {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return 9,
    };
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return 9;
    }
    let mut so = std::io::stdout();
    if std::io::copy(&mut f, &mut so).is_err() {
        return 1;
    }
    so.flush().is_err() as i32
}

/// Stream stdin into `path`, truncating/creating it (`cat > path`).
fn op_write(path: &str) -> i32 {
    let mut f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(_) => return 1,
    };
    let mut si = std::io::stdin();
    match std::io::copy(&mut si, &mut f) {
        Ok(_) => f.flush().is_err() as i32,
        Err(_) => 1,
    }
}

/// Existence probe (no-follow lstat): exit 0 when `path` exists, 7 when not.
fn op_stat(path: &str) -> i32 {
    if std::fs::symlink_metadata(path).is_ok() {
        0
    } else {
        7
    }
}

/// Rename/move `path` to the destination path supplied on stdin. Exit 8 when
/// the destination already exists (no silent clobber), 2 on a malformed
/// destination, 1 on failure.
fn op_rename(path: &str) -> i32 {
    let mut dest = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut dest).is_err() {
        return 2;
    }
    let dest = dest.trim_end_matches('\n');
    if dest.is_empty() || !dest.starts_with('/') {
        return 2;
    }
    if std::fs::symlink_metadata(dest).is_ok() {
        return 8;
    }
    match std::fs::rename(path, dest) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Write `bytes` to stdout, flushing (we exit via `process::exit`, which does NOT
/// flush std buffers). Returns 0 on success, 1 on a write error.
fn write_stdout(bytes: &[u8]) -> i32 {
    let mut so = std::io::stdout();
    if so.write_all(bytes).is_err() || so.flush().is_err() {
        return 1;
    }
    0
}
