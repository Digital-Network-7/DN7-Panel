//! Client-side password credential for `dn7 user add|passwd`.
//!
//! The panel never sees the cleartext password for console auth: the client
//! derives a salted-iterated SHA-256 *verifier* (the `s256:N` scheme) and POSTs
//! `{pw_salt, pw_hash, pw_kdf}` — byte-for-byte what the browser's `deriveVerifier`
//! produces. The live panel then wraps that verifier in Argon2id at rest, so we do
//! NOT do Argon2 here. The cleartext is sent only as the optional `password` field,
//! which the panel uses to sync the matching OS account password.

use std::io::{self, BufRead, Write};

/// The three persisted credential fields the API expects.
pub struct Credential {
    pub salt: String,
    pub hash: String,
    pub kdf: String,
}

/// Build a fresh credential (random salt + `s256:30000` verifier) for `password`,
/// via the shared `dn7_cred` KDF (the same one the panel's init wizard uses).
pub fn make_credential(password: &str) -> Credential {
    let salt = dn7_cred::random_salt_hex();
    let hash = dn7_cred::derive_verifier_s256(&salt, password, dn7_cred::KDF_ITERS);
    Credential {
        salt,
        hash,
        kdf: dn7_cred::kdf_string(),
    }
}

// --- password input -------------------------------------------------------

/// Resolve the cleartext password for a create/passwd command per the flags:
/// `--password <pw>` (explicit), `--stdin` (read one line from stdin, for
/// scripts), else an interactive no-echo prompt entered twice. Returns the
/// password or an error string for the caller to surface.
pub fn resolve_password(explicit: Option<&str>, from_stdin: bool) -> Result<String, String> {
    if let Some(p) = explicit {
        if p.is_empty() {
            return Err("密码不能为空 / password must not be empty".into());
        }
        return Ok(p.to_string());
    }
    if from_stdin {
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("读取 stdin 失败 / cannot read stdin: {e}"))?;
        let p = line.trim_end_matches(['\n', '\r']).to_string();
        if p.is_empty() {
            return Err("stdin 密码为空 / empty password on stdin".into());
        }
        return Ok(p);
    }
    if !crate::common::stdin_is_tty() {
        return Err(
            "非交互环境请用 --password 或 --stdin / non-interactive: use --password or --stdin"
                .into(),
        );
    }
    let p1 = read_noecho("设置密码 / set password: ")?;
    if p1.is_empty() {
        return Err("密码不能为空 / password must not be empty".into());
    }
    let p2 = read_noecho("确认密码 / confirm password: ")?;
    if p1 != p2 {
        return Err("两次密码不一致 / passwords do not match".into());
    }
    Ok(p1)
}

/// Read a line from the terminal with echo disabled (termios), then restore it.
fn read_noecho(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().ok();
    // SAFETY: standard termios get/set on fd 0; we restore the original on exit.
    let fd = 0;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let have_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if have_term {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut line = String::new();
    let res = io::stdin().lock().read_line(&mut line);
    if have_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    println!();
    res.map_err(|e| format!("读取密码失败 / cannot read password: {e}"))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
