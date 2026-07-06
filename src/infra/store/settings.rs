//! Console-settings store: `<data>/web.json` (0600). Pure persistence of the
//! `WebSettings` domain entity — seeding/reset/validation stay in
//! `web::settings`.

use anyhow::Result;

use crate::core::settings::WebSettings;

fn path() -> std::path::PathBuf {
    crate::platform::paths::data_dir().join("web.json")
}

/// Read persisted settings without seeding. None when not initialized/corrupt.
/// Tolerant — for genuinely-optional reads (owner-uid lookup, banner info).
pub(crate) fn load() -> Option<WebSettings> {
    crate::infra::support::json_store::load_opt(&path())
}

/// Strict load for the startup seed path: `Ok(None)` only when web.json is
/// genuinely ABSENT (fresh install → seed), `Ok(Some(_))` when present +
/// parseable, and `Err` (with the bad file *quarantined* to
/// `web.json.corrupt-<ts>`) when present but UNPARSEABLE. This is the ONE
/// distinction the tolerant [`load`] collapses — a corrupt web.json holds the
/// superadmin verifier + TOTP secret + IP allow-list, so the seed path must
/// refuse rather than overwrite it with a fresh uninitialized default.
pub(crate) fn load_strict() -> Result<Option<WebSettings>> {
    crate::infra::support::json_store::load_strict(&path())
}

/// Persist settings 0600 atomically (no create-then-chmod window).
pub(crate) fn save(s: &WebSettings) -> Result<()> {
    crate::infra::support::json_store::save_private(&path(), s)
}

#[cfg(test)]
mod tests {
    use super::*;
    // `path()` resolves through `data_dir()`, which honors the process-global
    // `DN7_RUNTIME_DIR`. This test sets it, so serialize against every other
    // env-mutating test (docker/backups + files-controller) via the one
    // crate-wide `test_support::ENV_LOCK`, and restore the previous value on exit.
    use crate::test_support::ENV_LOCK;

    fn quarantine_copies() -> Vec<std::path::PathBuf> {
        let p = path();
        let dir = p.parent().unwrap().to_path_buf();
        let stem = p.file_name().unwrap().to_string_lossy().to_string();
        std::fs::read_dir(&dir)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().to_string();
                        n.starts_with(&stem) && n.contains(".corrupt-")
                    })
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    }

    // A corrupt web.json must make load_strict() Err (and quarantine the bad
    // bytes aside), and must NOT leave a parseable default at the web.json path —
    // so the startup seed path (web::settings::load_or_init) can refuse rather
    // than clobber the superadmin credential + TOTP secret with a fresh default.
    #[test]
    fn corrupt_web_json_is_quarantined_and_not_clobbered() {
        let _g = ENV_LOCK.blocking_lock();
        let prev = std::env::var_os("DN7_RUNTIME_DIR");
        let base = std::env::temp_dir().join(format!(
            "dn7-websettings-test-{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        ));
        std::env::set_var("DN7_RUNTIME_DIR", &base);

        let p = path();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();

        // A genuinely-absent file is Ok(None) (the fresh-install seed signal),
        // not an error — the seed path relies on this to distinguish absent from
        // corrupt.
        assert!(matches!(load_strict(), Ok(None)));

        // A well-formed web.json parses back (only `port` lacks a serde default,
        // so a minimal object is enough).
        save(&WebSettings {
            port: 1080,
            username: "admin".into(),
            pw_salt: String::new(),
            pw_hash: "deadbeef".into(),
            pw_kdf: "s256:30000".into(),
            pw_default: false,
            owner_uid: 1000,
            full_name: String::new(),
            nickname: String::new(),
            avatar: String::new(),
            totp_secret: "SECRET".into(),
            totp_enabled: true,
            initialized: true,
            init_token: String::new(),
            external_address: "panel.example.com".into(),
            https_mode: "le".into(),
            website_http_port: 80,
            website_https_port: 443,
            console_port: 0,
            entry_path: String::new(),
            language: String::new(),
            timezone: String::new(),
            session_timeout: 1440,
            allow_ips: vec!["10.0.0.0/8".into()],
            trusted_proxies: Vec::new(),
        })
        .unwrap();
        let loaded = load_strict().unwrap().expect("valid web.json loads");
        assert_eq!(loaded.username, "admin");
        assert!(loaded.initialized && loaded.totp_enabled);

        // Now corrupt it. load_strict must Err (NOT silently return None like the
        // tolerant load()), and the corrupt bytes must be moved aside.
        std::fs::write(&p, b"{ not valid json").unwrap();
        // The tolerant load() SWALLOWS the corruption into None (which is exactly
        // why the seed path must not key off it) — load_strict() surfaces it.
        assert!(load().is_none());
        assert!(
            load_strict().is_err(),
            "corrupt web.json must be a hard error, not a silent None"
        );
        assert!(
            !p.exists(),
            "the corrupt web.json must be quarantined (moved aside), leaving nothing to clobber in place"
        );
        // Exactly one quarantine copy, preserving the original corrupt bytes.
        let q = quarantine_copies();
        assert_eq!(q.len(), 1, "corrupt bytes preserved for inspection");
        assert_eq!(std::fs::read(&q[0]).unwrap(), b"{ not valid json");
        // The web.json path holds no parseable settings, so the seed path can't
        // have (and must not) resurrect a fresh uninitialized default over it.
        assert!(load().is_none());

        // Cleanup + restore.
        for f in q {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_dir_all(&base);
        match prev {
            Some(v) => std::env::set_var("DN7_RUNTIME_DIR", v),
            None => std::env::remove_var("DN7_RUNTIME_DIR"),
        }
    }
}
