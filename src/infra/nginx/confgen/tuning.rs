//! http/server tuning directive rendering + http-context include.
use super::*;

// ---------------------------------------------------------------------------
// HTTP tuning config rendering (reads the persisted tuning from the store).
// ---------------------------------------------------------------------------

/// The server-context tuning directives, emitted into each managed server
/// block. When the operator hasn't configured tuning we still emit a generous
/// `client_max_body_size` so a managed proxy site (e.g. the panel proxied
/// behind its own nginx) doesn't inherit nginx's tiny 1 MiB default and return
/// 413 on file / Docker-image uploads. The remaining directives stay opt-in
/// (we don't override the distro's http defaults until the operator asks).
pub(crate) fn render_tuning_block() -> String {
    let t = match load_tuning_opt() {
        Some(t) => t,
        None => {
            // Not configured → only pin the upload size to a sane default.
            return format!(
                "    client_max_body_size {};\n",
                HttpTuning::default().client_max_body_size
            );
        }
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
