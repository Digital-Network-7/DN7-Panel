//! Server-level security/auth directives (real-IP, HSTS, access blocks).
use super::*;

/// HTTPS server security directives: trusted-proxy real-IP headers and HSTS.
pub(crate) fn render_ssl_security(site: &Site) -> String {
    let mut sec = String::new();
    if site.trust_proxy {
        // Honour a trusted front proxy / CDN's real-client + protocol headers,
        // but only from the configured trusted sources. Trusting every source
        // (0.0.0.0/0) would let any client spoof X-Forwarded-For and bypass
        // IP-based access rules, so an empty list falls back to private/loopback
        // ranges rather than the whole internet.
        for cidr in trusted_proxy_sources(site) {
            sec.push_str(&format!("    set_real_ip_from {cidr};\n"));
        }
        sec.push_str("    real_ip_header X-Forwarded-For;\n    real_ip_recursive on;\n");
    }
    if site.hsts {
        let sub = if site.hsts_sub {
            "; includeSubDomains"
        } else {
            ""
        };
        sec.push_str(&format!(
            "    add_header Strict-Transport-Security \"max-age=63072000{sub}\" always;\n"
        ));
    }
    sec
}

/// The `set_real_ip_from` sources for a site: the operator's explicit trusted
/// IP/CIDR list (already validated on save), or — when none are configured —
/// the private + loopback ranges only. This never trusts the public internet,
/// so a client can't forge `X-Forwarded-For` to spoof its source IP.
pub(crate) fn trusted_proxy_sources(site: &Site) -> Vec<String> {
    let explicit: Vec<String> = site
        .trust_proxy_cidrs
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if !explicit.is_empty() {
        return explicit;
    }
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Build the server-level access-control directives for an access list:
/// `satisfy`, `allow`/`deny` rules, and `auth_basic` + `auth_basic_user_file`.
/// Returns an empty string when the list is absent or has no rules.
pub(crate) fn render_auth_block(access: Option<&AccessList>) -> String {
    let a = match access {
        Some(a) => a,
        None => return String::new(),
    };
    let has_auth = !a.users.is_empty();
    let has_clients = !a.clients.is_empty();
    if !has_auth && !has_clients {
        return String::new();
    }
    let mut s = String::from("\n");
    // `satisfy` only matters when both factors are present, but it's harmless
    // otherwise and makes the intent explicit.
    if has_auth && has_clients {
        let mode = if a.satisfy == "all" { "all" } else { "any" };
        s.push_str(&format!("    satisfy {mode};\n"));
    }
    if has_clients {
        for c in &a.clients {
            let dir = if c.directive == "deny" {
                "deny"
            } else {
                "allow"
            };
            s.push_str(&format!("    {dir} {};\n", c.address));
        }
    }
    if has_auth {
        s.push_str(&format!(
            "    auth_basic \"{}\";\n",
            a.name.replace('"', "")
        ));
        s.push_str(&format!(
            "    auth_basic_user_file {};\n",
            htpasswd_path(&a.id).display()
        ));
    }
    s.push('\n');
    s
}
