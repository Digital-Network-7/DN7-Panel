//! Pure lexical path normalization — a shared domain rule used by the
//! capability guards (docker bind-mount deny-list, host file-manager
//! protection). Purely textual: resolves `.`/`..` segments and collapses
//! repeated/leading/trailing separators, with no filesystem or symlink
//! resolution, so it's safe for both host and container paths. `..` can never
//! climb above the root. Always returns an absolute path ("/" for the root).
//!
//! Centralizing this matters for security: a guard that prefix-matches a raw
//! string is trivially bypassed by `//etc`, `/./etc`, or `/srv/../etc` — the
//! OS / docker daemon resolves those to the real target while the literal
//! prefix check says "not sensitive". Every sensitive-path guard must normalize
//! first.
pub(crate) fn normalize_lexical(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.trim().split('/') {
        match seg {
            "" | "." => {} // leading/repeated '/', trailing '/', or '.'
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    if out.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", out.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_and_resolves() {
        assert_eq!(normalize_lexical("/etc/../etc"), "/etc");
        assert_eq!(
            normalize_lexical("//var/run/docker.sock"),
            "/var/run/docker.sock"
        );
        assert_eq!(normalize_lexical("/./etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_lexical("/srv/../etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_lexical("/usr//"), "/usr");
        assert_eq!(normalize_lexical("/etc/.."), "/");
        assert_eq!(normalize_lexical("//"), "/");
        assert_eq!(normalize_lexical("/../../../etc"), "/etc"); // can't climb above root
        assert_eq!(normalize_lexical("/opt/data"), "/opt/data");
    }
}
