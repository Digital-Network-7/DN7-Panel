//! Mirror "lines" for self-update fetching: the ways to reach github.com and the
//! URL rewrite for each. See the parent module for how the lines are raced.
//!
//! To stay fast on networks where github.com is slow or blocked, every request
//! can travel through one of several lines — github direct, a URL-prefix proxy,
//! or a host-swap mirror. The updater probes them all and uses whichever responds
//! fastest, silently dropping any that are dead or geo-blocked, so a bad line
//! never blocks an update.

/// One way to reach github.com.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Mirror {
    pub name: &'static str,
    pub kind: MirrorKind,
}

/// How a line rewrites a canonical `https://github.com/...` URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MirrorKind {
    /// github.com itself — no rewrite.
    Direct,
    /// URL-prefix proxy: the whole github URL is appended to the prefix,
    /// e.g. `https://gh-proxy.com/` + `https://github.com/...`.
    Prefix(&'static str),
    /// Host-swap mirror: the `github.com` host is replaced, e.g. `kkgithub.com`.
    Host(&'static str),
}

impl Mirror {
    /// Rewrite a canonical `https://github.com/...` URL to travel through this line.
    pub(crate) fn rewrite(&self, gh: &str) -> String {
        match self.kind {
            MirrorKind::Direct => gh.to_string(),
            MirrorKind::Prefix(p) => format!("{p}{gh}"),
            MirrorKind::Host(h) => gh.replacen("github.com", h, 1),
        }
    }
}

/// The download lines, github-direct first. The order is only a tiebreaker —
/// the updater probes them all and uses whichever responds fastest, so a dead or
/// geo-blocked line simply loses the race. Edit this list to add/remove lines.
const MIRRORS: &[Mirror] = &[
    Mirror {
        name: "github",
        kind: MirrorKind::Direct,
    },
    Mirror {
        name: "gh-proxy.com",
        kind: MirrorKind::Prefix("https://gh-proxy.com/"),
    },
    Mirror {
        name: "ghfast.top",
        kind: MirrorKind::Prefix("https://ghfast.top/"),
    },
    Mirror {
        name: "ghproxy.net",
        kind: MirrorKind::Prefix("https://ghproxy.net/"),
    },
    Mirror {
        name: "gh.ddlc.top",
        kind: MirrorKind::Prefix("https://gh.ddlc.top/"),
    },
    Mirror {
        name: "cors.isteed.cc",
        kind: MirrorKind::Prefix("https://cors.isteed.cc/"),
    },
    Mirror {
        name: "ghproxy.homeboyc.cn",
        kind: MirrorKind::Prefix("https://ghproxy.homeboyc.cn/"),
    },
    Mirror {
        name: "ghproxy.cc",
        kind: MirrorKind::Prefix("https://ghproxy.cc/"),
    },
    Mirror {
        name: "gh.api.99988866.xyz",
        kind: MirrorKind::Prefix("https://gh.api.99988866.xyz/"),
    },
    Mirror {
        name: "ghp.ci",
        kind: MirrorKind::Prefix("https://ghp.ci/"),
    },
    Mirror {
        name: "kkgithub.com",
        kind: MirrorKind::Host("kkgithub.com"),
    },
];

/// The active line set. `DN7_UPDATE_DIRECT=1` forces github-direct only (for
/// debugging, or installs that reach github fine and want no proxy hops).
pub(crate) fn mirrors() -> &'static [Mirror] {
    if std::env::var_os("DN7_UPDATE_DIRECT").is_some() {
        &MIRRORS[..1] // github is first
    } else {
        MIRRORS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_rewrite_forms() {
        let gh = "https://github.com/o/r/releases/download/v1.2.3/asset";
        assert_eq!(
            Mirror {
                name: "d",
                kind: MirrorKind::Direct
            }
            .rewrite(gh),
            gh
        );
        assert_eq!(
            Mirror {
                name: "p",
                kind: MirrorKind::Prefix("https://gh-proxy.com/")
            }
            .rewrite(gh),
            "https://gh-proxy.com/https://github.com/o/r/releases/download/v1.2.3/asset"
        );
        assert_eq!(
            Mirror {
                name: "h",
                kind: MirrorKind::Host("kkgithub.com")
            }
            .rewrite(gh),
            "https://kkgithub.com/o/r/releases/download/v1.2.3/asset"
        );
    }

    #[test]
    fn github_is_the_first_line() {
        // rank_lines/`DN7_UPDATE_DIRECT` both rely on github being index 0.
        assert_eq!(MIRRORS[0].name, "github");
        assert_eq!(MIRRORS[0].kind, MirrorKind::Direct);
    }
}
