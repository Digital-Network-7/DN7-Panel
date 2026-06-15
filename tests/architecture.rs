//! Architecture test — enforces the layer dependency rules from
//! `.kiro/steering/architecture.md` (§4 禁止项 / §8 测试策略).
//!
//! Tier 1 (directory-level deny) only, for now: each governed directory must
//! not reference the listed forbidden crates/paths. Rules are added as modules
//! migrate into the layered layout — start loose, tighten over time. Tiers 2
//! (module allowlist) and 3 (semantic, e.g. serde in domain) come later.
//!
//! Robustness: we scan `use`/code lines, skip comment lines (incl. `///`/`//!`
//! doc comments, which legitimately mention forbidden names), and honour a
//! `// arch-allow(<phase/ticket>): <reason>` escape hatch on the offending line
//! for the migration window (see steering §8 — exceptions must be temporary).

use std::fs;
use std::path::Path;

/// (governed directory relative to crate root, forbidden substrings).
const RULES: &[(&str, &[&str])] = &[
    (
        // domain 不懂传输,也不碰外部系统/进程。
        "src/domain",
        &[
            "axum",
            "bollard",
            "reqwest",
            "tokio::process",
            "std::process",
        ],
    ),
    (
        // infra 实现规则,不决定规则;不得依赖交付层或 axum。
        "src/infra",
        &["axum", "crate::web"],
    ),
    (
        // app 编排用例,只依赖 domain + ports;不碰交付层/外部系统。
        "src/app",
        &["axum", "bollard", "reqwest", "crate::web"],
    ),
];

fn scan(dir: &Path, forbidden: &[&str], violations: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return, // directory not present yet — nothing to govern
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan(&p, forbidden, violations);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap_or_default();
        for (i, raw) in src.lines().enumerate() {
            let line = raw.trim_start();
            // Skip comments (line + doc comments) and migration exceptions.
            if line.starts_with("//") || raw.contains("arch-allow") {
                continue;
            }
            for tok in forbidden {
                if line.contains(tok) {
                    violations.push(format!(
                        "{}:{}: forbidden `{tok}` (rule for {dir})",
                        p.display(),
                        i + 1,
                        dir = dir.display()
                    ));
                }
            }
        }
    }
}

#[test]
fn layers_respect_dependency_rules() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();
    for (layer, forbidden) in RULES {
        scan(&Path::new(root).join(layer), forbidden, &mut violations);
    }
    assert!(
        violations.is_empty(),
        "architecture violations (see .kiro/steering/architecture.md):\n{}",
        violations.join("\n")
    );
}
