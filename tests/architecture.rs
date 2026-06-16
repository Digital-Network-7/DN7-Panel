//! Architecture test — enforces the layer dependency rules from
//! `.kiro/steering/architecture.md` (§4 禁止项 / §8 测试策略).
//!
//! Tier 1 (directory-level deny) governs `domain`/`infra`/`app`/`web`. Tier 2
//! (module allowlist) is in place via `capability_tokens_stay_in_their_layer`
//! (`bollard` only under `infra/`, `axum` only under `web/`). Tier 3 (semantic):
//! `domain_serde_is_whitelisted` restricts serde to reviewed `domain` entities.
//! Rules are added as modules migrate — start loose, tighten over time.
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
        // contracts 是对外协议唯一来源:可引用 domain 基础类型 + serde,但不依赖任何
        // 上层(app/infra/web),也不碰传输框架/外部系统。
        "src/contracts",
        &[
            "axum",
            "bollard",
            "reqwest",
            "tokio::process",
            "std::process",
            "crate::app",
            "crate::infra",
            "crate::web",
        ],
    ),
    (
        // domain 不懂传输,不碰外部系统/进程,也不依赖任何上层(app/infra/web)。
        "src/domain",
        &[
            "axum",
            "bollard",
            "reqwest",
            "tokio::process",
            "std::process",
            "crate::app",
            "crate::infra",
            "crate::web",
        ],
    ),
    (
        // infra 实现规则,不决定规则;不得依赖交付层或上层用例(web/app),也不引 axum。
        "src/infra",
        &["axum", "crate::web", "crate::app"],
    ),
    (
        // app 编排用例,不碰交付层/外部系统;可直接用 infra 适配器(§5:仅在需 mock/swap 时才抽 port)。
        "src/app",
        &["axum", "bollard", "reqwest", "crate::web"],
    ),
    (
        // web 只做交付(鉴权入口/DTO/响应映射),不直接碰容器/进程,也不直接调用各能力的内部
        // web_dispatch——能力一律经 app::<cap> 用例入口(web→app→infra)。
        "src/web",
        &["bollard", "tokio::process", "std::process", "web_dispatch"],
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

/// Tier-3 semantic guard (steering §2/§4): `domain` default-forbids `serde`.
/// Only the reviewed persisted-entity files may derive it — everything else in
/// `domain` must stay pure rules/values with no transport/serialization shape.
/// New serde in a non-whitelisted domain file is a deliberate review decision:
/// add the file here (and a `NOTE:` doc comment) only after that review.
const DOMAIN_SERDE_WHITELIST: &[&str] = &["identity.rs", "settings.rs", "mysql.rs", "nginx.rs"];

fn scan_domain_serde(dir: &Path, violations: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan_domain_serde(&p, violations);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if DOMAIN_SERDE_WHITELIST.contains(&fname) {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap_or_default();
        for (i, raw) in src.lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with("//") || raw.contains("arch-allow") {
                continue;
            }
            if line.contains("serde") || line.contains("Serialize") || line.contains("Deserialize")
            {
                violations.push(format!(
                    "{}:{}: domain serde outside whitelist (steering §2/§4)",
                    p.display(),
                    i + 1
                ));
            }
        }
    }
}

#[test]
fn domain_serde_is_whitelisted() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();
    scan_domain_serde(&Path::new(root).join("src/domain"), &mut violations);
    assert!(
        violations.is_empty(),
        "domain serde must be a reviewed exception (see .kiro/steering/architecture.md §2/§4):\n{}",
        violations.join("\n")
    );
}

/// Tier-2 module allowlist (steering §8): a capability/transport token may
/// appear ONLY under its owning subtree. This makes the "who may touch what"
/// boundary explicit and stops, e.g., a bollard call or an axum import drifting
/// out of `infra`/`web`. `arch-allow` (with reason+ticket) is the temporary
/// escape hatch for the few legitimate cross-cuts (e.g. the WS↔exec terminal).
///
/// (token, the only path fragment allowed to contain it).
const ALLOWLIST: &[(&str, &str)] = &[
    // The Docker daemon client lives only in the infra adapters.
    ("bollard", "src/infra/"),
    // axum (the HTTP framework) is the delivery layer's alone.
    ("axum", "src/web/"),
];

fn scan_allowlist(dir: &Path, violations: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan_allowlist(&p, violations);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let path_str = p.to_string_lossy().replace('\\', "/");
        let src = fs::read_to_string(&p).unwrap_or_default();
        for (i, raw) in src.lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with("//") || raw.contains("arch-allow") {
                continue;
            }
            for (tok, allowed) in ALLOWLIST {
                if line.contains(tok) && !path_str.contains(allowed) {
                    violations.push(format!(
                        "{}:{}: `{tok}` is only allowed under {allowed} (tier-2 allowlist)",
                        p.display(),
                        i + 1
                    ));
                }
            }
        }
    }
}

#[test]
fn capability_tokens_stay_in_their_layer() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();
    scan_allowlist(&Path::new(root).join("src"), &mut violations);
    assert!(
        violations.is_empty(),
        "tier-2 module-allowlist violations (see .kiro/steering/architecture.md §8):\n{}",
        violations.join("\n")
    );
}
