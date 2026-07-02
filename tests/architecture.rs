//! Architecture test — enforces the layer dependency rules from
//! `.kiro/steering/architecture.md` (§4 禁止项 / §8 测试策略).
//!
//! Tier 1 (directory-level deny) governs `domain`/`infra`/`app`/`web`. Tier 2
//! (module allowlist) is in place via `capability_tokens_stay_in_their_layer`
//! (`bollard` only under `infra/`, `axum` only under `web/`). Tier 3 (semantic):
//! `core_serde_is_whitelisted` restricts serde to reviewed `domain` entities.
//! `files_stay_within_size_limit` gates the ARCHITECTURE.md §9 ≤500-line rule
//! across `src/` and `crates/*/src/`. Rules are added as modules migrate —
//! start loose, tighten over time.
//!
//! Robustness: we scan `use`/code lines, skip comment lines (incl. `///`/`//!`
//! doc comments, which legitimately mention forbidden names), and honour a
//! `// arch-allow(<phase/ticket>): <reason>` escape hatch on the offending line
//! for the migration window (see steering §8 — exceptions must be temporary).
//! The marker is format-checked (`arch_allow_marker_ok`): a bare/malformed
//! `arch-allow` no longer exempts the line.

use std::fs;
use std::path::Path;

/// Validate an `arch-allow` escape marker. Only a *well-formed* marker exempts a
/// line; a bare or malformed `arch-allow` (steering §8 requires ticket+reason)
/// no longer opens the loophole and still counts as a violation.
///
/// Accepted shape (must appear inside a `//` comment on the line):
///   `// arch-allow(<ticket>): <reason>`
/// where `<ticket>` is the (non-empty) text up to the matching `)` — it may
/// itself contain `:`/spaces (e.g. `arch-migration: ws-pty-bridge`) — and
/// `<reason>` is non-empty after the `):`. Parsed with std string ops only
/// (zero-dep, no regex).
fn arch_allow_marker_ok(line: &str) -> bool {
    // The marker must live in a comment; find the `//` that precedes it.
    let comment = match line.find("//") {
        Some(idx) => &line[idx..],
        None => return false,
    };
    let after = match comment.find("arch-allow") {
        Some(idx) => &comment[idx + "arch-allow".len()..],
        None => return false,
    };
    // `arch-allow` must be immediately followed by `(`.
    let after = match after.strip_prefix('(') {
        Some(rest) => rest,
        None => return false,
    };
    // Ticket = everything up to the matching `)`; must be non-empty.
    let close = match after.find(')') {
        Some(idx) => idx,
        None => return false,
    };
    let ticket = &after[..close];
    if ticket.trim().is_empty() {
        return false;
    }
    // `)` must be immediately followed by `:`, then a non-empty reason.
    let rest = &after[close + 1..];
    let reason = match rest.strip_prefix(':') {
        Some(r) => r,
        None => return false,
    };
    !reason.trim().is_empty()
}

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
        // core 不懂传输,不碰外部系统/进程,也不依赖任何上层(app/infra/web)。
        "src/core",
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
            // Skip comments (line + doc comments) and well-formed migration exceptions.
            if line.starts_with("//") || arch_allow_marker_ok(raw) {
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
///
/// Entries are path suffixes (relative to the crate root) so a capability that
/// was split into a directory keeps a precise whitelist (e.g. only
/// `website/model.rs`, not every `model.rs`).
const DOMAIN_SERDE_WHITELIST: &[&str] = &[
    "core/identity/model.rs",
    "core/settings/model.rs",
    "core/website/model.rs",
];

fn scan_core_serde(dir: &Path, violations: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan_core_serde(&p, violations);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let path_str = p.to_string_lossy().replace('\\', "/");
        if DOMAIN_SERDE_WHITELIST
            .iter()
            .any(|suffix| path_str.ends_with(suffix))
        {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap_or_default();
        for (i, raw) in src.lines().enumerate() {
            let line = raw.trim_start();
            if line.starts_with("//") || arch_allow_marker_ok(raw) {
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
fn core_serde_is_whitelisted() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut violations = Vec::new();
    scan_core_serde(&Path::new(root).join("src/core"), &mut violations);
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
            if line.starts_with("//") || arch_allow_marker_ok(raw) {
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

/// Per-file line budget from the constitution (ARCHITECTURE.md §9 — 文件 ≤ 500 行).
const FILE_LINE_LIMIT: usize = 500;

/// Migration ledger: NON-TEST source files that currently exceed the line budget.
/// Each is grandfathered so the gate is GREEN today and only catches NEW
/// regressions; this list should SHRINK over time (matches the file's
/// "start loose, tighten over time" philosophy — split a file or earn its spot
/// here with a tracked reason). Entries are repo-relative paths.
const FILE_SIZE_WHITELIST: &[(&str, &str)] = &[
    (
        "src/infra/docker/runtime_dn7.rs",
        "in-house container runtime core",
    ),
    ("src/platform/init_cli.rs", "first-run interactive wizard"),
    (
        "src/web/http/controllers/files_controller.rs",
        "file mgr + staged up/download",
    ),
    (
        "crates/dn7-container/src/container/mod.rs",
        "container lifecycle",
    ),
    (
        "src/infra/docker/backups.rs",
        "backup + image import/export",
    ),
    ("crates/dn7-edge/src/proxy.rs", "edge proxy core"),
    ("crates/dn7-edge/src/static_files.rs", "static file serving"),
    ("crates/dn7-edge/src/build.rs", "route table builder"),
    ("src/infra/system/ops.rs", "/etc + user/group ops"),
    ("crates/dn7-container/src/net/nl.rs", "rtnetlink"),
    (
        "crates/dn7-container/src/sys/mount.rs",
        "bind/pivot_root mount setup + volume-dest traversal guard",
    ),
    (
        "crates/dn7-container/src/net/nft.rs",
        "hand-rolled nftables netlink encoder (replaces GPL/bindgen rustables)",
    ),
];

/// True if a `.rs` file is a test file that the size gate skips: named
/// `tests.rs`, living under a `/tests/` (or `/target/`) path, or opening with
/// `#![cfg(test)]` (data tables / fixtures are the documented exception).
fn is_test_file(rel: &str, src: &str) -> bool {
    if rel.ends_with("tests.rs") || rel.contains("/tests/") || rel.contains("/target/") {
        return true;
    }
    // Cheap heuristic: first non-empty line is a crate-level test gate.
    src.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .is_some_and(|first| first == "#![cfg(test)]")
}

fn scan_file_sizes(dir: &Path, root: &Path, oversized: &mut Vec<(String, usize)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan_file_sizes(&p, root, oversized);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let src = fs::read_to_string(&p).unwrap_or_default();
        if is_test_file(&rel, &src) {
            continue; // test files / fixtures are exempt from the size gate
        }
        let lines = src.lines().count();
        if lines > FILE_LINE_LIMIT && !FILE_SIZE_WHITELIST.iter().any(|(path, _)| *path == rel) {
            oversized.push((rel, lines));
        }
    }
}

#[test]
fn files_stay_within_size_limit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut oversized = Vec::new();
    // The single-crate root `src/` plus every helper crate's `src/`.
    scan_file_sizes(&root.join("src"), root, &mut oversized);
    if let Ok(crates) = fs::read_dir(root.join("crates")) {
        for ent in crates.flatten() {
            let p = ent.path();
            if p.is_dir() {
                scan_file_sizes(&p.join("src"), root, &mut oversized);
            }
        }
    }
    let report = oversized
        .iter()
        .map(|(path, lines)| format!("  {path}: {lines} lines (limit {FILE_LINE_LIMIT})"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        oversized.is_empty(),
        "files exceed the {FILE_LINE_LIMIT}-line budget (ARCHITECTURE.md §9). Split them, \
         or add a tracked FILE_SIZE_WHITELIST entry with a reason:\n{report}"
    );
}

/// Files permitted to shell out to the host init manager. See the "外部程序例外"
/// carve-out in ARCHITECTURE.md §4 + CLAUDE.md: init/bootstrap, service
/// lifecycle, and the human-invoked `dn7` management CLI have no pure-Rust
/// equivalent. Everything else — above all the resident serving loop — must stay
/// init-manager-free. A NEW file that shells out to one of these fails the gate
/// until it is reviewed and added here with a reason.
const INIT_MANAGER_SHELLOUT_ALLOWLIST: &[(&str, &str)] = &[
    (
        "src/main.rs",
        "run_reset: `dn7 reset` stops the systemd service",
    ),
    (
        "src/platform/init_cli.rs",
        "register_and_start_service: first-run install/start",
    ),
    (
        "crates/dn7-cli/src/service.rs",
        "dn7 service enable/disable/is-enabled",
    ),
    (
        "crates/dn7-cli/src/panel.rs",
        "dn7 panel status/logs/restart (systemctl/journalctl)",
    ),
    (
        "crates/dn7-cli/src/uninstall.rs",
        "dn7 uninstall: disable/stop the service",
    ),
    (
        "crates/dn7-cli/src/edge.rs",
        "dn7 edge: restart the panel service after edge changes",
    ),
];

/// Double-quoted command literals that mark an init-manager shell-out. The quote
/// form catches `Command::new("systemctl")` / `run_quiet("systemctl", …)` while
/// ignoring backtick-quoted mentions in comments and systemd-unit content.
const INIT_MANAGER_LITERALS: &[&str] = &["\"systemctl\"", "\"journalctl\"", "\"update-rc.d\""];

fn scan_init_manager_shellouts(dir: &Path, root: &Path, offenders: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.is_dir() {
            scan_init_manager_shellouts(&p, root, offenders);
            continue;
        }
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        let src = fs::read_to_string(&p).unwrap_or_default();
        if is_test_file(&rel, &src) {
            continue;
        }
        if INIT_MANAGER_SHELLOUT_ALLOWLIST
            .iter()
            .any(|(path, _)| *path == rel)
        {
            continue;
        }
        for line in src.lines() {
            if line.trim_start().starts_with("//") {
                continue; // a comment may name systemctl without shelling out
            }
            if INIT_MANAGER_LITERALS.iter().any(|lit| line.contains(lit)) {
                offenders.push(rel.clone());
                break;
            }
        }
    }
}

#[test]
fn no_new_init_manager_shellouts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    scan_init_manager_shellouts(&root.join("src"), root, &mut offenders);
    if let Ok(crates) = fs::read_dir(root.join("crates")) {
        for ent in crates.flatten() {
            let p = ent.path();
            if p.is_dir() {
                scan_init_manager_shellouts(&p.join("src"), root, &mut offenders);
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "new init-manager (systemctl/journalctl/update-rc.d) shell-out outside the audited \
         carve-out (ARCHITECTURE.md §4 / CLAUDE.md). The resident runtime must stay \
         external-program-free; if this is a reviewed lifecycle/CLI site, add it to \
         INIT_MANAGER_SHELLOUT_ALLOWLIST with a reason:\n  {}",
        offenders.join("\n  ")
    );
}
