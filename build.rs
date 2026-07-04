//! Build script: inject the release codename (from `release.toml`) into the
//! binary as the `DN7_CODENAME` env, so the panel can display
//! "<codename> <version>". The numeric version rides in via Cargo.toml
//! (CARGO_PKG_VERSION, stamped by CI); the codename can't live there, so it is
//! read here at build time — which works both inside CI's `cross` container and
//! in local dev builds. std-only; adds no dependency.

use std::path::Path;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let path = Path::new(&dir).join("release.toml");
    // Rebuild when the codename changes (or the file appears/disappears).
    println!("cargo:rerun-if-changed={}", path.display());
    let codename = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| codename_of(&s))
        .unwrap_or_else(|| "dev".to_string());
    println!("cargo:rustc-env=DN7_CODENAME={codename}");
}

/// Pull the value out of `codename = "…"` with a minimal line parser (keeps the
/// build free of a toml dependency). Returns the text between the first pair of
/// double quotes on the `codename` line.
fn codename_of(src: &str) -> Option<String> {
    for line in src.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.starts_with("codename") {
            continue;
        }
        let start = line.find('"')?;
        let after = &line[start + 1..];
        let end = after.find('"')?;
        let val = &after[..end];
        if !val.is_empty() {
            return Some(val.to_string());
        }
    }
    None
}
