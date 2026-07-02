//! Small JSON + argument helpers for the channel (`dn7 site/cert/user/...`) views.

use serde_json::Value;

/// Whether `flag` (e.g. `--admin`) is present anywhere in `args`.
pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// The value following `--flag` in `args`, if present.
pub fn flag_val<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Whether the caller asked for machine-readable JSON output (`--json`).
pub fn wants_json(args: &[String]) -> bool {
    has_flag(args, "--json")
}

/// Pretty-print a JSON value (for `--json` output, pipeable to `jq`).
pub fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

/// First present field among `keys` as a display string, else `-`.
pub fn sf(v: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    for k in keys {
        match v.get(*k) {
            Some(x) if !x.is_null() => return x.to_string(),
            _ => {}
        }
    }
    "-".to_string()
}
