//! Per-install console branding (`<data>/branding.json`, 0600).
//!
//! Lets the operator customise the console's panel name, logo, accent colour
//! and default theme (à la 1Panel). These values are **non-secret** and are
//! injected directly into the served `index.html` so the login page renders
//! already-branded with no flash of the default brand before JS runs.

use serde::{Deserialize, Serialize};

/// Default favicon / brand mark: the DN7 hexagon-network emblem (cyan→violet).
const DEFAULT_FAVICON: &str = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%2322d3ee'/%3E%3Cstop offset='1' stop-color='%238b5cf6'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cg fill='none' stroke='url(%23g)' stroke-width='1.5' stroke-linejoin='round'%3E%3Cpolygon points='16,4 26,9.5 26,22.5 16,28 6,22.5 6,9.5'/%3E%3Cpath d='M16 16 L16 4 M16 16 L26 9.5 M16 16 L26 22.5 M16 16 L16 28 M16 16 L6 22.5 M16 16 L6 9.5' stroke-linecap='round'/%3E%3C/g%3E%3Cg fill='url(%23g)'%3E%3Ccircle cx='16' cy='16' r='2.6'/%3E%3Ccircle cx='16' cy='4' r='1.7'/%3E%3Ccircle cx='26' cy='9.5' r='1.7'/%3E%3Ccircle cx='26' cy='22.5' r='1.7'/%3E%3Ccircle cx='16' cy='28' r='1.7'/%3E%3Ccircle cx='6' cy='22.5' r='1.7'/%3E%3Ccircle cx='6' cy='9.5' r='1.7'/%3E%3C/g%3E%3C/svg%3E";

/// The default brand mark rendered inside the `.cup` span (sized by CSS).
const DEFAULT_MARK: &str = r#"<svg viewBox="0 0 24 24" fill="none"><polygon points="12,3 19,7.5 19,16.5 12,21 5,16.5 5,7.5" stroke="white" stroke-width="1.4" stroke-linejoin="round" opacity="0.6"/><path d="M12 12 L12 3 M12 12 L19 7.5 M12 12 L19 16.5 M12 12 L12 21 M12 12 L5 16.5 M12 12 L5 7.5" stroke="white" stroke-width="1.4" stroke-linecap="round"/><g fill="white"><circle cx="12" cy="12" r="2"/><circle cx="12" cy="3" r="1.4"/><circle cx="19" cy="7.5" r="1.4"/><circle cx="19" cy="16.5" r="1.4"/><circle cx="12" cy="21" r="1.4"/><circle cx="5" cy="16.5" r="1.4"/><circle cx="5" cy="7.5" r="1.4"/></g></svg>"#;

const DEFAULT_NAME: &str = "DN7 Panel";
/// Cap the stored logo data-URI (~512 KiB of base64 ≈ 384 KiB raw image).
const MAX_LOGO_LEN: usize = 700_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    /// Panel name shown in the title, login brand and sidebar.
    #[serde(default = "default_name")]
    pub panel_name: String,
    /// Custom logo as an image data-URI, or empty to use the built-in mark.
    #[serde(default)]
    pub logo: String,
    /// Accent colour as `#rrggbb`, or empty to use the built-in palette.
    #[serde(default)]
    pub accent: String,
    /// Default theme mode for new visitors: `auto` | `light` | `dark`.
    #[serde(default = "default_theme")]
    pub theme_default: String,
}

fn default_name() -> String {
    DEFAULT_NAME.to_string()
}

fn default_theme() -> String {
    "auto".to_string()
}

impl Default for Branding {
    fn default() -> Self {
        Branding {
            panel_name: default_name(),
            logo: String::new(),
            accent: String::new(),
            theme_default: default_theme(),
        }
    }
}

fn branding_path() -> std::path::PathBuf {
    crate::paths::data_dir().join("branding.json")
}

/// Load persisted branding, falling back to defaults when absent/corrupt.
pub fn load() -> Branding {
    crate::json_store::load_or_default(&branding_path())
}

/// Persist branding to `<data>/branding.json` with 0600 perms (atomic).
pub fn save(b: &Branding) -> anyhow::Result<()> {
    crate::json_store::save_private(&branding_path(), b)
}

/// Validate + normalise an incoming branding update. Returns the value to
/// store, or a stable error **code** (mapped client-side to a localized
/// message via `err.<code>`) suitable for a 400 response.
pub fn validate(
    panel_name: Option<String>,
    logo: Option<String>,
    accent: Option<String>,
    theme_default: Option<String>,
) -> Result<Branding, String> {
    let mut b = load();
    if let Some(name) = panel_name {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 40 {
            return Err("branding.name_len".into());
        }
        b.panel_name = name.to_string();
    }
    if let Some(logo) = logo {
        let logo = logo.trim();
        if logo.is_empty() {
            b.logo = String::new();
        } else if !logo.starts_with("data:image/") || logo.len() > MAX_LOGO_LEN {
            return Err("branding.logo_invalid".into());
        } else {
            b.logo = logo.to_string();
        }
    }
    if let Some(accent) = accent {
        let accent = accent.trim();
        if accent.is_empty() {
            b.accent = String::new();
        } else if !is_hex_color(accent) {
            return Err("branding.accent_format".into());
        } else {
            b.accent = accent.to_lowercase();
        }
    }
    if let Some(theme) = theme_default {
        match theme.as_str() {
            "auto" | "light" | "dark" => b.theme_default = theme,
            _ => return Err("branding.theme_invalid".into()),
        }
    }
    Ok(b)
}

fn is_hex_color(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 7 && b[0] == b'#' && b[1..].iter().all(|c| c.is_ascii_hexdigit())
}

/// Minimal HTML-text escaping for values injected into markup.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render the static `index.html` template with this install's branding baked
/// in, so the page arrives already-branded (no flash).
pub fn render_index(tmpl: &str, b: &Branding) -> String {
    let name = esc(&b.panel_name);
    let favicon_href = if b.logo.is_empty() {
        DEFAULT_FAVICON.to_string()
    } else {
        b.logo.clone()
    };
    // Public, non-secret brand info for the runtime JS (theme fallback, etc.).
    let global = format!(
        "<script>window.__BRAND__={};</script>",
        serde_json::to_string(&serde_json::json!({
            "name": b.panel_name,
            "logo": b.logo,
            "accent": b.accent,
            "theme": b.theme_default,
        }))
        .unwrap_or_else(|_| "{}".into())
    );
    let favicon = format!(
        "<link rel=\"icon\" type=\"image/svg+xml\" href=\"{}\" />",
        esc(&favicon_href)
    );
    let mut accent_style = String::new();
    if !b.accent.is_empty() {
        // `!important` so it wins over the later light/dark theme blocks.
        accent_style = format!(
            "<style>:root{{--br:{c} !important;--cy:{c} !important;--vio:{c} !important;}}</style>",
            c = b.accent
        );
    }
    // A custom logo image shouldn't sit on the gradient chip background.
    let logo_css = if b.logo.is_empty() {
        ""
    } else {
        "<style>.login-brand .cup,aside .logo .cup{background:transparent !important;box-shadow:none !important;}</style>"
    };
    let head_inject = format!("{global}{favicon}{accent_style}{logo_css}");

    let mark = if b.logo.is_empty() {
        DEFAULT_MARK.to_string()
    } else {
        format!(
            "<img src=\"{}\" alt=\"\" style=\"width:100%;height:100%;object-fit:contain;border-radius:inherit\" />",
            esc(&b.logo)
        )
    };

    tmpl.replace("<!--__DN7_HEAD__-->", &head_inject)
        .replace(
            "<title>DN7 Panel</title>",
            &format!("<title>{name}</title>"),
        )
        .replace("<!--__DN7_BRAND_MARK__-->", &mark)
        .replace("__DN7_BRAND_NAME__", &name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_color_validation() {
        assert!(is_hex_color("#3b82f6"));
        assert!(is_hex_color("#FFFFFF"));
        assert!(!is_hex_color("3b82f6"));
        assert!(!is_hex_color("#3b82f"));
        assert!(!is_hex_color("#xyz123"));
    }

    #[test]
    fn validate_rejects_bad_input() {
        assert!(validate(Some("".into()), None, None, None).is_err());
        assert!(validate(Some("a".repeat(41)), None, None, None).is_err());
        assert!(validate(None, Some("not-a-data-uri".into()), None, None).is_err());
        assert!(validate(None, None, Some("blue".into()), None).is_err());
        assert!(validate(None, None, None, Some("solar".into())).is_err());
    }

    #[test]
    fn validate_normalises_accepted_input() {
        let b = validate(
            Some("  Acme  ".into()),
            Some("data:image/png;base64,AAAA".into()),
            Some("#AABBCC".into()),
            Some("dark".into()),
        )
        .unwrap();
        assert_eq!(b.panel_name, "Acme");
        assert_eq!(b.accent, "#aabbcc");
        assert_eq!(b.theme_default, "dark");
        assert!(b.logo.starts_with("data:image/png"));
    }

    #[test]
    fn render_default_keeps_builtin_mark_and_name() {
        let tmpl = "<title>DN7 Panel</title><!--__DN7_HEAD__--><span><!--__DN7_BRAND_MARK__--></span><h1>__DN7_BRAND_NAME__</h1>";
        let out = render_index(tmpl, &Branding::default());
        assert!(out.contains("window.__BRAND__"));
        assert!(out.contains("<svg")); // built-in mark
        assert!(out.contains(">DN7 Panel</h1>"));
        assert!(!out.contains("__DN7_BRAND_NAME__"));
        assert!(out.contains(DEFAULT_FAVICON));
    }

    #[test]
    fn render_custom_injects_logo_accent_and_escapes_name() {
        let b = Branding {
            panel_name: "<Acme>".into(),
            logo: "data:image/png;base64,ZZ".into(),
            accent: "#ff0000".into(),
            theme_default: "light".into(),
        };
        let tmpl = "<title>DN7 Panel</title><!--__DN7_HEAD__--><span><!--__DN7_BRAND_MARK__--></span><h1>__DN7_BRAND_NAME__</h1>";
        let out = render_index(tmpl, &b);
        assert!(out.contains("&lt;Acme&gt;")); // escaped name in markup
        assert!(out.contains("<img src=")); // custom logo mark
        assert!(out.contains("--br:#ff0000")); // accent override
        assert!(out.contains("background:transparent")); // logo chip bg reset
        assert!(out.contains("data:image/png;base64,ZZ")); // favicon = logo
    }
}
