//! Render a QR code to an inline SVG string (no JS lib needed in the browser).

use qrcode::render::svg;
use qrcode::{EcLevel, QrCode};

/// Render `data` as an SVG QR code (black modules on white), sized to `px`.
/// Returns None on encode failure.
pub fn svg(data: &str, px: u32) -> Option<String> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M).ok()?;
    let image = code
        .render::<svg::Color>()
        .min_dimensions(px, px)
        .quiet_zone(true)
        .dark_color(svg::Color("#0b1220"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Some(image)
}
