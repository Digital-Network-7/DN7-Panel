//! TOTP two-factor auth (RFC 6238) — pure Rust, musl-safe.
//!
//! A per-account base32 secret is generated at enrollment; the client shows it
//! as a QR (otpauth:// URI rendered to SVG) and as the raw string, then must
//! prove possession by entering a live code before 2FA is bound. Login then
//! requires a current code in addition to the password.

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

const STEP: u64 = 30; // seconds per TOTP window
const DIGITS: u32 = 6;
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generate a fresh random base32 secret (20 bytes → 32 base32 chars).
pub fn gen_secret() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32).map(|_| B32[rng.gen_range(0..32)] as char).collect()
}

/// Decode a base32 secret (RFC 4648, no padding, case-insensitive) to bytes.
fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let up = c.to_ascii_uppercase() as u8;
        let v = B32.iter().position(|&b| b == up)? as u32;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}

/// Current unix time in seconds.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compute the HOTP/TOTP code for a given counter.
fn hotp(secret: &[u8], counter: u64) -> Option<u32> {
    let mut mac = HmacSha1::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    let off = (tag[19] & 0x0f) as usize;
    let bin = ((tag[off] as u32 & 0x7f) << 24)
        | ((tag[off + 1] as u32) << 16)
        | ((tag[off + 2] as u32) << 8)
        | (tag[off + 3] as u32);
    Some(bin % 10u32.pow(DIGITS))
}

/// Verify a user-entered code against the secret, allowing ±1 step of clock
/// skew. `code` may contain spaces; only the digits matter.
pub fn verify(secret_b32: &str, code: &str) -> bool {
    let code: String = code.chars().filter(|c| c.is_ascii_digit()).collect();
    if code.len() != DIGITS as usize {
        return false;
    }
    let want: u32 = match code.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let secret = match b32_decode(secret_b32) {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    let t = now_secs() / STEP;
    for c in [t.wrapping_sub(1), t, t + 1] {
        if hotp(&secret, c) == Some(want) {
            return true;
        }
    }
    false
}

/// Build the `otpauth://` provisioning URI for authenticator apps.
pub fn provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    let label = pct(&format!("{issuer}:{account}"));
    let iss = pct(issuer);
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={iss}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
    )
}

/// Minimal percent-encoding for the otpauth label/issuer (space + a few chars).
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Render the provisioning URI as an inline SVG QR code.
pub fn qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};
    match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .dark_color(svg::Color("#0e1626"))
            .light_color(svg::Color("#ffffff"))
            .build(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_known_vector() {
        // RFC 6238 test secret "12345678901234567890" (ASCII) in base32.
        let secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let secret = b32_decode(secret_b32).unwrap();
        // T=59 → counter 1 → code 287082 (SHA1, 6 digits).
        assert_eq!(hotp(&secret, 1), Some(287082));
    }

    #[test]
    fn verify_roundtrip() {
        let s = gen_secret();
        let secret = b32_decode(&s).unwrap();
        let t = now_secs() / STEP;
        let code = format!("{:06}", hotp(&secret, t).unwrap());
        assert!(verify(&s, &code));
        assert!(verify(&s, &format!("{} {}", &code[..3], &code[3..]))); // spaces ok
        assert!(!verify(&s, "000000"));
        assert!(!verify(&s, "12345"));
    }

    #[test]
    fn b32_decode_basic() {
        assert_eq!(b32_decode("ME======").unwrap(), b"a");
        assert_eq!(b32_decode("MFRA").unwrap(), b"ab");
    }
}
