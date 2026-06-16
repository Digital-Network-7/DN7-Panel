//! Minimal X.509 expiry parsing for the Nginx cert library.
//!
//! We ship only `rcgen` + `instant-acme` (no `x509-parser`), so this walks the
//! DER just far enough to read the certificate's `notAfter` date. Best-effort:
//! returns `None` when the structure isn't as expected.

/// Parse a PEM cert's notAfter (expiry) as a "YYYY-MM-DD" string.
pub(crate) fn cert_not_after(pem: &str) -> Option<String> {
    let der = pem_first_cert_der(pem)?;
    parse_not_after(&der)
}

/// Extract DER bytes of the first PEM "CERTIFICATE" block.
fn pem_first_cert_der(pem: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin)? + begin.len();
    let stop = pem[start..].find(end)? + start;
    let b64: String = pem[start..stop].split_whitespace().collect();
    base64_decode(&b64)
}

/// Minimal base64 decoder (standard alphabet) for the cert body.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = val(c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Walk the DER of an X.509 cert to the Validity.notAfter time and format it as
/// "YYYY-MM-DD". Best-effort; returns None if the structure isn't as expected.
fn parse_not_after(der: &[u8]) -> Option<String> {
    // Find the first UTCTime (0x17) or GeneralizedTime (0x18) that looks like a
    // validity date. The Validity sequence holds notBefore then notAfter, so we
    // take the SECOND such time value.
    let mut times = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() {
        let tag = der[i];
        if tag == 0x17 || tag == 0x18 {
            let len = der[i + 1] as usize;
            if len > 0 && len < 40 && i + 2 + len <= der.len() {
                if let Ok(s) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                    times.push((tag, s.to_string()));
                }
                i += 2 + len;
                continue;
            }
        }
        i += 1;
    }
    let (tag, val) = times.get(1).or_else(|| times.first())?;
    // UTCTime: YYMMDDHHMMSSZ ; GeneralizedTime: YYYYMMDDHHMMSSZ
    let (yyyy, rest) = if *tag == 0x17 {
        // YY -> 20YY (certs are well past 2000).
        let yy: i32 = val.get(0..2)?.parse().ok()?;
        let full = if yy < 50 { 2000 + yy } else { 1900 + yy };
        (full, &val[2..])
    } else {
        let y: i32 = val.get(0..4)?.parse().ok()?;
        (y, &val[4..])
    };
    let mm = rest.get(0..2)?;
    let dd = rest.get(2..4)?;
    Some(format!("{yyyy}-{mm}-{dd}"))
}
