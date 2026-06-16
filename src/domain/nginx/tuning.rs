//! Pure nginx tuning / default-site rules: validate a request against fixed
//! bounds and build the persisted entity. No I/O, unit-testable.

use super::*;

/// A nginx tuning / default-site validation failure. A **semantic** value (no
/// transport or frontend `err.*` string — per architecture §2 the domain must
/// not carry protocol content). The app boundary maps each variant to the
/// transitional `ERR_CODE:` channel (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TuningError {
    HashBucket,
    CompLevel,
    MinLength,
    Keepalive,
    SizeValue,
    DefaultMode,
    RedirectUrl,
}

/// Validate a tuning request against fixed bounds and merge it over the current
/// values (any omitted field keeps its current value). Returns the merged
/// entity, or a semantic [`TuningError`]. Pure rule, unit-testable.
pub(crate) fn merge_http_tuning(
    cur: &HttpTuning,
    input: &HttpTuningInput,
) -> Result<HttpTuning, TuningError> {
    let snhbs = input
        .server_names_hash_bucket_size
        .unwrap_or(cur.server_names_hash_bucket_size);
    if ![32u32, 64, 128, 256, 512].contains(&snhbs) {
        return Err(TuningError::HashBucket);
    }
    let gcl = input.gzip_comp_level.unwrap_or(cur.gzip_comp_level);
    if !(1..=9).contains(&gcl) {
        return Err(TuningError::CompLevel);
    }
    let gmin = input.gzip_min_length.unwrap_or(cur.gzip_min_length);
    if gmin > 10_000_000 {
        return Err(TuningError::MinLength);
    }
    let kat = input.keepalive_timeout.unwrap_or(cur.keepalive_timeout);
    if kat > 86_400 {
        return Err(TuningError::Keepalive);
    }
    let chdr = input
        .client_header_buffer_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_header_buffer_size)
        .to_string();
    let cmbs = input
        .client_max_body_size
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&cur.client_max_body_size)
        .to_string();
    if !valid_size_value(&chdr) || !valid_size_value(&cmbs) {
        return Err(TuningError::SizeValue);
    }
    Ok(HttpTuning {
        server_names_hash_bucket_size: snhbs,
        gzip: input.gzip.unwrap_or(cur.gzip),
        client_header_buffer_size: chdr,
        gzip_min_length: gmin,
        client_max_body_size: cmbs,
        gzip_comp_level: gcl,
        keepalive_timeout: kat,
    })
}

/// Validate a default-site (catch-all) request and build the persisted entity.
/// `mode` must be one of `404`/`welcome`/`444`/`redirect`; a `redirect` mode
/// requires a valid http(s) URL. Returns a semantic [`TuningError`] on failure.
/// Pure rule.
pub(crate) fn build_default_site(
    mode_input: &str,
    redirect_url_input: &str,
) -> Result<WebGlobal, TuningError> {
    let mode = match mode_input {
        m @ ("404" | "welcome" | "444" | "redirect") => m.to_string(),
        _ => return Err(TuningError::DefaultMode),
    };
    let redirect_url = redirect_url_input.trim().to_string();
    if mode == "redirect" && !valid_redirect_url(&redirect_url) {
        return Err(TuningError::RedirectUrl);
    }
    Ok(WebGlobal {
        default_site: DefaultSite { mode, redirect_url },
    })
}

#[cfg(test)]
mod tuning_tests {
    use super::*;

    #[test]
    fn merge_keeps_current_when_omitted() {
        let cur = HttpTuning::default();
        let merged = merge_http_tuning(&cur, &HttpTuningInput::default()).unwrap();
        assert_eq!(
            merged.server_names_hash_bucket_size,
            cur.server_names_hash_bucket_size
        );
        assert_eq!(merged.keepalive_timeout, cur.keepalive_timeout);
        assert_eq!(merged.client_max_body_size, cur.client_max_body_size);
    }

    #[test]
    fn merge_rejects_out_of_bounds() {
        let cur = HttpTuning::default();
        let bad_bucket = HttpTuningInput {
            server_names_hash_bucket_size: Some(100),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_bucket).unwrap_err(),
            TuningError::HashBucket
        );
        let bad_level = HttpTuningInput {
            gzip_comp_level: Some(10),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_level).unwrap_err(),
            TuningError::CompLevel
        );
        let bad_size = HttpTuningInput {
            client_max_body_size: Some("50x".to_string()),
            ..Default::default()
        };
        assert_eq!(
            merge_http_tuning(&cur, &bad_size).unwrap_err(),
            TuningError::SizeValue
        );
    }

    #[test]
    fn merge_accepts_valid_override() {
        let cur = HttpTuning::default();
        let input = HttpTuningInput {
            server_names_hash_bucket_size: Some(128),
            gzip_comp_level: Some(6),
            client_max_body_size: Some("100m".to_string()),
            keepalive_timeout: Some(75),
            ..Default::default()
        };
        let merged = merge_http_tuning(&cur, &input).unwrap();
        assert_eq!(merged.server_names_hash_bucket_size, 128);
        assert_eq!(merged.gzip_comp_level, 6);
        assert_eq!(merged.client_max_body_size, "100m");
        assert_eq!(merged.keepalive_timeout, 75);
    }

    #[test]
    fn redirect_url_validation() {
        assert!(valid_redirect_url("https://example.com/path"));
        assert!(valid_redirect_url("http://a.test"));
        assert!(!valid_redirect_url("ftp://x"));
        assert!(!valid_redirect_url("https://a b.com"));
        assert!(!valid_redirect_url("javascript:alert(1)"));
    }

    #[test]
    fn default_site_rules() {
        assert!(build_default_site("bogus", "").is_err());
        assert!(build_default_site("welcome", "").is_ok());
        assert_eq!(
            build_default_site("redirect", "not-a-url").unwrap_err(),
            TuningError::RedirectUrl
        );
        let g = build_default_site("redirect", " https://x.test ").unwrap();
        assert_eq!(g.default_site.mode, "redirect");
        assert_eq!(g.default_site.redirect_url, "https://x.test");
    }
}
