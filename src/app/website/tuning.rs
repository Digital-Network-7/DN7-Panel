//! Website settings/tuning use-cases: project the persisted website settings, and
//! validate+apply http/server tuning and the default-site catch-all. Pure
//! validation lives in `core::website`; persistence + edge route rebuild + reload
//! are delegated to the `infra::website` adapter.

use anyhow::Result;
use serde_json::{json, Value};

/// `get_settings` use-case: project the persisted website-settings state
/// (default-site behaviour + http/server tuning + configured flags) into the
/// console response. Orchestration lives here; the raw read is delegated to the
/// `infra::website` adapter.
pub(crate) fn get_settings() -> Result<Value> {
    let (g, t, configured, tuning_configured) = crate::infra::website::web_settings_state();
    Ok(json!({
        "default_site": { "mode": g.default_site.mode, "redirect_url": g.default_site.redirect_url },
        "configured": configured,
        "tuning": {
            "server_names_hash_bucket_size": t.server_names_hash_bucket_size,
            "gzip": t.gzip,
            "client_header_buffer_size": t.client_header_buffer_size,
            "gzip_min_length": t.gzip_min_length,
            "client_max_body_size": t.client_max_body_size,
            "gzip_comp_level": t.gzip_comp_level,
            "keepalive_timeout": t.keepalive_timeout,
        },
        "tuning_configured": tuning_configured,
    }))
}

/// `set_tuning` use-case: read current tuning (infra) → validate/merge against
/// fixed bounds (domain) → persist + rewrite confs + reload (infra). The stable
/// validation code is surfaced through the transitional `ERR_CODE:` channel.
pub(crate) async fn set_tuning(body: &Value) -> Result<Value> {
    let input = crate::core::website::HttpTuningInput {
        server_names_hash_bucket_size: body
            .get("server_names_hash_bucket_size")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        gzip: body.get("gzip").and_then(|v| v.as_bool()),
        client_header_buffer_size: body
            .get("client_header_buffer_size")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        gzip_min_length: body
            .get("gzip_min_length")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        client_max_body_size: body
            .get("client_max_body_size")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        gzip_comp_level: body
            .get("gzip_comp_level")
            .and_then(|v| v.as_u64())
            .map(|n| n as u8),
        keepalive_timeout: body
            .get("keepalive_timeout")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
    };
    let cur = crate::infra::website::current_tuning();
    let t = crate::core::website::merge_http_tuning(&cur, &input)
        .map_err(|e| anyhow::anyhow!("ERR_CODE:{}", tuning_err_code(e)))?;
    crate::infra::website::apply_tuning(&t).await
}

/// `set_default_site` use-case: validate + build the default-site entity
/// (domain) → persist + (re)write catch-all conf + reload/rollback (infra).
pub(crate) async fn set_default_site(body: &Value) -> Result<Value> {
    let mode = body
        .get("default_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("404");
    let redirect_url = body
        .get("redirect_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let g = crate::core::website::build_default_site(mode, redirect_url)
        .map_err(|e| anyhow::anyhow!("ERR_CODE:{}", tuning_err_code(e)))?;
    crate::infra::website::apply_default_site(&g).await
}

/// Map a domain [`crate::core::website::TuningError`] to its stable frontend
/// `err.*` code, surfaced through the transitional `ERR_CODE:` channel
/// (architecture §6). This is the single place the website tuning/default-site
/// codes are spelled out; the domain stays free of protocol strings (§2).
fn tuning_err_code(e: crate::core::website::TuningError) -> &'static str {
    use crate::core::website::TuningError::*;
    match e {
        HashBucket => "website.bad_hash_bucket",
        CompLevel => "website.bad_comp_level",
        MinLength => "website.bad_min_length",
        Keepalive => "website.bad_keepalive",
        SizeValue => "website.bad_size_value",
        DefaultMode => "website.bad_default_mode",
        RedirectUrl => "website.bad_redirect_url",
    }
}
