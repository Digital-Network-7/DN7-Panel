//! Certificate auto-renewal + renewal scheduler (split from sites.rs).
use super::*;

/// Days from `date` ("YYYY-MM-DD") until today (negative once past).
pub(crate) fn days_until(date: &str) -> Option<i64> {
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    // Howard Hinnant's days_from_civil (days since 1970-01-01).
    let yy = if m <= 2 { y - 1 } else { y };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let target = era * 146097 + doe - 719468;
    let now = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs()
        / 86400) as i64;
    Some(target - now)
}

/// True if the cert PEM at `path` exists, parses, and is within `within_days`
/// of expiry. A missing/unparseable cert returns false so we never hammer
/// Let's Encrypt for a cert that was never successfully issued.
pub(crate) fn cert_due(path: &std::path::Path, within_days: i64) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|p| cert_not_after(&p))
        .and_then(|date| days_until(&date))
        .map(|n| n < within_days)
        .unwrap_or(false)
}

/// Renew per-site and standalone Let's Encrypt / self-signed certificates that
/// are near expiry. Manual certs are user-supplied and never auto-renewed.
pub async fn renew_due_certs() {
    if !is_setup() {
        return;
    }
    let lo = match layout() {
        Ok(l) => l,
        Err(_) => return,
    };
    const WITHIN: i64 = 30; // LE certs last 90d; renew comfortably before expiry.
    renew_due_site_certs(&lo, WITHIN).await;
    renew_due_named_certs(&lo, WITHIN).await;
}

/// Auto-renew per-site certs (LE reissue / self-signed regenerate) that expire
/// within `within` days. Named-cert and manual sites are skipped here.
pub(crate) async fn renew_due_site_certs(lo: &Layout, within: i64) {
    for site in load_sites() {
        if !site.ssl || !site.cert_name.is_empty() {
            continue; // named certs handled separately; manual isn't auto-renewed
        }
        let crt = lo.cert_store.join(format!("{}.crt", site.id));
        if !cert_due(&crt, within) {
            continue;
        }
        match site.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&site.server_name));
                match issue_le(&op_id, lo, &site).await {
                    Ok(()) => {
                        op_finish(&op_id, "done", "");
                        tracing::info!(site = %site.server_name, "auto-renewed Let's Encrypt certificate");
                    }
                    Err(e) => {
                        op_finish(&op_id, "error", &e.to_string());
                        tracing::warn!(site = %site.server_name, "cert auto-renew failed: {e}");
                    }
                }
            }
            "self" => {
                if gen_self_signed(lo, &site).await.is_ok() {
                    let _ = write_site_conf(lo, &site, &[]).await;
                    let _ = validate_and_reload(lo).await;
                }
            }
            _ => {}
        }
    }
}

/// Auto-renew standalone named certs that expire within `within` days. Sites
/// reference these cert files directly, so nginx is reloaded after each renewal.
pub(crate) async fn renew_due_named_certs(lo: &Layout, within: i64) {
    for c in load_named_certs() {
        if c.domain.is_empty() {
            continue;
        }
        let crt = named_crt_file(lo, &c.name);
        if !cert_due(&crt, within) {
            continue;
        }
        match c.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&c.domain));
                match issue_le_named(&op_id, lo, &c.name, &c.domain).await {
                    Ok(()) => op_finish(&op_id, "done", ""),
                    Err(e) => op_finish(&op_id, "error", &e.to_string()),
                }
            }
            "self" => {
                let host = primary_host(&c.domain);
                let _ = gen_self_signed_to(
                    &named_crt_file(lo, &c.name),
                    &named_key_file(lo, &c.name),
                    &host,
                )
                .await;
            }
            _ => continue,
        }
        let _ = validate_and_reload(lo).await;
    }
}

/// Background loop: renew certs nearing expiry. First pass ~10 min after start,
/// then daily — so a 90-day Let's Encrypt cert renews well before it lapses.
pub fn spawn_cert_renewal() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        loop {
            renew_due_certs().await;
            tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
        }
    });
}
