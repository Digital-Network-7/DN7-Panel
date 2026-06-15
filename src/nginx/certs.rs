//! Certificates: self-signed + Lets Encrypt issuance (split from nginx.rs).
use super::*;

// Certificates.
// ---------------------------------------------------------------------------

/// Write user-supplied cert + key to the cert store (manual mode).
pub(crate) fn write_cert_files(
    lo: &Layout,
    site: &Site,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(lo.cert_store.join(format!("{}.crt", site.id)), cert_pem)?;
    write_key_file(&lo.cert_store.join(format!("{}.key", site.id)), key_pem)?;
    Ok(())
}

/// Write a private key file with owner-only (0600) permissions from creation,
/// so it never lands world-readable even briefly (default umask would make a
/// plain `write` 0644). All private-key writes go through here.
pub(crate) fn write_key_file(path: &std::path::Path, pem: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(pem.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, pem)?;
    }
    // `.mode()` only applies on create; chmod covers a pre-existing looser file.
    set_key_perms(path);
    Ok(())
}

/// Generate a self-signed cert/key pair for the site's primary host using
/// pure-Rust `rcgen` (no `openssl` dependency). Writes into the host cert store
/// that the host nginx reads from.
pub(crate) async fn gen_self_signed(lo: &Layout, site: &Site) -> Result<()> {
    let host = primary_host(&site.server_name);
    let host = if host == "_" {
        "localhost".to_string()
    } else {
        host
    };
    let crt_path = lo.cert_store.join(format!("{}.crt", site.id));
    let key_path = lo.cert_store.join(format!("{}.key", site.id));
    gen_self_signed_to(&crt_path, &key_path, &host).await
}

/// Generate a self-signed cert/key pair for `host` and write them to the given
/// paths. Shared by per-site and standalone-named cert generation.
pub(crate) async fn gen_self_signed_to(
    crt_path: &std::path::Path,
    key_path: &std::path::Path,
    host: &str,
) -> Result<()> {
    if let Some(dir) = crt_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let host = if host.is_empty() || host == "_" {
        "localhost".to_string()
    } else {
        host.to_string()
    };

    let mut params = rcgen::CertificateParams::new(vec![host.clone()])
        .map_err(|e| anyhow!("生成证书参数失败：{e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.clone());
    // 10-year validity (self-signed; the browser will warn regardless).
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(3650 * 24 * 3600)).into();

    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| anyhow!("签发自签证书失败：{e}"))?;

    std::fs::write(crt_path, cert.pem())?;
    write_key_file(key_path, &key_pair.serialize_pem())?;
    Ok(())
}

/// Best-effort: restrict a private key file to owner-only (0600).
pub(crate) fn set_key_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Issue a Let's Encrypt cert via the ACME HTTP-01 challenge, detached. The flow:
///   1. serve the challenge inline from an HTTP conf for the domain,
///   2. run the ACME order + validation,
///   3. install the issued cert into our cert store,
///   4. rewrite the conf with SSL and reload.
pub(crate) async fn start_cert_issue(lo: Layout, site: Site) -> Result<Value> {
    let op_id = new_op_id();
    let target = primary_host(&site.server_name);
    op_create(&op_id, "cert", &target);
    let op_id_ret = op_id.clone();
    tokio::spawn(async move {
        match issue_le(&op_id, &lo, &site).await {
            Ok(()) => {
                op_push(&op_id, &pmsg("ng.cert_done_https", &[]));
                op_finish(&op_id, "done", "");
            }
            Err(e) => op_finish(&op_id, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": op_id_ret, "target": target }))
}

pub(crate) async fn issue_le(op_id: &str, lo: &Layout, site: &Site) -> Result<()> {
    let host = primary_host(&site.server_name);
    if host.is_empty() || host == "_" || host.contains('*') {
        return Err(anyhow!("ERR_CODE:nginx.le_need_domain_specific"));
    }

    // Steps 1-5: serve the HTTP-01 challenge inline from the site's HTTP conf
    // (no webroot — so it works regardless of file perms / SELinux), then run
    // the ACME dance. The `serve` callback writes the conf + reloads once the
    // challenge tokens are known.
    op_push(op_id, &pmsg("ng.prep_http", &[]));
    let (cert_chain_pem, key_pem) = {
        let lo2 = lo.clone();
        let mut http_site = site.clone();
        http_site.ssl = false;
        acme_http01(op_id, &host, move |chals| async move {
            write_site_conf(&lo2, &http_site, &chals).await?;
            validate_and_reload(&lo2).await
        })
        .await?
    };

    // Persist the issued chain + key into the certificate library (a named
    // cert), so the cert shows up under SSL certificate management and is
    // covered by the named-cert auto-renewal loop.
    let mut certs = load_named_certs();
    let cert_name = unique_le_cert_name(&certs, &host, &site.id);
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(named_crt_file(lo, &cert_name), cert_chain_pem)?;
    write_key_file(&named_key_file(lo, &cert_name), &key_pem)?;
    certs.retain(|c| c.name != cert_name);
    certs.push(NamedCert {
        name: cert_name.clone(),
        domain: host.clone(),
        cert_mode: "le".to_string(),
    });
    save_named_certs(&certs)?;

    // Point the site at the library cert and rewrite with SSL + reload.
    op_push(op_id, &pmsg("ng.enable_https", &[]));
    attach_named_cert_to_site(lo, site, cert_name).await
}

/// The name to store an LE cert for `host` under: reuse an existing same-domain
/// entry's name, else derive a unique one from the host (falling back to
/// `le-<site_id>` when the host isn't a valid cert-name token).
fn unique_le_cert_name(certs: &[NamedCert], host: &str, site_id: &str) -> String {
    if let Some(c) = certs.iter().find(|c| c.domain.eq_ignore_ascii_case(host)) {
        return c.name.clone();
    }
    let base = if valid_cert_name(host) {
        host.to_string()
    } else {
        format!("le-{site_id}")
    };
    let mut name = base.clone();
    let mut i = 1;
    while certs.iter().any(|c| c.name == name) {
        name = format!("{base}-{i}");
        i += 1;
    }
    name
}

/// Point `site` at a named cert, then rewrite its conf with SSL on, reload, and
/// persist the updated site.
async fn attach_named_cert_to_site(lo: &Layout, site: &Site, cert_name: String) -> Result<()> {
    let mut site = site.clone();
    site.cert_mode = "named".to_string();
    site.cert_name = cert_name;
    write_site_conf(lo, &site, &[]).await?;
    validate_and_reload(lo).await?;
    let mut sites = load_sites();
    sites.retain(|s| s.id != site.id);
    sites.push(site);
    save_sites(&sites)?;
    Ok(())
}

/// Issue a standalone Let's Encrypt cert (detached). Serves the HTTP-01
/// challenge from a temporary HTTP-only conf for `domain`, then writes the
/// issued chain/key into the named cert store and records the manifest.
pub(crate) fn start_named_cert_issue(lo: Layout, name: String, domain: String) -> Result<Value> {
    let op_id = new_op_id();
    let target = primary_host(&domain);
    op_create(&op_id, "cert", &target);
    let op_id_ret = op_id.clone();
    tokio::spawn(async move {
        match issue_le_named(&op_id, &lo, &name, &domain).await {
            Ok(()) => {
                op_push(&op_id, &pmsg("ng.cert_done", &[]));
                op_finish(&op_id, "done", "");
            }
            Err(e) => op_finish(&op_id, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": op_id_ret, "target": target }))
}

pub(crate) async fn issue_le_named(
    op_id: &str,
    lo: &Layout,
    name: &str,
    domain: &str,
) -> Result<()> {
    let host = primary_host(domain);
    if host.is_empty() || host == "_" || host.contains('*') {
        return Err(anyhow!("ERR_CODE:nginx.le_need_domain_specific"));
    }

    // Steps 1-5: serve the HTTP-01 challenge from a temporary conf for this
    // domain (challenges answered inline — no webroot), then run the ACME dance.
    op_push(op_id, &pmsg("ng.prep_http", &[]));
    let conf_id = format!("acme-{name}");
    let conf_file = conf_path(lo, &conf_id);
    let dance = {
        let lo2 = lo.clone();
        let host2 = host.clone();
        let conf_file2 = conf_file.clone();
        acme_http01(op_id, &host, move |chals| async move {
            let conf = format!(
                "server {{\n    listen 80;\n    server_name {host2};\n{loc}\
                 \n    location / {{\n        return 404;\n    }}\n}}\n",
                loc = acme_challenge_locations(&chals)
            );
            std::fs::create_dir_all(&lo2.confd)?;
            std::fs::write(&conf_file2, conf)?;
            validate_and_reload(&lo2).await
        })
        .await
    };

    // Always drop the temporary challenge conf afterwards.
    let _ = std::fs::remove_file(&conf_file);
    let _ = validate_and_reload(lo).await;

    let (cert_chain_pem, key_pem) = dance?;

    // Persist into the named cert store + manifest.
    std::fs::write(named_crt_file(lo, name), cert_chain_pem)?;
    write_key_file(&named_key_file(lo, name), &key_pem)?;
    let mut certs = load_named_certs();
    certs.retain(|c| c.name != name);
    certs.push(NamedCert {
        name: name.to_string(),
        domain: domain.to_string(),
        cert_mode: "le".to_string(),
    });
    save_named_certs(&certs)?;
    Ok(())
}

/// The ACME HTTP-01 issuance dance for `host`. Creates the account and order,
/// hands the `(token, keyAuthorization)` pairs to `serve` (which makes them
/// reachable at `http://host/.well-known/acme-challenge/<token>` — e.g. by
/// writing an nginx conf that answers them inline and reloading), then tells
/// Let's Encrypt to validate, finalizes, and returns the issued
/// `(chain_pem, key_pem)`.
pub(crate) async fn acme_http01<F, Fut>(
    op_id: &str,
    host: &str,
    serve: F,
) -> Result<(String, String)>
where
    F: FnOnce(Vec<(String, String)>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    use instant_acme::{Account, Identifier, NewAccount, NewOrder, OrderStatus};

    // Create (or implicitly register) an ACME account with Let's Encrypt.
    op_push(op_id, &pmsg("ng.le_account", &[]));
    let (account, _creds) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        instant_acme::LetsEncrypt::Production.url(),
        None,
    )
    .await
    .map_err(|e| anyhow!("创建 ACME 账户失败：{e}"))?;

    // Place an order for the domain.
    op_push(op_id, &pmsg("ng.request_cert", &[host]));
    let identifier = Identifier::Dns(host.to_string());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .map_err(|e| anyhow!("创建订单失败：{e}"))?;

    // Collect the HTTP-01 challenge response for each pending authorization.
    let (to_serve, ready_urls) = acme_collect_http01(&mut order).await?;

    // Make the challenge responses reachable over HTTP, then tell LE we're ready.
    serve(to_serve.clone()).await?;

    // Pre-flight on THIS host before involving Let's Encrypt: fetch the challenge
    // over localhost:80 with the right Host header. If our nginx block isn't the
    // one answering (a foreign/own vhost is shadowing it, or conf.d isn't served),
    // this reproduces LE's 404 locally and fails with an actionable message —
    // without consuming a real validation attempt / rate limit.
    if let Some((token, keyauth)) = to_serve.first() {
        self_check_challenge(host, token, keyauth).await?;
    }

    for url in &ready_urls {
        order
            .set_challenge_ready(url)
            .await
            .map_err(|e| anyhow!("提交验证失败：{e}"))?;
    }

    // Poll the order until it's ready (or fails), then finalize.
    op_push(op_id, &pmsg("ng.wait_verify", &[]));
    let mut tries = 0;
    let (cert_chain_pem, key_pem) = loop {
        tokio::time::sleep(std::time::Duration::from_secs(if tries == 0 {
            1
        } else {
            3
        }))
        .await;
        let state = order
            .refresh()
            .await
            .map_err(|e| anyhow!("查询订单状态失败：{e}"))?;
        match state.status {
            OrderStatus::Ready => {
                op_push(op_id, &pmsg("ng.verify_ok", &[]));
                break acme_issue_cert(&mut order, host).await?;
            }
            OrderStatus::Invalid => {
                let detail = acme_failure_detail(&mut order).await;
                let sep = if detail.is_empty() { "" } else { "：" };
                return Err(anyhow!(
                    "域名验证失败{sep}{detail}（请确认 {host} 已解析到本机、公网可访问其 80 端口，且该域名未被其他站点抢先占用）"
                ));
            }
            _ => {
                tries += 1;
                if tries > 40 {
                    return Err(anyhow!("ERR_CODE:nginx.le_verify_timeout"));
                }
            }
        }
    };

    Ok((cert_chain_pem, key_pem))
}

/// Collect the HTTP-01 challenge `(token, key_authorization)` pairs to serve and
/// the challenge URLs to mark ready, for every pending authorization on `order`.
async fn acme_collect_http01(
    order: &mut instant_acme::Order,
) -> Result<(Vec<(String, String)>, Vec<String>)> {
    use instant_acme::{AuthorizationStatus, ChallengeType};
    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| anyhow!("获取授权失败：{e}"))?;
    let mut to_serve: Vec<(String, String)> = Vec::new();
    let mut ready_urls: Vec<String> = Vec::new();
    for authz in &authorizations {
        if !matches!(authz.status, AuthorizationStatus::Pending) {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("ERR_CODE:nginx.le_no_http01"))?;
        let key_auth = order.key_authorization(challenge);
        to_serve.push((challenge.token.clone(), key_auth.as_str().to_string()));
        ready_urls.push(challenge.url.clone());
    }
    Ok((to_serve, ready_urls))
}

/// Once an order is Ready: generate a keypair + CSR, finalize, and download the
/// issued chain. Returns (cert_chain_pem, key_pem).
async fn acme_issue_cert(order: &mut instant_acme::Order, host: &str) -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
    let mut csr_params = rcgen::CertificateParams::new(vec![host.to_string()])
        .map_err(|e| anyhow!("生成 CSR 参数失败：{e}"))?;
    csr_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host.to_string());
    let csr = csr_params
        .serialize_request(&key_pair)
        .map_err(|e| anyhow!("生成 CSR 失败：{e}"))?;
    order
        .finalize(csr.der())
        .await
        .map_err(|e| anyhow!("finalize 失败：{e}"))?;
    let chain = wait_for_cert(order).await?;
    Ok((chain, key_pair.serialize_pem()))
}

/// Pre-flight the HTTP-01 challenge against THIS host (localhost:80, with the
/// domain in the Host header) so we serve the same server block Let's Encrypt
/// will hit. A 404/mismatch here means a non-panel nginx vhost is shadowing the
/// domain (or `conf.d` isn't served) — fail with an actionable message rather
/// than burning a real validation attempt.
pub(crate) async fn self_check_challenge(host: &str, token: &str, expected: &str) -> Result<()> {
    let url = format!("http://127.0.0.1/.well-known/acme-challenge/{token}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| anyhow!("自检客户端创建失败：{e}"))?;
    // nginx reload is asynchronous; retry briefly so we don't false-negative on
    // the worker-swap race right after the reload.
    let mut last = String::new();
    for attempt in 0..4 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        match client
            .get(&url)
            .header(reqwest::header::HOST, host)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if status.is_success() && body.trim() == expected {
                    return Ok(());
                }
                last = format!(
                    "本机校验未通过（HTTP {code}）：{host} 的 80 端口请求没有命中本面板的站点配置。\
                     通常是有另一段非面板管理的 Nginx 配置抢先处理了该域名，或 nginx.conf 未 include /etc/nginx/conf.d。\
                     请执行 `nginx -T | grep -n {host}` 排查重复的 server_name，移除冲突配置后重试。",
                    code = status.as_u16()
                );
            }
            Err(e) => {
                last = format!(
                    "无法在本机访问校验路径（{e}）：Nginx 可能未监听 80 端口，或被本机防火墙拦截。"
                );
            }
        }
    }
    Err(anyhow!("{last}"))
}

/// Best-effort: pull the ACME server's error detail for a failed order so the
/// UI can show *why* validation failed (404, connection refused, DNS, …)
/// instead of a generic message — mirroring NPM/1panel.
pub(crate) async fn acme_failure_detail(order: &mut instant_acme::Order) -> String {
    if let Ok(authzs) = order.authorizations().await {
        for a in &authzs {
            for c in &a.challenges {
                if let Some(err) = &c.error {
                    if let Some(d) = &err.detail {
                        return d.clone();
                    }
                }
            }
        }
    }
    String::new()
}

/// Poll an order's certificate endpoint until the chain PEM is available.
pub(crate) async fn wait_for_cert(order: &mut instant_acme::Order) -> Result<String> {
    for _ in 0..15 {
        match order.certificate().await {
            Ok(Some(pem)) => return Ok(pem),
            Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            Err(e) => return Err(anyhow!("下载证书失败：{e}")),
        }
    }
    Err(anyhow!("ERR_CODE:nginx.le_issue_timeout"))
}
