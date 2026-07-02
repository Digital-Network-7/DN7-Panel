//! ACME HTTP-01 protocol dance (account/order/challenge/finalize) (split from certs.rs).
use super::*;

/// The ACME HTTP-01 issuance dance for `host`. Creates the account and order,
/// hands the `(token, keyAuthorization)` pairs to `serve` (which makes them
/// reachable at `http://host/.well-known/acme-challenge/<token>` — by
/// registering them in the edge server's in-memory challenge map), then tells
/// Let's Encrypt to validate, finalizes, and returns the issued
/// `(chain_pem, key_pem)`.
pub(crate) async fn acme_http01<F, Fut>(
    op_id: &str,
    host: &str,
    key_type: &str,
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
    // over localhost:80 with the right Host header. If the built-in edge isn't the
    // one answering (a foreign vhost is shadowing it, or the route isn't served),
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
                break acme_issue_cert(&mut order, host, key_type).await?;
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
                    return Err(website_err(WebsiteError::LeVerifyTimeout));
                }
            }
        }
    };

    Ok((cert_chain_pem, key_pem))
}

/// Collect the HTTP-01 challenge `(token, key_authorization)` pairs to serve and
/// the challenge URLs to mark ready, for every pending authorization on `order`.
pub(crate) async fn acme_collect_http01(
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
            .ok_or_else(|| website_err(WebsiteError::LeNoHttp01))?;
        let key_auth = order.key_authorization(challenge);
        to_serve.push((challenge.token.clone(), key_auth.as_str().to_string()));
        ready_urls.push(challenge.url.clone());
    }
    Ok((to_serve, ready_urls))
}

/// Once an order is Ready: generate a keypair + CSR, finalize, and download the
/// issued chain. Returns (cert_chain_pem, key_pem).
pub(crate) async fn acme_issue_cert(
    order: &mut instant_acme::Order,
    host: &str,
    key_type: &str,
) -> Result<(String, String)> {
    let key_pair = rcgen::KeyPair::generate_for(super::issue::key_alg(key_type))
        .map_err(|e| anyhow!("生成私钥失败：{e}"))?;
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
/// will hit. A 404/mismatch here means a foreign server (e.g. a non-panel nginx
/// vhost) is shadowing the domain, or the route isn't served — fail with an
/// actionable message rather than burning a real validation attempt.
pub(crate) async fn self_check_challenge(host: &str, token: &str, expected: &str) -> Result<()> {
    let url = format!("http://127.0.0.1/.well-known/acme-challenge/{token}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|e| anyhow!("自检客户端创建失败：{e}"))?;
    // The edge reload is asynchronous; retry briefly so we don't false-negative
    // on the route-swap race right after the reload.
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
                    "本机校验未通过（HTTP {code}）：{host} 的 80 端口请求没有命中本面板内置的 Web 服务器。\
                     通常是宿主机上另有一个程序（如系统自带的 Nginx/Apache）抢占了 80 端口，\
                     使校验请求没有到达本面板。请停止/卸载占用 80 端口的其他 Web 服务后重试。",
                    code = status.as_u16()
                );
            }
            Err(e) => {
                last = format!(
                    "无法在本机访问校验路径（{e}）：本面板内置 Web 服务器可能未监听 80 端口，或被本机防火墙拦截。"
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
    Err(website_err(WebsiteError::LeIssueTimeout))
}
