//! The panel control channel: a minimal pure-std loopback HTTP/1.1 client that
//! reads the root-only CLI token (`<data>/cli.token`) and talks to the console on
//! `127.0.0.1:CONSOLE_LOOPBACK_PORT` with `Authorization: Bearer <token>`. The
//! panel accepts that token as the super-admin owner on a direct loopback hit, so
//! the CLI drives the SAME API the web console uses — no login, no HTTP crate.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use dn7_edge::CONSOLE_LOOPBACK_PORT;

use crate::common::data_dir;

pub struct Resp {
    pub status: u16,
    pub body: String,
}

impl Resp {
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
    /// The `data` payload — the API wraps successful responses as `{ok, data}`;
    /// falls back to the whole body when there's no envelope.
    pub fn data(&self) -> serde_json::Value {
        let v = self.json().unwrap_or_default();
        v.get("data").cloned().unwrap_or(v)
    }
    pub fn is_ok(&self) -> bool {
        if !(200..300).contains(&self.status) {
            return false;
        }
        // The console API returns HTTP 200 with `{ok:false, error:...}` for
        // logical errors — honor the body's `ok` flag, not just the status.
        match self.json() {
            Some(v) => v.get("ok").and_then(|x| x.as_bool()) != Some(false),
            None => true,
        }
    }
    /// A human-readable error for a failed response: the API's `msg`/`error`/`code`
    /// field, translated to a friendly bilingual string for known codes.
    pub fn err_text(&self) -> String {
        self.json()
            .and_then(|v| {
                v.get("msg")
                    .or_else(|| v.get("error"))
                    .or_else(|| v.get("code"))
                    .and_then(|m| m.as_str())
                    .map(friendly)
            })
            .unwrap_or_else(|| self.body.trim().to_string())
    }
    /// Whether the (HTTP-200) error body carries a specific wire error `code`.
    pub fn has_code(&self, code: &str) -> bool {
        self.json()
            .map(|v| {
                [v.get("code"), v.get("error")]
                    .iter()
                    .flatten()
                    .filter_map(|x| x.as_str())
                    .any(|c| c == code)
            })
            .unwrap_or(false)
    }
}

/// Friendly bilingual text for known wire error codes (falls back to the raw code).
fn friendly(code: &str) -> String {
    let m = match code {
        "website.not_setup" => "网站子系统未初始化 / website not set up (try `dn7 site setup`)",
        "website.duplicate_domain" => "域名已存在 / domain already in use",
        "website.need_domain" => "缺少域名 / a domain is required",
        "website.bad_domain" => "域名无效 / invalid domain",
        "website.need_target" => "缺少上游目标 / upstream target required",
        "website.bad_target" => "上游目标无效 / invalid upstream target",
        "website.unknown_site_kind" => "未知站点类型 / unknown site kind",
        "website.site_not_found" => "站点不存在 / no such site",
        "website.missing_site_id" => "缺少站点 ID / missing site id",
        "website.need_cert_domain" => "缺少证书域名 / cert domain required",
        "website.missing_cert_name" => "缺少证书名 / cert name required",
        "website.cert_not_found" => "证书不存在 / no such certificate",
        "website.cert_domain_exists" => "该域名证书已存在 / a cert for this domain exists",
        "website.need_cert_key" => "缺少证书或私钥 / certificate and key required",
        "website.unknown_cert_mode" => "未知证书模式 / unknown cert mode",
        "website.need_root" => "需要 root / requires root",
        _ => return code.to_string(),
    };
    m.to_string()
}

/// Read the CLI control token (root-only). None if the panel hasn't created it
/// (not initialized / never run).
pub fn token() -> Option<String> {
    let t = std::fs::read_to_string(data_dir().join("cli.token")).ok()?;
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

/// POST `/api/website` with `{ op, ...extra }` — the website/edge/cert capability.
pub fn website(op: &str, extra: serde_json::Value) -> Result<Resp, String> {
    let mut body = if extra.is_object() {
        extra
    } else {
        serde_json::json!({})
    };
    body["op"] = serde_json::Value::String(op.to_string());
    api("POST", "/api/website", Some(&body))
}

/// Run a mutating website op, auto-initializing the subsystem on first use: the
/// site/cert mutations gate on `setup` and return `website.not_setup` until it
/// has run (and the read ops can't be used to probe — `list_sites` doesn't gate).
/// So we try, run `setup` on a `not_setup` reply, and retry until it takes.
pub fn website_setup_aware(op: &str, extra: serde_json::Value) -> Result<Resp, String> {
    let r = website(op, extra.clone())?;
    if r.is_ok() || !r.has_code("website.not_setup") {
        return Ok(r);
    }
    println!("  · 首次使用,正在初始化网站子系统 / first use: initializing website subsystem…");
    // Surface a logical setup failure (e.g. need_root) right away instead of
    // masking it behind the poll timeout below.
    let setup = website("setup", serde_json::json!({}))?;
    if !setup.is_ok() {
        return Ok(setup);
    }
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let retry = website(op, extra.clone())?;
        if retry.is_ok() || !retry.has_code("website.not_setup") {
            return Ok(retry);
        }
    }
    Err("网站子系统初始化超时 / website setup timed out".into())
}

/// The op_id of a currently-RUNNING cert issuance for `domain`'s primary host, if
/// any. Lets the CLI avoid starting a SECOND ACME order for a host that already
/// has one in flight — the server records the cert only when its detached
/// issuance finishes, so the server-side dup guard can't see an in-flight one.
/// Best-effort (a convenience guard, not a hard lock): on any error it returns
/// None and the caller proceeds.
pub fn running_cert_op(domain: &str) -> Option<String> {
    let host = domain.split_whitespace().next()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let r = website("list_ops", serde_json::json!({})).ok()?;
    if !r.is_ok() {
        return None;
    }
    find_running_cert_op(&r.data(), &host)
}

/// Pure core of [`running_cert_op`]: scan an ops snapshot for a running `cert` op
/// whose `target` matches `host` (case-insensitive), returning its `op_id`.
fn find_running_cert_op(data: &serde_json::Value, host: &str) -> Option<String> {
    data.get("ops")?
        .as_array()?
        .iter()
        .find_map(|op| {
            let matches = op.get("kind").and_then(|k| k.as_str()) == Some("cert")
                && op.get("status").and_then(|s| s.as_str()) == Some("running")
                && op
                    .get("target")
                    .and_then(|t| t.as_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref()
                    == Some(host);
            matches.then(|| {
                op.get("op_id")
                    .and_then(|i| i.as_str())
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .filter(|s| !s.is_empty())
}

/// Run an API call and reduce it to ok-or-message for a simple action.
pub fn act(call: Result<Resp, String>, done_zh: &str, done_en: &str) -> i32 {
    match call {
        Ok(r) if r.is_ok() => {
            crate::common::ok(done_zh, done_en);
            0
        }
        Ok(r) => {
            crate::common::warn(
                &format!("失败:{}", r.err_text()),
                &format!("failed: {}", r.err_text()),
            );
            1
        }
        Err(e) => {
            eprintln!("dn7: {e}");
            1
        }
    }
}

/// Poll a detached website op (e.g. LE cert issuance) to completion, printing new
/// progress lines as they appear. Ok on `done`; Err on `error`/`gone`/timeout.
pub fn wait_for_op(op_id: &str) -> Result<(), String> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let mut shown = 0usize;
    loop {
        let r = website("op_log", serde_json::json!({ "op_id": op_id }))?;
        if !r.is_ok() {
            return Err(r.err_text());
        }
        let d = r.data();
        if let Some(lines) = d.get("lines").and_then(|l| l.as_array()) {
            // The server caps the log at 400 lines (older ones drop), so `lines`
            // is a sliding window, not strictly append-only; clamp the cursor so a
            // shrink can't make us skip past the end. (The curated cert/LE flows
            // emit far fewer than 400 lines, so this is just a safety guard.)
            let n = lines.len();
            for line in lines.iter().skip(shown.min(n)).filter_map(|x| x.as_str()) {
                println!("    {}", clean_op_line(line));
            }
            shown = n;
        }
        match d.get("status").and_then(|s| s.as_str()).unwrap_or("") {
            "done" => return Ok(()),
            "error" => {
                return Err(d
                    .get("error")
                    .and_then(|e| e.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("operation failed")
                    .to_string())
            }
            "gone" => {
                return Err("操作记录已丢失,结果未知 / op record gone (result unknown)".into())
            }
            _ => {}
        }
        if start.elapsed() > Duration::from_secs(300) {
            return Err("等待超时 / timed out".into());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Strip the localized-message sentinel (`\x1eMSG\x1e<code>[\x1e<arg>…]`) from an
/// op-log line for plain CLI display.
fn clean_op_line(s: &str) -> String {
    match s.strip_prefix("\u{1e}MSG\u{1e}") {
        Some(rest) => rest.replace('\u{1e}', " "),
        None => s.to_string(),
    }
}

/// Send `method path` (+ optional JSON body) to the console API.
pub fn api(method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<Resp, String> {
    let tok = token().ok_or(
        "找不到 CLI 控制令牌(面板未初始化或未运行?)/ CLI control token not found \
         (is the panel initialized + running?)",
    )?;
    let mut stream = TcpStream::connect(("127.0.0.1", CONSOLE_LOOPBACK_PORT))
        .map_err(|e| format!("连接控制台失败 / cannot reach the console: {e} (面板在运行吗?)"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));

    let body_bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Authorization: Bearer {tok}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n"
    );
    if body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_bytes.len()
        ));
    }
    req.push_str("\r\n");
    req.push_str(&body_bytes);

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("写请求失败 / write failed: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("读响应失败 / read failed: {e}"))?;
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<Resp, String> {
    // Split head/body on the first CRLFCRLF in the RAW bytes — keep the body
    // byte-exact so de-chunking can slice by the wire byte counts; UTF-8 is then
    // decoded once at the end (slicing a lossily-decoded &str by chunk byte sizes
    // can land mid-character and panic, and this CLI carries non-ASCII content).
    let sep = find_subslice(raw, b"\r\n\r\n").ok_or("响应不完整 / malformed response")?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = &raw[sep + 4..];
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("无法解析状态行 / bad status line")?;
    // axum buffers JSON with Content-Length, but de-chunk defensively in case a
    // response uses chunked transfer-encoding.
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    Ok(Resp {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// De-chunk a `Transfer-Encoding: chunked` body on RAW bytes (chunk sizes are
/// byte lengths, so byte-slicing can't split a UTF-8 character).
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(nl) = find_subslice(rest, b"\r\n") {
        let size = std::str::from_utf8(&rest[..nl])
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
            .unwrap_or(0);
        let after = &rest[nl + 2..];
        if size == 0 || after.len() < size {
            break;
        }
        out.extend_from_slice(&after[..size]);
        rest = after[size..]
            .strip_prefix(b"\r\n")
            .unwrap_or(&after[size..]);
    }
    out
}

/// First index of `needle` in `hay`, if any.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Resp {
        Resp {
            status,
            body: body.to_string(),
        }
    }

    #[test]
    fn parse_response_splits_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "{\"ok\":true}");
    }

    #[test]
    fn parse_response_rejects_garbage() {
        assert!(parse_response(b"no-header-terminator").is_err());
    }

    #[test]
    fn dechunk_reassembles_chunks() {
        assert_eq!(
            dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
            b"Wikipedia".to_vec()
        );
    }

    #[test]
    fn dechunk_survives_multibyte_split_across_chunks() {
        // "错误" is e9 94 99 e8 af af; split so a char boundary falls INSIDE a chunk.
        // The old &str-slicing dechunk panicked here; the byte version must not.
        let raw = b"2\r\n\xe9\x94\r\n4\r\n\x99\xe8\xaf\xaf\r\n0\r\n\r\n";
        assert_eq!(String::from_utf8(dechunk(raw)).unwrap(), "错误");
    }

    #[test]
    fn parse_response_dechunks_when_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().body, "abc");
    }

    #[test]
    fn is_ok_honors_the_body_ok_flag_not_just_status() {
        assert!(resp(200, "{\"ok\":true,\"data\":{}}").is_ok());
        assert!(!resp(200, "{\"ok\":false,\"error\":\"website.not_setup\"}").is_ok());
        assert!(!resp(401, "{\"ok\":false}").is_ok());
        assert!(resp(200, "not json").is_ok()); // non-JSON 2xx → ok
        assert!(resp(204, "").is_ok());
    }

    #[test]
    fn data_unwraps_the_envelope_or_falls_back() {
        let r = resp(200, "{\"ok\":true,\"data\":{\"sites\":[1,2]}}");
        assert_eq!(r.data().get("sites").unwrap().as_array().unwrap().len(), 2);
        let bare = resp(200, "{\"sites\":[]}");
        assert!(bare.data().get("sites").is_some());
    }

    #[test]
    fn has_code_checks_code_and_error_fields() {
        let r = resp(
            200,
            "{\"ok\":false,\"code\":\"website.not_setup\",\"error\":\"website.not_setup\"}",
        );
        assert!(r.has_code("website.not_setup"));
        assert!(!r.has_code("website.duplicate_domain"));
    }

    #[test]
    fn err_text_translates_known_codes_passes_through_unknown() {
        assert!(
            resp(200, "{\"ok\":false,\"error\":\"website.duplicate_domain\"}")
                .err_text()
                .contains("domain already in use")
        );
        assert_eq!(
            resp(200, "{\"ok\":false,\"error\":\"website.some_future_code\"}").err_text(),
            "website.some_future_code"
        );
    }

    #[test]
    fn find_running_cert_op_matches_only_running_cert_for_host() {
        let ops = serde_json::json!({ "ops": [
            { "op_id": "nop1", "kind": "cert", "status": "done",    "target": "a.com" },
            { "op_id": "nop2", "kind": "cert", "status": "running", "target": "a.com" },
            { "op_id": "nop3", "kind": "cert", "status": "running", "target": "b.com" },
            { "op_id": "nop4", "kind": "backup", "status": "running", "target": "a.com" },
            { "op_id": "nop5", "kind": "cert", "status": "running", "target": "UP.com" },
        ]});
        assert_eq!(find_running_cert_op(&ops, "a.com").as_deref(), Some("nop2"));
        assert_eq!(find_running_cert_op(&ops, "b.com").as_deref(), Some("nop3"));
        assert_eq!(
            find_running_cert_op(&ops, "up.com").as_deref(),
            Some("nop5")
        ); // target lowercased
        assert_eq!(find_running_cert_op(&ops, "c.com"), None); // no op for host
        assert_eq!(find_running_cert_op(&serde_json::json!({}), "a.com"), None);
        // no ops key
    }
}
