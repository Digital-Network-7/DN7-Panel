//! Container log tailing + log sanitization.
use super::*;

/// Strip non-text bytes from decoded log output: keep newlines/tabs and any
/// valid printable character (including CJK/emoji), drop control characters and
/// the U+FFFD replacement marker left by invalid UTF-8 — so a binary line (e.g.
/// a raw TLS handshake logged verbatim) becomes harmless short text instead of
/// a wall of escapes / boxes. ANSI SGR (color/style, `ESC [ … m`) sequences pass
/// through intact so the log viewer can render them as real colors; every other
/// escape sequence — cursor movement, screen clears, OSC titles — is dropped
/// whole (previously only the ESC byte was dropped, leaving `[31m` garbage in
/// the text).
pub(crate) fn sanitize_log_keep_sgr(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut kept = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1b}' {
            // CSI sequence: ESC [ <params 0x30–0x3F> <intermediates 0x20–0x2F>
            // <final 0x40–0x7E>. Keep only a plain SGR (digit/`;` params, final
            // `m`); everything else — cursor moves, clears, `?25l` — drops whole.
            if chars.get(i + 1) == Some(&'[') {
                let mut j = i + 2;
                let mut plain = true;
                while j < chars.len() && matches!(chars[j], '\u{30}'..='\u{3f}') {
                    plain &= chars[j].is_ascii_digit() || chars[j] == ';';
                    j += 1;
                }
                while j < chars.len() && matches!(chars[j], '\u{20}'..='\u{2f}') {
                    plain = false;
                    j += 1;
                }
                if plain && chars.get(j) == Some(&'m') {
                    kept.extend(&chars[i..=j]);
                }
                i = if j < chars.len() { j + 1 } else { chars.len() };
                continue;
            }
            // OSC sequence: ESC ] … (BEL | ESC \). Drop it whole.
            if chars.get(i + 1) == Some(&']') {
                let mut j = i + 2;
                while j < chars.len() && chars[j] != '\u{7}' && chars[j] != '\u{1b}' {
                    j += 1;
                }
                i = (j + if chars.get(j) == Some(&'\u{1b}') {
                    2
                } else {
                    1
                })
                .min(chars.len());
                continue;
            }
            // Any other two-byte escape: drop both.
            i = (i + 2).min(chars.len());
            continue;
        }
        if c == '\n' || c == '\r' || c == '\t' || (!c.is_control() && c != '\u{FFFD}') {
            kept.push(c);
        }
        i += 1;
    }
    strip_hex_escapes(&kept)
}

/// Remove literal C-style hex escapes like `\x16\x03\x01…` that some servers
/// (notably web servers) write into their access logs when a client sends raw binary
/// to a text endpoint (e.g. a TLS ClientHello to a plain-HTTP port). They are
/// valid text but render as a wall of noise, so any run of them is collapsed
/// away. Three-digit octal escapes (`\NNN`) emitted by some loggers go too.
pub(crate) fn strip_hex_escapes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        // \xHH (hex byte escape)
        if i + 4 <= chars.len()
            && chars[i] == '\\'
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && chars[i + 2].is_ascii_hexdigit()
            && chars[i + 3].is_ascii_hexdigit()
        {
            i += 4;
            continue;
        }
        // \NNN (3-digit octal byte escape)
        if i + 4 <= chars.len()
            && chars[i] == '\\'
            && ('0'..='7').contains(&chars[i + 1])
            && ('0'..='7').contains(&chars[i + 2])
            && ('0'..='7').contains(&chars[i + 3])
        {
            i += 4;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

pub(crate) async fn container_logs(req: &Req) -> Result<Value> {
    let r = need_ref(req)?;
    let tail = req.tail.unwrap_or(200).clamp(1, 2000);
    let dkr = dkr()?;
    let opts = bollard::container::LogsOptions::<String> {
        stdout: true,
        stderr: true,
        tail: tail.to_string(),
        timestamps: false,
        ..Default::default()
    };
    let mut stream = dkr.logs(&r, Some(opts));
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(out) => bytes.extend_from_slice(&out.into_bytes()),
            Err(e) => {
                // "bytes remaining on stream" and similar end-of-stream framing
                // errors (common with TTY containers / stream teardown) are
                // benign — keep whatever we've already collected.
                let msg = e.to_string();
                if msg.contains("bytes remaining") || !bytes.is_empty() {
                    break;
                }
                return Err(anyhow!(friendly_docker_err(&e)));
            }
        }
    }
    // Decode leniently, then drop non-text bytes so a stray binary line (e.g. a
    // TLS handshake probe logged verbatim) doesn't fill the view with control /
    // replacement characters. Keeps newlines/tabs, all valid (incl. CJK) text,
    // and ANSI SGR color sequences (rendered by the log viewer).
    let mut text = sanitize_log_keep_sgr(&String::from_utf8_lossy(&bytes));
    // If there's no output, a constantly-restarting container is the usual
    // cause. Surface its state + last exit code so the user understands why.
    if text.trim().is_empty() {
        text = empty_logs_hint(&dkr, &r).await;
    }
    Ok(json!({ "logs": text }))
}

/// Build the placeholder text shown when a container produced no log output:
/// its state + last exit code + restart count, plus a hint when it's stuck in a
/// restart loop. Falls back to empty when the container can't be inspected.
async fn empty_logs_hint(dkr: &Docker, r: &str) -> String {
    let Ok(c) = dkr.inspect_container(r, None).await else {
        return String::new();
    };
    let st = c.state.as_ref();
    let status = st
        .and_then(|s| s.status.map(|x| format!("{x:?}").to_lowercase()))
        .unwrap_or_default();
    let exit = st.and_then(|s| s.exit_code).unwrap_or(0);
    let err = st.and_then(|s| s.error.clone()).unwrap_or_default();
    let restarts = c.restart_count.unwrap_or(0);
    let mut hint =
        format!("（容器暂无日志输出）\n状态：{status} · 退出码：{exit} · 重启次数：{restarts}");
    if !err.trim().is_empty() {
        hint.push_str(&format!("\n错误：{}", err.trim()));
    }
    if restarts != 0 || status == "restarting" {
        hint.push_str(
            "\n\n提示：容器可能因默认命令立即退出而不断重启。请在创建时开启「分配终端」或填写常驻启动命令（如 sleep infinity），或将重启策略设为 no。",
        );
    }
    hint
}
