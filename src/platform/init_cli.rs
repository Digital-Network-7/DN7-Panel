//! First-run **CLI** initialization (replaces the old web wizard).
//!
//! On the first top-level launch, while the panel is UNINITIALIZED and stdin is
//! a TTY, [`run_if_needed`] runs an interactive, bilingual (中文/English) wizard:
//!   1. verify the environment can host the panel's FULL functionality
//!      (hard-abort with reasons if an unfixable prerequisite is missing; small
//!      fixable issues are repaired in place);
//!   2. ensure :80 / :443 are free (offer to take them over — those ports are
//!      mandatory, so declining aborts);
//!   3. pick the console default language + timezone (the timezone is also
//!      written to the host clock: /etc/localtime + /etc/timezone);
//!   4. ask the setup questions (UI address, SSL on/off → Let's Encrypt vs
//!      self-signed, admin username, admin password ×2);
//!   5. issue the console cert (self-signed now; Let's Encrypt is deferred to the
//!      first edge serve, which needs :80 up) and persist the admin account +
//!      language/timezone, flipping the panel to INITIALIZED.
//!
//! It runs in the TTY-attached top-level process (before the supervisor detaches
//! / the panel role spawns), so the interactive prompts and no-echo password
//! read work. Pure-Rust throughout (no external programs).

use anyhow::{anyhow, Result};
use std::io::{self, Write};
use std::path::Path;

use crate::platform::config::PanelConfig;
use crate::web::settings;

/// Run the first-run CLI wizard if the panel is uninitialized. Returns `Ok(())`
/// when the panel is (or becomes) initialized so the caller proceeds to serve;
/// returns `Err` when setup cannot proceed (no TTY, missing prerequisite, the
/// operator declined the mandatory port takeover, or aborted) so the caller
/// exits without serving a half-configured panel.
pub async fn run_if_needed(cfg: &PanelConfig) -> Result<bool> {
    if settings::load().map(|s| s.initialized).unwrap_or(false) {
        return Ok(false); // already initialized — proceed to serve.
    }

    if !stdin_is_tty() {
        bilingual(&[
            (
                "DN7 面板尚未初始化。首次配置必须在交互式终端中完成。",
                "DN7 Panel is not initialized. First-run setup must be done interactively in a terminal.",
            ),
            (
                "请在一个终端里前台运行 `dn7-panel` 以完成初始化。",
                "Run `dn7-panel` in a foreground terminal to initialize.",
            ),
        ]);
        return Err(anyhow!("uninitialized and no TTY for interactive setup"));
    }

    rule();
    println!("  DN7 Panel · 首次初始化 / First-run setup");
    rule();

    check_environment(cfg)?;
    ensure_ports_available().await?;
    let (language, timezone) = ask_locale()?;
    let mut answers = ask_questions()?;
    answers.language = language;
    answers.timezone = timezone;
    apply(cfg, answers).await?;
    Ok(true)
}

// --- 1. environment -------------------------------------------------------

/// Verify the host can run the panel with FULL functionality. Auto-fix the small
/// fixable issues (ip_forward, the data dir); hard-abort (bilingual) on anything
/// unfixable that a core feature needs.
fn check_environment(cfg: &PanelConfig) -> Result<()> {
    section("环境检测 / Environment check");
    let mut bad: Vec<(String, String)> = Vec::new();

    // root — account management, containers, firewall, and binding :80/:443.
    if uid() != 0 {
        bad.push((
            "需要以 root 运行(系统账户管理、容器、防火墙、绑定 80/443 都需要)。".into(),
            "Must run as root (account management, containers, firewall, binding :80/:443).".into(),
        ));
    }
    // Linux — the runtime drives cgroups/namespaces/overlayfs directly.
    if !cfg!(target_os = "linux") || !Path::new("/proc/self").exists() {
        bad.push((
            "仅支持 Linux(需要 /proc、cgroup、命名空间、overlayfs)。".into(),
            "Linux only (requires /proc, cgroups, namespaces, overlayfs).".into(),
        ));
    }
    // cgroup v2 (unified) — the container runtime requires it.
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bad.push((
            "内核未启用 cgroup v2 统一层级(容器功能必需)。请用 systemd.unified_cgroup_hierarchy=1 启动。".into(),
            "cgroup v2 unified hierarchy is not mounted (required for containers). Boot with systemd.unified_cgroup_hierarchy=1.".into(),
        ));
    }
    // overlayfs — container image layers. A fresh boot may not have autoloaded
    // the `overlay` module yet (nothing has mounted one), so load it ourselves
    // before deciding it's missing — otherwise this is a false negative.
    crate::platform::kmod::ensure_loaded("overlay");
    if !crate::platform::kmod::available("overlay") {
        bad.push((
            "内核不支持 overlayfs(容器镜像必需,CONFIG_OVERLAY_FS)。".into(),
            "Kernel lacks overlayfs (required for container images, CONFIG_OVERLAY_FS).".into(),
        ));
    }
    // namespaces — container isolation.
    if !Path::new("/proc/self/ns/pid").exists() || !Path::new("/proc/self/ns/net").exists() {
        bad.push((
            "内核不支持命名空间(容器隔离必需,CONFIG_*_NS)。".into(),
            "Kernel lacks namespaces (required for container isolation, CONFIG_*_NS).".into(),
        ));
    }
    // nftables — container DNAT/masquerade + the edge firewall features. Same
    // fresh-boot autoload gap as overlay: load nf_tables before probing.
    crate::platform::kmod::ensure_loaded("nf_tables");
    if !nftables_ok() {
        bad.push((
            "内核不支持 nf_tables(容器发布端口/出网 NAT 必需,CONFIG_NF_TABLES)。".into(),
            "Kernel lacks nf_tables (required for container port-publish / egress NAT, CONFIG_NF_TABLES).".into(),
        ));
    }
    // A service manager — to register boot autostart + manage the panel service.
    if detect_init_system().is_none() {
        bad.push((
            "未检测到 systemd 或 SysV(service)init 系统——面板需要它来注册开机自启动并作为服务运行。".into(),
            "No systemd or SysV (service) init system found — the panel needs one to register boot autostart and run as a service.".into(),
        ));
    }

    // --- auto-fix the small, fixable issues -------------------------------
    // Writable data dir.
    if let Err(e) = std::fs::create_dir_all(&cfg.data_dir) {
        bad.push((
            format!("无法创建数据目录 {}：{e}", cfg.data_dir.display()),
            format!("Cannot create data dir {}: {e}", cfg.data_dir.display()),
        ));
    } else if !dir_writable(&cfg.data_dir) {
        bad.push((
            format!("数据目录不可写：{}", cfg.data_dir.display()),
            format!("Data dir is not writable: {}", cfg.data_dir.display()),
        ));
    }
    // IPv4 forwarding — needed for container egress/masquerade. Fixable in place.
    if read_trim("/proc/sys/net/ipv4/ip_forward").as_deref() != Some("1")
        && std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").is_ok()
    {
        ok_fix(
            "已启用 IPv4 转发 (net.ipv4.ip_forward=1)",
            "Enabled IPv4 forwarding (net.ipv4.ip_forward=1)",
        );
    }

    if bad.is_empty() {
        ok(
            "环境满足面板全部功能。",
            "Environment supports all panel features.",
        );
        return Ok(());
    }
    println!();
    bilingual(&[(
        "无法初始化：缺少以下面板全功能所需的条件：",
        "Cannot initialize: the following prerequisites for full panel functionality are missing:",
    )]);
    for (zh, en) in &bad {
        println!("  ✗ {zh}");
        println!("    {en}");
    }
    Err(anyhow!("environment prerequisites not met"))
}

// --- 2. ports -------------------------------------------------------------

/// Ensure :80 and :443 are free, offering to take them over. Those ports are
/// mandatory (the edge serves the console + sites on them), so declining aborts.
async fn ensure_ports_available() -> Result<()> {
    section("端口检测 / Port check (80, 443)");
    let busy = crate::infra::website::ports_with_listener(&[80, 443]).await;
    if busy.is_empty() {
        ok("80 / 443 可用。", "80 / 443 are available.");
        return Ok(());
    }
    println!("  ! 端口 {busy:?} 已被其它进程占用。面板的内置 Web 服务必须使用 80/443。");
    println!("    Port(s) {busy:?} are in use. The panel's built-in web server must use 80/443.");
    for &p in &busy {
        for pid in crate::infra::website::listeners_on(p).await {
            let unit = systemd_unit_of(pid);
            match unit {
                Some(u) => println!("    :{p} ← pid {pid} (systemd: {u})"),
                None => println!("    :{p} ← pid {pid}"),
            }
        }
    }
    if !prompt_yes_no(
        "是否接管这些端口(将停止占用进程)? / Take over these ports (the occupying processes will be stopped)?",
        false,
    )? {
        bilingual(&[(
            "已取消初始化:80/443 是面板必不可少的功能,无法在不占用这两个端口的情况下运行。",
            "Initialization cancelled: :80/:443 are mandatory — the panel cannot run without them.",
        )]);
        return Err(anyhow!("user declined the mandatory port takeover"));
    }
    let still = crate::infra::website::take_over_ports(&[80, 443]).await;
    if still.is_empty() {
        ok("已接管 80 / 443。", "Took over 80 / 443.");
        return Ok(());
    }
    // A respawning systemd service (Restart=) re-grabbed the port. We stay
    // pure-Rust (no `systemctl`), so tell the operator which unit to disable.
    println!("  ! 端口 {still:?} 仍被占用——很可能是会自动重启的 systemd 服务。");
    println!(
        "    Port(s) {still:?} are still occupied — likely a systemd service that auto-restarts."
    );
    for &p in &still {
        for pid in crate::infra::website::listeners_on(p).await {
            if let Some(u) = systemd_unit_of(pid) {
                println!("    请先停用 / disable it first:  systemctl disable --now {u}");
            }
        }
    }
    Err(anyhow!("ports still occupied after takeover"))
}

// --- 2.5 language & timezone ---------------------------------------------

/// Common IANA zones offered as a numbered menu (0 = type any other name).
const COMMON_ZONES: &[&str] = &[
    "UTC",
    "Asia/Shanghai",
    "Asia/Hong_Kong",
    "Asia/Tokyo",
    "Asia/Singapore",
    "Asia/Kolkata",
    "Europe/London",
    "Europe/Berlin",
    "America/New_York",
    "America/Los_Angeles",
];

/// Ask the preferred console language + default timezone. Returns
/// `(language, timezone)`; the timezone is applied to the host clock in `apply`.
fn ask_locale() -> Result<(String, String)> {
    section("语言与时区 / Language & timezone");

    let deflang = detect_lang();
    let language = loop {
        let c = prompt_line(&format!(
            "首选界面语言 / UI language [1] 简体中文 [2] 繁體中文 [3] English [4] 日本語 (默认/default {deflang}): "
        ))?;
        match c.trim() {
            "" => break deflang.to_string(),
            "1" | "zh-CN" | "zh" => break "zh-CN".to_string(),
            "2" | "zh-TW" => break "zh-TW".to_string(),
            "3" | "en" => break "en".to_string(),
            "4" | "ja" => break "ja".to_string(),
            _ => warn("请输入 1-4。", "Please enter 1-4."),
        }
    };

    let detected = detect_system_tz();
    let def_tz = detected.as_deref().unwrap_or("UTC");
    println!("  时区 / Timezone:");
    for (i, z) in COMMON_ZONES.iter().enumerate() {
        println!("    [{}] {z}", i + 1);
    }
    println!("    [0] 其它 / other (type an IANA name)");
    let timezone = loop {
        let c = prompt_line(&format!("  选择 / choose (默认/default {def_tz}): "))?;
        let c = c.trim();
        let tz = if c.is_empty() {
            def_tz.to_string()
        } else if let Ok(n) = c.parse::<usize>() {
            if n == 0 {
                prompt_line("    IANA 时区名 / IANA name (e.g. Asia/Shanghai): ")?
                    .trim()
                    .to_string()
            } else if (1..=COMMON_ZONES.len()).contains(&n) {
                COMMON_ZONES[n - 1].to_string()
            } else {
                warn("序号无效。", "Invalid number.");
                continue;
            }
        } else {
            c.to_string() // typed a zone name directly
        };
        if !tz_exists(&tz) {
            warn(
                &format!("找不到时区 {tz}(不在 /usr/share/zoneinfo)。"),
                &format!("Timezone '{tz}' not found under /usr/share/zoneinfo."),
            );
            continue;
        }
        break tz;
    };

    ok(
        &format!("语言 {language} · 时区 {timezone}"),
        &format!("language {language} · timezone {timezone}"),
    );
    Ok((language, timezone))
}

/// A supported UI language guessed from the environment ($LANG/$LC_ALL), for the
/// wizard default. Falls back to English.
fn detect_lang() -> &'static str {
    let l = std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_default()
        .to_lowercase();
    if l.starts_with("zh_tw")
        || l.starts_with("zh_hk")
        || l.starts_with("zh_mo")
        || l.contains("hant")
    {
        "zh-TW"
    } else if l.starts_with("ja") {
        "ja"
    } else if l.starts_with("zh") || l.contains("hans") {
        "zh-CN"
    } else {
        "en"
    }
}

/// The host's current IANA timezone (for the wizard default): `/etc/timezone`
/// first, else the `/etc/localtime` symlink target under `zoneinfo/`.
fn detect_system_tz() -> Option<String> {
    if let Some(t) = read_trim("/etc/timezone") {
        if tz_exists(&t) {
            return Some(t);
        }
    }
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let s = target.to_string_lossy();
    let i = s.find("zoneinfo/")?;
    let t = s[i + "zoneinfo/".len()..]
        .trim_start_matches('/')
        .to_string();
    (!t.is_empty()).then_some(t)
}

/// Whether `tz` is a real zoneinfo entry (also rejects path traversal).
fn tz_exists(tz: &str) -> bool {
    !tz.is_empty()
        && !tz.starts_with('/')
        && !tz.contains("..")
        && Path::new(&format!("/usr/share/zoneinfo/{tz}")).is_file()
}

/// Point the host clock at `tz`: `/etc/localtime` symlink (glibc reads it for
/// local time) + `/etc/timezone` (Debian tooling). Pure Rust, no `timedatectl`.
fn set_system_timezone(tz: &str) -> std::io::Result<()> {
    let target = format!("/usr/share/zoneinfo/{tz}");
    let _ = std::fs::remove_file("/etc/localtime");
    std::os::unix::fs::symlink(&target, "/etc/localtime")?;
    let _ = std::fs::write("/etc/timezone", format!("{tz}\n"));
    Ok(())
}

// --- 3. questions ---------------------------------------------------------

struct Answers {
    language: String, // zh-CN | zh-TW | en | ja
    timezone: String, // IANA name, e.g. Asia/Shanghai
    external_address: String,
    https_mode: String, // none | selfsigned | le
    username: String,
    salt: String,
    stored: String, // Argon2id(verifier)
    kdf: String,
}

/// Whether `s` is a usable panel host: a single canonical DNS hostname OR a
/// canonical IP literal, and nothing else. It becomes the edge's host key, so we
/// reject anything that carries a scheme (`http://`), a port (`:443`), a path
/// (`/x`), a wildcard (`*.x`), embedded whitespace, or more than one host — none
/// of which the edge would match. An IP literal short-circuits (parsed by
/// `std::net`); otherwise the value must be a valid DNS name.
fn valid_host_address(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    // An IP literal (v4 or v6) is accepted as-is.
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Otherwise it must be a canonical DNS hostname: dot-separated labels of
    // ASCII letters/digits/hyphen, each 1..=63 chars, not hyphen-bordered, and
    // no trailing dot. This rejects schemes, ports, paths, wildcards, `_`, and
    // whitespace (a space or any of `:/@*` can't appear in a label).
    let mut labels = 0;
    for label in s.split('.') {
        labels += 1;
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return false;
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    labels >= 1
}

fn ask_questions() -> Result<Answers> {
    section("配置 / Configuration");

    // 1. UI address. This value becomes the edge's host key, so it must be a
    // single canonical hostname or IP literal — reject a scheme/port/path,
    // wildcards, whitespace, or multiple hosts (any of which would break the
    // host match) and re-prompt instead of accepting it.
    let external_address = loop {
        let a = prompt_line("1) 面板访问地址(域名或 IP) / Panel address (domain or IP): ")?;
        if !valid_host_address(&a) {
            warn(
                "请输入单个域名或 IP(不含 http://、端口、路径、通配符或空格)。",
                "Enter a single hostname or IP (no http://, port, path, wildcard, or spaces).",
            );
            continue;
        }
        break a;
    };

    // 2. SSL on/off → 2.1 LE vs self-signed.
    let ssl = prompt_yes_no(
        "2) 是否开启 SSL(在 443 上提供 HTTPS)? / Enable SSL (HTTPS on 443)?",
        false,
    )?;
    let https_mode = if !ssl {
        "none".to_string()
    } else {
        loop {
            let c = prompt_line(
                "2.1) 证书类型 [1] Let's Encrypt(需域名+公网可达) [2] 自签名 / Cert type [1] Let's Encrypt (needs a public domain) [2] self-signed: ",
            )?;
            match c.as_str() {
                "1" | "le" => {
                    if external_address.parse::<std::net::IpAddr>().is_ok() {
                        warn(
                            "Let's Encrypt 需要域名,不能用 IP。请选自签名或返回改用域名。",
                            "Let's Encrypt needs a domain, not an IP. Choose self-signed, or restart and use a domain.",
                        );
                        continue;
                    }
                    break "le".to_string();
                }
                "2" | "self" | "selfsigned" => break "selfsigned".to_string(),
                _ => warn("请输入 1 或 2。", "Please enter 1 or 2."),
            }
        }
    };

    // 3. Admin username.
    let username = loop {
        let u = prompt_line("3) 管理员用户名 / Admin username: ")?;
        if crate::app::users::valid_username(&u) {
            break u;
        }
        warn(
            "用户名格式不正确(小写字母/数字/_/-,1-32 位,且不能为 root)。",
            "Invalid username (lowercase letters/digits/_/-, 1-32 chars, not 'root').",
        );
    };

    // 4 + 4.1. Admin password, entered twice (no echo).
    let (salt, stored, kdf) = loop {
        let p1 = read_password("4) 管理员密码 / Admin password: ")?;
        if p1.len() < 8 {
            warn("密码至少 8 位。", "Password must be at least 8 characters.");
            continue;
        }
        let p2 = read_password("4.1) 再次输入密码 / Confirm password: ")?;
        if p1 != p2 {
            warn(
                "两次输入不一致,请重试。",
                "Passwords do not match, try again.",
            );
            continue;
        }
        let salt = dn7_cred::random_salt_hex();
        let verifier = dn7_cred::derive_verifier_s256(&salt, &p1, dn7_cred::KDF_ITERS);
        let stored = crate::infra::auth::hash_verifier(&verifier)
            .ok_or_else(|| anyhow!("密码哈希失败 / password hashing failed"))?;
        break (salt, stored, dn7_cred::kdf_string());
    };

    Ok(Answers {
        // language + timezone are collected separately by `ask_locale` and filled
        // in by `run_if_needed`; left empty here.
        language: String::new(),
        timezone: String::new(),
        external_address,
        https_mode,
        username,
        salt,
        stored,
        kdf,
    })
}

// --- 4. apply -------------------------------------------------------------

async fn apply(cfg: &PanelConfig, a: Answers) -> Result<()> {
    section("应用 / Applying");
    // Self-signed issues immediately (no network). "none" clears any stale cert.
    // Let's Encrypt is DEFERRED: it needs the edge serving :80 to answer the
    // ACME challenge, which isn't up yet — the panel issues it on first serve.
    if a.https_mode == "selfsigned" || a.https_mode == "none" {
        crate::infra::website::console_apply_tls(&a.https_mode, &a.external_address)
            .await
            .map_err(|e| anyhow!("证书处理失败 / certificate setup failed: {e:#}"))?;
    }

    let (mut s, _) = settings::load_or_init(cfg.web_port);
    s.external_address = a.external_address.clone();
    s.https_mode = a.https_mode.clone();
    s.language = a.language.clone();
    s.timezone = a.timezone.clone();
    s.username = a.username.clone();
    s.set_password_hashed(&a.salt, &a.stored, &a.kdf);
    s.initialized = true;
    s.init_token = String::new();
    settings::save(&s).map_err(|e| anyhow!("保存设置失败 / failed to save settings: {e}"))?;

    // Point the host clock at the chosen timezone (best-effort; the console's
    // display uses settings.timezone regardless of whether this succeeds).
    if !a.timezone.is_empty() {
        match set_system_timezone(&a.timezone) {
            Ok(()) => ok_fix(
                &format!("已将系统时区设为 {}", a.timezone),
                &format!("Set the system timezone to {}", a.timezone),
            ),
            Err(e) => warn(
                &format!("设置系统时区失败({e});控制台仍会按所选时区显示。"),
                &format!("Could not set the system timezone ({e}); the console still displays in the chosen zone."),
            ),
        }
    }

    rule();
    ok("初始化完成。", "Initialization complete.");
    println!("    管理员 / admin : {}", a.username);
    println!("    地址 / address  : {}", a.external_address);
    let mode = match a.https_mode.as_str() {
        "le" => "Let's Encrypt (将在服务启动后签发 / issued on first serve)",
        "selfsigned" => "self-signed",
        _ => "off (HTTP)",
    };
    println!("    SSL             : {mode}");
    println!("    语言 / language : {}", a.language);
    println!("    时区 / timezone : {}", a.timezone);
    rule();
    Ok(())
}

// --- env probes -----------------------------------------------------------

fn uid() -> u32 {
    // SAFETY: getuid() takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// nf_tables availability — reuses the runtime's own probe (lists tables via the
/// pure-Rust `rustables`; `Ok` means the kernel speaks nf_tables).
fn nftables_ok() -> bool {
    dn7_container::net::firewall::have_nft()
}

fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(".dn7-write-probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    let _ = std::fs::remove_file(&probe);
    ok
}

/// The systemd unit owning `pid` (from its cgroup line), if any — for reporting
/// (we never shell out to systemctl in the port-takeover path).
fn systemd_unit_of(pid: u32) -> Option<String> {
    let cg = read_trim(&format!("/proc/{pid}/cgroup"))?;
    cg.lines()
        .filter_map(|l| l.rsplit('/').next())
        .find(|seg| seg.ends_with(".service"))
        .map(|s| s.to_string())
}

// --- service manager registration -----------------------------------------

#[derive(Clone, Copy)]
enum InitSystem {
    Systemd,
    Sysv,
}

/// The host's service manager: systemd if it's the init manager, else SysV if a
/// `service` command is present. `None` → the env check hard-aborts.
fn detect_init_system() -> Option<InitSystem> {
    if std::path::Path::new("/run/systemd/system").is_dir() {
        return Some(InitSystem::Systemd);
    }
    if which_on_path("service").is_some() || std::path::Path::new("/usr/sbin/service").exists() {
        return Some(InitSystem::Sysv);
    }
    None
}

fn which_on_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.exists())
}

const SYSTEMD_UNIT: &str = "/etc/systemd/system/dn7-panel.service";

/// Register the panel as a managed service and start it via the service manager,
/// printing each step + the management example commands. Called once on a fresh
/// init, AFTER `autostart::install_all` has written the unit/symlink (systemd);
/// here we load + START it so `systemctl status` is immediately truthful and the
/// example commands work. The caller then EXITS — the service runs the panel.
///
/// NOTE: service registration/start here (`systemctl`/`service`/`update-rc.d`)
/// and `dn7 reset`'s service-stop (`run_reset` in main.rs) are the panel's only
/// invocations of the host init manager — a deliberate, documented exception to
/// the "zero external programs" invariant for one-time INIT-TIME / service-
/// lifecycle bootstrap (see the carve-out in CLAUDE.md / ARCHITECTURE.md). The
/// running panel and its runtime stay pure-Rust / external-program-free.
pub fn register_and_start_service() {
    println!();
    println!();
    section("服务注册与启动 / Service registration & start");
    let exe = std::env::current_exe().unwrap_or_else(|_| "/var/dn7/panel/dn7-panel".into());
    match detect_init_system() {
        Some(InitSystem::Systemd) => {
            // The unit + the enable-symlink were written pure-Rust by
            // autostart::install_all; load + start it as a managed service.
            run_quiet("systemctl", &["daemon-reload"]);
            run_quiet("systemctl", &["start", "dn7-panel"]);
            std::thread::sleep(std::time::Duration::from_millis(900));
            if std::path::Path::new(SYSTEMD_UNIT).exists() {
                ok(
                    "已注册 systemd 服务并设为开机自启动 (dn7-panel.service)",
                    "Registered systemd service + enabled at boot (dn7-panel.service)",
                );
            }
            if is_active_systemd() {
                ok(
                    "面板已启动(systemd 托管)。",
                    "Panel started (managed by systemd).",
                );
            } else {
                warn(
                    "面板可能仍在启动,请用 `systemctl status dn7-panel` 查看。",
                    "Panel may still be starting; check `systemctl status dn7-panel`.",
                );
            }
            println!("\n  管理命令 / Manage:");
            println!("    systemctl status dn7-panel        # 状态 / status");
            println!("    systemctl restart dn7-panel       # 重启 / restart");
            println!("    systemctl stop dn7-panel          # 停止 / stop");
            println!("    journalctl -u dn7-panel -f        # 日志 / logs");
        }
        Some(InitSystem::Sysv) => {
            let _ = write_sysv_script(&exe);
            run_quiet("update-rc.d", &["dn7-panel", "defaults"]); // best-effort boot-enable
            let started = run_quiet("service", &["dn7-panel", "start"]);
            ok(
                "已注册 SysV 服务并设为开机自启动 (/etc/init.d/dn7-panel)",
                "Registered SysV service + boot autostart (/etc/init.d/dn7-panel)",
            );
            if started {
                ok("面板已启动。", "Panel started.");
            } else {
                warn(
                    "面板可能未启动,请用 `service dn7-panel status` 查看。",
                    "Panel may not have started; check `service dn7-panel status`.",
                );
            }
            println!("\n  管理命令 / Manage:");
            println!("    service dn7-panel status          # 状态 / status");
            println!("    service dn7-panel restart         # 重启 / restart");
            println!("    service dn7-panel stop            # 停止 / stop");
        }
        None => {} // unreachable — the env check already hard-failed.
    }
    rule();
}

fn run_quiet(bin: &str, args: &[&str]) -> bool {
    std::process::Command::new(bin)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_active_systemd() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "dn7-panel"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Minimal LSB init script for SysV hosts (written pure-Rust; executed by the
/// host's `service` command, not by the panel).
fn write_sysv_script(exe: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let bin = exe.display();
    let script = format!(
        "#!/bin/sh\n\
### BEGIN INIT INFO\n\
# Provides:          dn7-panel\n\
# Required-Start:    $network $remote_fs\n\
# Required-Stop:     $network $remote_fs\n\
# Default-Start:     2 3 4 5\n\
# Default-Stop:      0 1 6\n\
# Short-Description: DN7 Panel\n\
### END INIT INFO\n\
BIN={bin}\n\
case \"$1\" in\n\
  start) \"$BIN\" --foreground >/dev/null 2>&1 & ;;\n\
  stop) pkill -f \"$BIN\" ;;\n\
  restart) pkill -f \"$BIN\"; sleep 1; \"$BIN\" --foreground >/dev/null 2>&1 & ;;\n\
  status) pgrep -f \"$BIN\" >/dev/null && echo running || echo stopped ;;\n\
  *) echo \"usage: $0 {{start|stop|restart|status}}\"; exit 1 ;;\n\
esac\n"
    );
    let path = "/etc/init.d/dn7-panel";
    std::fs::write(path, script)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

// The password verifier KDF (`s256:N`) now lives in the shared `dn7_cred` crate —
// the single byte-exact source of truth, also used by `dn7 user add|passwd`, so
// the wizard and the CLI can't drift apart and break login.

// --- terminal I/O ---------------------------------------------------------

fn stdin_is_tty() -> bool {
    // SAFETY: isatty on fd 0 (stdin); returns 1 for a terminal.
    unsafe { libc::isatty(0) == 1 }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let a = prompt_line(&format!("{prompt} {hint} "))?.to_ascii_lowercase();
        match a.as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => warn("请输入 y 或 n。", "Please enter y or n."),
        }
    }
}

/// Read a line with terminal echo disabled (so the password isn't shown).
fn read_password(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    // SAFETY: tcgetattr/tcsetattr on stdin (fd 0); we always restore the saved
    // termios before returning, on every path.
    let fd = 0;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if have {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let res = io::stdin().read_line(&mut line);
    if have {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    println!(); // the user's Enter wasn't echoed
    res?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

// --- bilingual output helpers ---------------------------------------------

fn rule() {
    println!("────────────────────────────────────────────────────────");
}
fn section(title: &str) {
    println!("\n▶ {title}");
}
fn ok(zh: &str, en: &str) {
    println!("  ✓ {zh} / {en}");
}
fn ok_fix(zh: &str, en: &str) {
    println!("  ⚙ {zh} / {en}");
}
fn warn(zh: &str, en: &str) {
    println!("  ! {zh} / {en}");
}
fn bilingual(lines: &[(&str, &str)]) {
    for (zh, en) in lines {
        println!("{zh}");
        println!("{en}");
    }
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_address_accepts_single_hostname_or_ip_only() {
        // A canonical hostname or IP literal is accepted.
        assert!(valid_host_address("example.com"));
        assert!(valid_host_address("sub.example.co.uk"));
        assert!(valid_host_address("localhost"));
        assert!(valid_host_address("a-b.example.com"));
        assert!(valid_host_address("1.2.3.4"));
        assert!(valid_host_address("2001:db8::1"));
        assert!(valid_host_address("  example.com  ")); // trimmed

        // Rejected: scheme, port, path, wildcard, whitespace, or multiple hosts —
        // anything that would break the edge's host key.
        assert!(!valid_host_address(""));
        assert!(!valid_host_address("https://x")); // scheme
        assert!(!valid_host_address("x:443")); // port
        assert!(!valid_host_address("x/y")); // path
        assert!(!valid_host_address("*.example.com")); // wildcard
        assert!(!valid_host_address("a b.com")); // whitespace
        assert!(!valid_host_address("a.com b.com")); // multiple hosts
        assert!(!valid_host_address("-x.com")); // hyphen-bordered label
        assert!(!valid_host_address("x-.com")); // hyphen-bordered label
        assert!(!valid_host_address("x..com")); // empty label
        assert!(!valid_host_address("under_score.com")); // '_' not a DNS char
        assert!(!valid_host_address("example.com.")); // trailing dot (non-canonical)
    }
}
