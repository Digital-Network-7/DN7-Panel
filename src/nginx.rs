//! Panel-side Nginx management (host-only).
//!
//! Manages the **host's own nginx**: DN7 Panel ensures nginx is installed (via
//! the system package manager) and only ever writes its own
//! `dn7-<id>.conf` files into `/etc/nginx/conf.d`, never touching the user's
//! existing configs, reloading via `nginx -s reload`. Certs and static webroots
//! live under the panel state dir (`/var/dn7/panel/.../nginx/`).
//!
//! Long operations (install / Let's Encrypt issuance) run **detached** in a
//! process-global op registry so they survive client reconnects.
//!
//! Sites are form-defined (domain + target), never raw nginx config, so there's
//! no config-injection surface. Each site is generated from a small manifest
//! (`sites.json`) into a single conf file and validated with `nginx -t` before
//! it's kept (otherwise it's rolled back).
//!
//! Requests (client -> panel):
//!   {"id","op":"info"}
//!   {"id","op":"setup"}                       -> {op_id} (detached install)
//!   {"id","op":"list_sites"}
//!   {"id","op":"add_site", <site fields>}     -> {site} or {op_id} (LE issuance)
//!   {"id","op":"remove_site","site_id"}
//!   {"id","op":"reload"}
//!   {"id","op":"list_containers"}             -> running containers (proxy menu)
//!   {"id","op":"list_ops"} / {"op_log","op_id"} / {"dismiss_op","op_id"}

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct Req {
    #[serde(default)]
    #[allow(dead_code)]
    id: i64,
    op: String,
    #[serde(default)]
    op_id: Option<String>,
    #[serde(default)]
    site_id: Option<String>,
    // add_site fields
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    kind: Option<String>, // "proxy_host" | "proxy_container" | "static"
    #[serde(default)]
    target_url: Option<String>, // proxy_host
    #[serde(default)]
    container: Option<String>, // proxy_container
    #[serde(default)]
    container_port: Option<i64>, // proxy_container
    #[serde(default)]
    root: Option<String>, // static (subdir name)
    #[serde(default)]
    ssl: Option<bool>,
    #[serde(default)]
    cert_mode: Option<String>, // "self" | "le" | "manual"
    #[serde(default)]
    cert_pem: Option<String>, // manual
    #[serde(default)]
    key_pem: Option<String>, // manual
    #[serde(default)]
    cert_name: Option<String>, // standalone cert name (create_cert / reference)
    // New add-site fields (NPM-style options + custom path rules).
    #[serde(default)]
    scheme: Option<String>, // proxy upstream scheme "http"|"https"
    #[serde(default)]
    cache: Option<bool>,
    #[serde(default)]
    block_attacks: Option<bool>,
    #[serde(default)]
    websockets: Option<bool>,
    #[serde(default)]
    force_ssl: Option<bool>,
    #[serde(default)]
    http2: Option<bool>,
    #[serde(default)]
    hsts: Option<bool>,
    #[serde(default)]
    hsts_sub: Option<bool>,
    #[serde(default)]
    trust_proxy: Option<bool>,
    #[serde(default)]
    locations: Option<Vec<Location>>, // custom path rules
    #[serde(default)]
    extra_conf: Option<String>, // raw nginx directives injected into the server block
    // Access list reference on a site (empty = public/none).
    #[serde(default)]
    access_id: Option<String>,
    // Access list management (create/update/delete).
    #[serde(default)]
    name: Option<String>, // access list display name
    #[serde(default)]
    satisfy: Option<String>, // "any" | "all"
    #[serde(default)]
    pass_auth: Option<bool>, // forward Authorization header upstream
    #[serde(default)]
    users: Option<Vec<AccessUserInput>>, // basic-auth users (username + optional new password)
    #[serde(default)]
    clients: Option<Vec<AccessClient>>, // allow/deny IP rules
    // Default-site (Settings) configuration.
    #[serde(default)]
    default_mode: Option<String>, // "404" | "welcome" | "444" | "redirect"
    #[serde(default)]
    redirect_url: Option<String>,
}

/// A managed site, persisted in the manifest and regenerated into one conf file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Site {
    id: String,
    server_name: String,
    kind: String,
    #[serde(default)]
    target_url: String,
    #[serde(default)]
    container: String,
    #[serde(default)]
    container_port: i64,
    #[serde(default)]
    root: String,
    #[serde(default)]
    ssl: bool,
    #[serde(default)]
    cert_mode: String,
    /// When set, this site uses a standalone named cert from the cert manifest
    /// instead of a per-site `<id>.crt/.key`. Empty means per-site (legacy).
    #[serde(default)]
    cert_name: String,
    /// Upstream scheme for proxy kinds ("http" | "https"). Empty == http.
    #[serde(default)]
    scheme: String,
    /// Behaviour toggles (NPM-style): long-cache static assets, block common
    /// exploit patterns, and enable WebSocket upgrade headers on proxies.
    #[serde(default)]
    cache: bool,
    #[serde(default)]
    block_attacks: bool,
    #[serde(default)]
    websockets: bool,
    /// HTTPS feature toggles. `force_ssl` (HTTP→HTTPS redirect) and `http2`
    /// default on for backward compatibility; the rest default off.
    #[serde(default = "default_true")]
    force_ssl: bool,
    #[serde(default = "default_true")]
    http2: bool,
    #[serde(default)]
    hsts: bool,
    #[serde(default)]
    hsts_sub: bool,
    #[serde(default)]
    trust_proxy: bool,
    /// Extra path rules layered on top of the main location (NPM "custom
    /// locations"): each forwards a path prefix to a host[:port].
    #[serde(default)]
    locations: Vec<Location>,
    /// Raw nginx directives, injected verbatim into the serving server block(s).
    /// Validated by `nginx -t` on save (invalid input rolls back).
    #[serde(default)]
    extra_conf: String,
    /// Access list id controlling this site (HTTP Basic Auth + IP allow/deny).
    /// Empty == publicly accessible.
    #[serde(default)]
    access_id: String,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Access lists (NPM-style): HTTP Basic Auth users + IP allow/deny rules, with
// "satisfy any/all" and an option to forward (or strip) the Authorization
// header upstream. Assigned to proxy hosts by id.
// ---------------------------------------------------------------------------

/// A stored access list. Passwords are kept only as nginx-htpasswd hashes
/// (`{SHA}…`), never in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessList {
    id: String,
    name: String,
    /// "any" | "all" — how auth and IP rules combine (nginx `satisfy`).
    #[serde(default)]
    satisfy: String,
    /// Forward the client's Authorization header to the upstream (else strip).
    #[serde(default)]
    pass_auth: bool,
    #[serde(default)]
    users: Vec<AccessUser>,
    #[serde(default)]
    clients: Vec<AccessClient>,
}

/// A basic-auth credential: the username and its precomputed htpasswd hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessUser {
    username: String,
    /// nginx-compatible hash, e.g. `{SHA}base64(sha1(password))`.
    #[serde(default)]
    hash: String,
}

/// An allow/deny rule against a client address (IP, CIDR, or "all").
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AccessClient {
    /// "allow" | "deny".
    directive: String,
    /// IP / CIDR / "all".
    address: String,
}

/// New/changed user input from the client (password is plaintext, optional on
/// edit — empty keeps the existing hash).
#[derive(Debug, Clone, Deserialize, Default)]
struct AccessUserInput {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// Default-site behaviour for requests matching no managed server_name.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DefaultSite {
    /// "404" | "welcome" | "444" | "redirect".
    mode: String,
    #[serde(default)]
    redirect_url: String,
}

impl Default for DefaultSite {
    fn default() -> Self {
        DefaultSite {
            mode: "404".to_string(),
            redirect_url: String::new(),
        }
    }
}

/// Global website settings (persisted in `websettings.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WebGlobal {
    #[serde(default)]
    default_site: DefaultSite,
}

/// A custom path rule (NPM-style "custom location"): forward a path prefix to a
/// host[:port] over http/https. Form-driven (no raw nginx config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Location {
    /// The location prefix, e.g. "/api". Must start with '/'.
    path: String,
    /// Upstream scheme: "http" | "https". Empty == http.
    #[serde(default)]
    scheme: String,
    /// Upstream host[:port].
    #[serde(default)]
    target: String,
    /// Enable WebSocket upgrade headers for this path.
    #[serde(default)]
    websockets: bool,
    /// Upstream kind: "host" (target host:port) | "container" (docker
    /// container). Empty == host (backward compatible).
    #[serde(default)]
    kind: String,
    /// Docker container name (when `kind == "container"`).
    #[serde(default)]
    container: String,
    /// Container port to proxy to (when `kind == "container"`).
    #[serde(default)]
    container_port: i64,
}

// ---------------------------------------------------------------------------
// Detached operation registry (setup + cert issuance) — see `opreg` submodule.
// ---------------------------------------------------------------------------
mod opreg;
use opreg::{new_op_id, op_create, op_dismiss, op_finish, op_log, op_push, ops_snapshot, pmsg};
mod certparse;
mod validate;
use validate::{
    norm_scheme, primary_host, valid_access_name, valid_auth_username, valid_cert_name,
    valid_client_address, valid_container_name, valid_host_token, valid_location_path, valid_port,
    valid_redirect_url, valid_root_segment, valid_server_name,
};

// ---------------------------------------------------------------------------
// State directory layout (persisted under the panel runtime dir).
//
//   <base>/nginx/setup_done    marker that host nginx setup completed
//   <base>/nginx/sites.json    the site manifest
//   <base>/nginx/certs/        per-site + named certs (nginx reads from here)
//   <base>/nginx/www/          static webroots (nginx reads from here)
//
// Generated conf files go directly into the host's /etc/nginx/conf.d.
// ---------------------------------------------------------------------------

fn base_dir() -> std::path::PathBuf {
    crate::paths::default_base_dir().join("nginx")
}
fn setup_marker() -> std::path::PathBuf {
    base_dir().join("setup_done")
}
fn sites_file() -> std::path::PathBuf {
    base_dir().join("sites.json")
}
fn certs_dir() -> std::path::PathBuf {
    base_dir().join("certs")
}
fn www_dir() -> std::path::PathBuf {
    base_dir().join("www")
}

/// Host nginx config drop-in directory.
const HOST_CONFD: &str = "/etc/nginx/conf.d";

/// Whether host nginx setup has been completed (marker file present).
fn is_setup() -> bool {
    setup_marker().exists()
}

fn mark_setup() -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(setup_marker(), "host")?;
    Ok(())
}

fn load_sites() -> Vec<Site> {
    std::fs::read_to_string(sites_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<Site>>(&s).ok())
        .unwrap_or_default()
}

fn save_sites(sites: &[Site]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(sites_file(), serde_json::to_string_pretty(sites)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone named-certificate store.
//
// Certs can be created independently of any site (manifest `certs.json`) and
// then referenced by one or more sites. Each named cert is stored as
//   <cert_store>/cert-<name>.crt   and   cert-<name>.key
// so a site that references it just points its conf at those files.
// ---------------------------------------------------------------------------

/// A standalone, named certificate. The PEM files live in the cert store; this
/// manifest just records its name, the domain it was issued for, and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NamedCert {
    name: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    cert_mode: String, // "self" | "le" | "manual"
}

fn certs_manifest_file() -> std::path::PathBuf {
    base_dir().join("certs.json")
}

fn load_named_certs() -> Vec<NamedCert> {
    std::fs::read_to_string(certs_manifest_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<NamedCert>>(&s).ok())
        .unwrap_or_default()
}

fn save_named_certs(certs: &[NamedCert]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(certs_manifest_file(), serde_json::to_string_pretty(certs)?)?;
    Ok(())
}

fn named_crt_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.crt"))
}
fn named_key_file(lo: &Layout, name: &str) -> std::path::PathBuf {
    lo.cert_store.join(format!("cert-{name}.key"))
}

// ---------------------------------------------------------------------------
// Access-list store + global website settings.
// ---------------------------------------------------------------------------

fn access_file() -> std::path::PathBuf {
    base_dir().join("access.json")
}
fn access_dir() -> std::path::PathBuf {
    base_dir().join("access")
}
fn htpasswd_path(id: &str) -> std::path::PathBuf {
    access_dir().join(format!("{id}.htpasswd"))
}
fn websettings_file() -> std::path::PathBuf {
    base_dir().join("websettings.json")
}

fn load_access() -> Vec<AccessList> {
    std::fs::read_to_string(access_file())
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<AccessList>>(&s).ok())
        .unwrap_or_default()
}
fn save_access(lists: &[AccessList]) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(access_file(), serde_json::to_string_pretty(lists)?)?;
    Ok(())
}
fn load_webglobal() -> WebGlobal {
    std::fs::read_to_string(websettings_file())
        .ok()
        .and_then(|s| serde_json::from_str::<WebGlobal>(&s).ok())
        .unwrap_or_default()
}
fn save_webglobal(g: &WebGlobal) -> Result<()> {
    std::fs::create_dir_all(base_dir())?;
    std::fs::write(websettings_file(), serde_json::to_string_pretty(g)?)?;
    Ok(())
}

/// An access-list id (random, filesystem-safe).
fn new_access_id() -> String {
    format!("al{:08x}", rand::random::<u32>())
}

// Access-list validators live in the `validate` submodule.

/// Compute a strong, salted password hash for nginx HTTP Basic Auth: bcrypt
/// (`$2b$…`), which the host nginx verifies via `crypt()`. Salted and
/// GPU-resistant — far stronger than the legacy unsalted `{SHA}` scheme.
fn htpasswd_hash(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap_or_default()
}

/// Write (or remove) an access list's htpasswd file from its stored hashes.
fn write_htpasswd(list: &AccessList) -> Result<()> {
    let path = htpasswd_path(&list.id);
    if list.users.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    std::fs::create_dir_all(access_dir())?;
    let mut body = String::new();
    for u in &list.users {
        body.push_str(&format!("{}:{}\n", u.username, u.hash));
    }
    std::fs::write(&path, body)?;
    harden_htpasswd_perms(&path);
    Ok(())
}

/// Tighten an htpasswd file to the minimum the nginx worker still needs:
/// owned by nginx's run-user at 0640 when that user can be determined, else
/// fall back to 0644 (world-readable) so auth never silently breaks. The hashes
/// are bcrypt, so even the 0644 fallback isn't trivially crackable.
fn harden_htpasswd_perms(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some((uid, gid)) = nginx_run_uid_gid() {
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
                // SAFETY: `c` is a valid NUL-terminated path; chown just sets
                // ownership and returns an error code we check.
                let rc = unsafe { libc::chown(c.as_ptr(), uid, gid) };
                if rc == 0 {
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640));
                    return;
                }
            }
        }
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The nginx worker's run-user from `nginx.conf` (`user <name>;`), resolved to
/// (uid, gid). Workers read auth_basic_user_file, so the htpasswd file must be
/// readable by this account. Returns None when it can't be determined.
#[cfg(unix)]
fn nginx_run_uid_gid() -> Option<(u32, u32)> {
    let conf = std::fs::read_to_string("/etc/nginx/nginx.conf").ok()?;
    let mut user = None;
    for line in conf.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("user ") {
            let name = rest
                .trim()
                .trim_end_matches(';')
                .split_whitespace()
                .next()?;
            if !name.is_empty() && name != "root" {
                user = Some(name.to_string());
            }
            break;
        }
    }
    let user = user?;
    let c = std::ffi::CString::new(user).ok()?;
    // SAFETY: getpwnam reads the passwd db for a valid C string and returns a
    // pointer we immediately copy out of (no retention).
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(((*pw).pw_uid, (*pw).pw_gid))
    }
}

// ---------------------------------------------------------------------------
// Static-site content upload (ZIP extraction / per-file), used by the web
// console's "static" site type. Writes into <www_store>/<root>/.
// ---------------------------------------------------------------------------

/// Public entrypoint for the web console's static-site upload. `mode` is "zip"
/// (extract `body` as a ZIP archive) or "file" (write `body` as a single file
/// at `rel` within the webroot). `clear` wipes the webroot first. Returns the
/// number of files written. `temp` is a host temp file holding the streamed
/// upload body (never buffered fully in memory).
pub async fn web_static_upload(
    root: &str,
    mode: &str,
    rel: Option<&str>,
    clear: bool,
    temp: &std::path::Path,
) -> Result<usize> {
    let lo = layout()?;
    if !valid_root_segment(root) {
        return Err(anyhow!("ERR_CODE:nginx.bad_static_dir"));
    }
    let dest = lo.www_store.join(root);
    std::fs::create_dir_all(&dest)?;
    if clear {
        // Wipe contents but keep the directory itself.
        if let Ok(entries) = std::fs::read_dir(&dest) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                } else {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    match mode {
        "zip" => {
            let f = std::fs::File::open(temp)?;
            extract_zip_from(f, &dest)
        }
        "file" => {
            let rel = rel.ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_file_path"))?;
            let safe = sanitize_rel(rel).ok_or_else(|| anyhow!("ERR_CODE:nginx.bad_file_path"))?;
            let target = dest.join(&safe);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(temp, &target)?; // streamed copy, bounded memory
            Ok(1)
        }
        _ => Err(anyhow!("ERR_CODE:nginx.unknown_upload_mode")),
    }
}

/// Sanitize a relative path from an upload: reject absolute paths, `..`
/// traversal, and empty/oversized names. Returns a safe relative PathBuf.
fn sanitize_rel(rel: &str) -> Option<std::path::PathBuf> {
    let rel = rel.trim().replace('\\', "/");
    if rel.is_empty() || rel.len() > 1024 {
        return None;
    }
    let mut out = std::path::PathBuf::new();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return None; // no traversal
        }
        // Reject NUL and control chars; allow normal filename characters.
        if seg.chars().any(|c| c.is_control()) {
            return None;
        }
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    Some(out)
}

/// Extract a ZIP archive (pure-Rust `zip` crate) into `dest`, guarding against
/// path traversal. Returns the number of files written.
fn extract_zip_from<R: std::io::Read + std::io::Seek>(
    reader: R,
    dest: &std::path::Path,
) -> Result<usize> {
    let mut zip = zip::ZipArchive::new(reader).map_err(|e| anyhow!("无法读取 ZIP：{e}"))?;
    let mut count = 0usize;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| anyhow!("读取 ZIP 条目失败：{e}"))?;
        // Use the archive's declared name; sanitize against traversal.
        let name = match entry.enclosed_name() {
            Some(p) => p.to_string_lossy().to_string(),
            None => continue,
        };
        if entry.is_dir() {
            let safe = match sanitize_rel(&name) {
                Some(p) => p,
                None => continue,
            };
            std::fs::create_dir_all(dest.join(safe))?;
            continue;
        }
        let safe = match sanitize_rel(&name) {
            Some(p) => p,
            None => continue,
        };
        let target = dest.join(&safe);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&target)?;
        std::io::copy(&mut entry, &mut out)?;
        count += 1;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Channel runner + dispatch.
// ---------------------------------------------------------------------------

/// Public entrypoint for the local web console: parse a JSON request and run it.
pub async fn web_dispatch(req: &Value) -> Result<Value> {
    let r: Req =
        serde_json::from_value(req.clone()).map_err(|e| anyhow!("bad nginx request: {e}"))?;
    handle(&r).await
}

async fn handle(req: &Req) -> Result<Value> {
    match req.op.as_str() {
        "info" => nginx_info().await,
        "setup" => start_setup(req),
        "list_sites" => Ok(json!({ "sites": load_sites() })),
        "add_site" => add_site(req).await,
        "update_site" => update_site(req).await,
        "remove_site" => remove_site(req).await,
        "list_named_certs" => list_named_certs().await,
        "create_cert" => create_cert(req).await,
        "delete_cert" => delete_cert(req).await,
        "list_access" => list_access().await,
        "save_access" => save_access_op(req).await,
        "delete_access" => delete_access_op(req).await,
        "get_settings" => get_web_settings().await,
        "set_default_site" => set_default_site(req).await,
        "reload" => {
            reload().await?;
            Ok(json!({ "reloaded": true }))
        }
        "list_containers" => list_running_containers().await,
        "list_ops" => Ok(ops_snapshot()),
        "op_log" => Ok(op_log(req.op_id.as_deref().unwrap_or(""))),
        "dismiss_op" => {
            if let Some(op_id) = req.op_id.as_deref() {
                op_dismiss(op_id);
            }
            Ok(json!({ "dismissed": true }))
        }
        other => Err(anyhow!("unsupported op: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Command helpers.
// ---------------------------------------------------------------------------

/// Run a command, returning (success, stdout, stderr).
async fn run(cmd: &str, args: &[&str]) -> Result<(bool, String, String)> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    ))
}

fn trim_msg(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(500).collect())
}

/// Run a shell script (used for docker exec into the nginx container, etc).
async fn sh(script: &str) -> Result<(bool, String, String)> {
    run("sh", &["-c", script]).await
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc_getuid() == 0 }
}
#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

// ---------------------------------------------------------------------------
// Detection: what's installed / occupying 80+443, and our current managed mode.
// ---------------------------------------------------------------------------

/// Detect the host nginx binary + whether it (or anything) holds 80/443, plus
/// whether we've completed setup. Never errors — a clean host reports
/// everything false so the UI can drive the setup flow.
async fn nginx_info() -> Result<Value> {
    // Host nginx binary + version.
    let (ok, _o, e) = run("nginx", &["-v"])
        .await
        .unwrap_or((false, String::new(), String::new()));
    // `nginx -v` prints to stderr like "nginx version: nginx/1.24.0".
    let host_nginx_present = ok;
    let host_nginx_version = if ok {
        e.split('/')
            .nth(1)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Who's listening on 80 / 443?
    let p80 = port_listener(80).await;
    let p443 = port_listener(443).await;

    // host nginx "owns" 80/443 if the listener process looks like nginx.
    let host_owns_ports = p80.contains("nginx") || p443.contains("nginx");

    Ok(json!({
        "managed": is_setup(),                  // setup completed?
        "host_nginx_present": host_nginx_present,
        "host_nginx_version": host_nginx_version,
        "host_owns_ports": host_owns_ports,
        "port80": p80,                          // listener description ("" if free)
        "port443": p443,
        "is_root": is_root(),
    }))
}

/// Best-effort: a short description of what's listening on `port` (process name)
/// or "" if it appears free. Tries `ss`, then `lsof`, then a pure-Rust
/// `/proc/net` fallback so it still works when neither tool is installed.
async fn port_listener(port: u16) -> String {
    if let Ok((true, out, _)) = run("ss", &["-ltnp"]).await {
        for line in out.lines() {
            if line.contains(&format!(":{port}")) && line.to_lowercase().contains("listen") {
                // Extract a process name from users:(("nginx",pid=..)).
                if let Some(idx) = line.find("users:((\"") {
                    let rest = &line[idx + 9..];
                    if let Some(end) = rest.find('"') {
                        return rest[..end].to_string();
                    }
                }
                return "占用".to_string();
            }
        }
        return String::new();
    }
    // Fallback: lsof.
    if let Ok((true, out, _)) =
        run("lsof", &["-i", &format!(":{port}"), "-sTCP:LISTEN", "-Pn"]).await
    {
        if let Some(line) = out.lines().nth(1) {
            return line.split_whitespace().next().unwrap_or("占用").to_string();
        }
    }
    // Last resort: parse /proc directly (no external tools needed).
    proc_port_listener(port)
}

/// Pure-Rust port-listener probe: scan `/proc/net/tcp` + `tcp6` for a socket in
/// the LISTEN state on `port`, then resolve its owning process name by matching
/// the socket inode against `/proc/<pid>/fd`. Returns the process name, a
/// generic "占用" if the port is held but the owner can't be resolved, or "" if
/// the port appears free.
fn proc_port_listener(port: u16) -> String {
    let inode = match listening_inode("/proc/net/tcp", port)
        .or_else(|| listening_inode("/proc/net/tcp6", port))
    {
        Some(i) => i,
        None => return String::new(),
    };
    proc_name_for_inode(inode).unwrap_or_else(|| "占用".to_string())
}

/// Find the socket inode listening on `port` in a `/proc/net/tcp{,6}` file.
/// Columns: `sl local_address rem_address st ... inode`. `local_address` is
/// `HEXIP:HEXPORT`; LISTEN state is `0A`.
fn listening_inode(path: &str, port: u16) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if cols[3] != "0A" {
            continue; // not LISTEN
        }
        let local_port = cols[1]
            .rsplit(':')
            .next()
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        if local_port != Some(port) {
            continue;
        }
        if let Ok(inode) = cols[9].parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

/// Resolve the process name owning a socket `inode` by scanning `/proc/<pid>/fd`
/// for a `socket:[<inode>]` symlink, then reading `/proc/<pid>/comm`.
fn proc_name_for_inode(inode: u64) -> Option<String> {
    let want = format!("socket:[{inode}]");
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid = match name.to_str().and_then(|s| s.parse::<u32>().ok()) {
            Some(p) => p,
            None => continue, // not a pid dir
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => continue, // no permission / process gone
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if target.to_string_lossy() == want {
                    return std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                }
            }
        }
    }
    None
}

/// List running containers (name + published port hint) so the proxy form can
/// offer "forward to container:port" targets. Uses the daemon API (no `docker`
/// CLI); returns empty if Docker isn't present.
async fn list_running_containers() -> Result<Value> {
    let dkr = crate::docker::dkr()?;
    let opts = bollard::container::ListContainersOptions::<String> {
        all: false,
        ..Default::default()
    };
    let containers = dkr
        .list_containers(Some(opts))
        .await
        .map_err(|e| anyhow!(trim_msg(&e.to_string()).unwrap_or_else(|| "无法获取容器".into())))?;
    let mut items = Vec::new();
    for c in containers {
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|s| s.trim_start_matches('/').to_string())
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let ports = c
            .ports
            .as_ref()
            .map(|ps| {
                let mut v: Vec<String> = ps
                    .iter()
                    .map(|p| {
                        let proto = p
                            .typ
                            .map(|t| format!("{t:?}").to_lowercase())
                            .unwrap_or_else(|| "tcp".into());
                        match p.public_port {
                            Some(pp) => format!("{pp}->{}/{proto}", p.private_port),
                            None => format!("{}/{proto}", p.private_port),
                        }
                    })
                    .collect();
                v.sort();
                v.dedup();
                v.join(", ")
            })
            .unwrap_or_default();
        items.push(json!({
            "name": name,
            "ports": ports,
            "image": c.image.clone().unwrap_or_default(),
        }));
    }
    Ok(json!({ "containers": items }))
}

// ---------------------------------------------------------------------------
// Validation (no raw config; everything is form-driven and checked).
// ---------------------------------------------------------------------------

// Validators (valid_server_name, primary_host, valid_host_token, …) live in
// the `validate` submodule.

// ---------------------------------------------------------------------------
// Setup: install host nginx OR create the docker nginx container. Detached.
// ---------------------------------------------------------------------------

fn start_setup(req: &Req) -> Result<Value> {
    let _ = req;
    const SETUP_OP: &str = "setup";
    if opreg::op_running(SETUP_OP) {
        return Ok(json!({ "op_id": SETUP_OP, "already_running": true }));
    }
    if !is_root() {
        return Err(anyhow!("ERR_CODE:nginx.need_root"));
    }

    op_create(SETUP_OP, "setup", "host");
    tokio::spawn(async move {
        match setup_host(SETUP_OP).await {
            Ok(()) => {
                let _ = mark_setup();
                op_push(SETUP_OP, &pmsg("ng.setup_done", &[]));
                op_finish(SETUP_OP, "done", "");
            }
            Err(e) => op_finish(SETUP_OP, "error", &e.to_string()),
        }
    });
    Ok(json!({ "op_id": SETUP_OP, "target": "host" }))
}

/// Ensure host nginx is installed (distro package manager), enabled, running,
/// and that our conf.d drop-in dir + state dirs exist.
async fn setup_host(op_id: &str) -> Result<()> {
    // Already present?
    if run("nginx", &["-v"])
        .await
        .map(|(ok, ..)| ok)
        .unwrap_or(false)
    {
        op_push(op_id, &pmsg("ng.detected_host", &[]));
    } else {
        op_push(op_id, &pmsg("ng.installing", &[]));
        let script = r#"set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get install -y nginx
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y nginx
elif command -v yum >/dev/null 2>&1; then
  yum install -y nginx
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache nginx
else
  echo "no supported package manager" >&2; exit 1
fi"#;
        stream_sh(op_id, script).await?;
    }

    op_push(op_id, &pmsg("ng.ensure_enable", &[]));
    let _ = sh(&format!("mkdir -p {HOST_CONFD}")).await;
    // Our state dirs (certs + webroots) that nginx reads from.
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    let _ = sh("systemctl enable nginx 2>/dev/null || true; systemctl restart nginx 2>/dev/null || service nginx restart 2>/dev/null || nginx 2>/dev/null || true").await;

    // Verify it's runnable.
    let (ok, _, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置测试失败".into())
        ));
    }
    Ok(())
}

/// Stream a shell script's output into the op log, erroring on non-zero exit.
async fn stream_sh(op_id: &str, script: &str) -> Result<()> {
    stream_cmd(op_id, "sh", &["-c", script]).await
}

/// Stream a command's combined output into the op log, erroring on non-zero.
async fn stream_cmd(op_id: &str, cmd: &str, args: &[&str]) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let mut child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("无法执行 {cmd}：{e}"))?;
    // Drain stderr concurrently so a child that fills the stderr pipe can't
    // deadlock against us waiting on stdout.
    let stderr = child.stderr.take();
    let err_task = tokio::spawn(async move {
        let mut buf = String::new();
        if let Some(mut er) = stderr {
            let _ = er.read_to_string(&mut buf).await;
        }
        buf
    });
    if let Some(out) = child.stdout.take() {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            op_push(op_id, line.trim());
        }
    }
    let status = child
        .wait()
        .await
        .map_err(|e| anyhow!("{cmd} 执行失败：{e}"))?;
    let err = err_task.await.unwrap_or_default();
    for line in err
        .lines()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        op_push(op_id, line.trim());
    }
    if !status.success() {
        return Err(anyhow!("{cmd} 返回非零退出码"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sites: add / remove / generate config / reload.
// ---------------------------------------------------------------------------

/// Where generated conf files live, and the paths the running host nginx reads
/// certs/webroots from. Host-only: nginx reads the same on-disk paths we write.
#[derive(Clone)]
struct Layout {
    confd: std::path::PathBuf, // where we WRITE conf files (/etc/nginx/conf.d)
    cert_ref: String,          // dir nginx READS certs from (== cert_store)
    www_ref: String,           // dir nginx READS webroots from (== www_store)
    cert_store: std::path::PathBuf, // where we WRITE cert files
    www_store: std::path::PathBuf, // where we WRITE webroots
}

fn layout() -> Result<Layout> {
    if !is_setup() {
        return Err(anyhow!("ERR_CODE:nginx.not_setup"));
    }
    std::fs::create_dir_all(certs_dir())?;
    std::fs::create_dir_all(www_dir())?;
    ensure_shared_conf();
    Ok(Layout {
        confd: std::path::PathBuf::from(HOST_CONFD),
        cert_ref: certs_dir().display().to_string(),
        www_ref: www_dir().display().to_string(),
        cert_store: certs_dir(),
        www_store: www_dir(),
    })
}

/// Write the shared http-context `map` once, so proxied sites can set the
/// WebSocket `Connection` header correctly: a normal request → `close`, a real
/// upgrade → `upgrade`. (Hardcoding `Connection: upgrade` on every request, as
/// older builds did, makes some backends abort plain HTTP requests, which the
/// browser surfaces as ERR_EMPTY_RESPONSE.) Named `00-` so it loads first and
/// isn't matched by the `dn7-<id>.conf` orphan cleanup.
fn ensure_shared_conf() {
    let path = std::path::Path::new(HOST_CONFD).join("00-dn7-maps.conf");
    let body = "map $http_upgrade $dn7_conn_upgrade {\n    default upgrade;\n    '' close;\n}\n\n\
                map $http_x_forwarded_proto $dn7_fwd_proto {\n    default $http_x_forwarded_proto;\n    '' $scheme;\n}\n";
    if std::fs::read_to_string(&path).ok().as_deref() != Some(body) {
        let _ = std::fs::create_dir_all(HOST_CONFD);
        let _ = std::fs::write(&path, body);
    }
}

fn conf_path(lo: &Layout, site_id: &str) -> std::path::PathBuf {
    lo.confd.join(format!("dn7-{site_id}.conf"))
}

/// Build a site from the request, validating every field.
fn site_from_req(req: &Req) -> Result<Site> {
    let server_name = req
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_domain"))?
        .to_string();
    if !valid_server_name(&server_name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_domain"));
    }
    let kind = req.kind.as_deref().unwrap_or("proxy_host").to_string();
    let ssl = req.ssl.unwrap_or(false);
    let cert_mode = req.cert_mode.as_deref().unwrap_or("self").to_string();
    let cert_name = req
        .cert_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !cert_name.is_empty() && !valid_cert_name(&cert_name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_cert_name"));
    }

    let mut site = Site {
        id: new_site_id(),
        server_name,
        kind: kind.clone(),
        target_url: String::new(),
        container: String::new(),
        container_port: 0,
        root: String::new(),
        ssl,
        cert_mode: cert_mode.clone(),
        cert_name: cert_name.clone(),
        scheme: norm_scheme(req.scheme.as_deref()),
        cache: req.cache.unwrap_or(false),
        block_attacks: req.block_attacks.unwrap_or(false),
        websockets: req.websockets.unwrap_or(true),
        force_ssl: req.force_ssl.unwrap_or(true),
        http2: req.http2.unwrap_or(true),
        hsts: req.hsts.unwrap_or(false),
        hsts_sub: req.hsts_sub.unwrap_or(false),
        trust_proxy: req.trust_proxy.unwrap_or(false),
        locations: Vec::new(),
        extra_conf: String::new(),
        access_id: String::new(),
    };

    match kind.as_str() {
        "proxy_host" => {
            let t = req
                .target_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_target"))?;
            if !valid_host_token(t) {
                return Err(anyhow!("ERR_CODE:nginx.bad_target"));
            }
            site.target_url = t.to_string();
        }
        "proxy_container" => {
            let c = req
                .container
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_container"))?;
            if !valid_container_name(c) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container"));
            }
            let port = req.container_port.unwrap_or(0);
            if !valid_port(port) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container_port"));
            }
            site.container = c.to_string();
            site.container_port = port;
        }
        "static" => {
            let r = req
                .root
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_static_dir"))?;
            if !valid_root_segment(r) {
                return Err(anyhow!("ERR_CODE:nginx.bad_static_dir_name"));
            }
            site.root = r.to_string();
        }
        _ => return Err(anyhow!("ERR_CODE:nginx.unknown_site_kind")),
    }

    // Validate + normalize any custom path rules.
    if let Some(locs) = &req.locations {
        site.locations = validate_locations(locs)?;
    }

    // Optional raw nginx directives (validated structurally here; nginx -t is
    // the final gate when the conf is written).
    let extra = req.extra_conf.as_deref().unwrap_or("").trim();
    validate_extra_conf(extra)?;
    site.extra_conf = extra.to_string();

    // Optional access list reference — must exist when set.
    let access_id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if !access_id.is_empty() && !load_access().iter().any(|a| a.id == access_id) {
        return Err(anyhow!("ERR_CODE:nginx.access_not_found"));
    }
    site.access_id = access_id;

    if ssl && !matches!(cert_mode.as_str(), "self" | "le" | "manual" | "named") {
        return Err(anyhow!("ERR_CODE:nginx.unknown_cert_mode"));
    }
    Ok(site)
}

/// Validate + normalize a list of custom path rules.
fn validate_locations(locs: &[Location]) -> Result<Vec<Location>> {
    let mut out = Vec::new();
    for l in locs {
        let path = l.path.trim();
        let kind = if l.kind.trim() == "container" {
            "container"
        } else {
            "host"
        };
        if kind == "container" {
            let container = l.container.trim();
            // Skip fully-empty rows.
            if path.is_empty() && container.is_empty() {
                continue;
            }
            if !valid_location_path(path) {
                return Err(anyhow!("路径规则需以 / 开头且不含空格等特殊字符：{path}"));
            }
            if !valid_container_name(container) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container"));
            }
            if !valid_port(l.container_port) {
                return Err(anyhow!("ERR_CODE:nginx.bad_container_port"));
            }
            out.push(Location {
                path: path.to_string(),
                scheme: norm_scheme(Some(&l.scheme)),
                target: String::new(),
                websockets: l.websockets,
                kind: "container".to_string(),
                container: container.to_string(),
                container_port: l.container_port,
            });
        } else {
            let target = l.target.trim();
            // Skip fully-empty rows (UI may submit blank trailing rows).
            if path.is_empty() && target.is_empty() {
                continue;
            }
            if !valid_location_path(path) {
                return Err(anyhow!("路径规则需以 / 开头且不含空格等特殊字符：{path}"));
            }
            if !valid_host_token(target) {
                return Err(anyhow!("路径规则目标格式不正确（host[:port]）：{target}"));
            }
            out.push(Location {
                path: path.to_string(),
                scheme: norm_scheme(Some(&l.scheme)),
                target: target.to_string(),
                websockets: l.websockets,
                kind: "host".to_string(),
                container: String::new(),
                container_port: 0,
            });
        }
    }
    if out.len() > 50 {
        return Err(anyhow!("ERR_CODE:nginx.too_many_rules"));
    }
    Ok(out)
}

/// Structural validation of raw custom nginx directives. The authoritative
/// syntax check is `nginx -t` (run when the conf is written, with rollback on
/// failure); here we only reject oversized input and stray control characters.
fn validate_extra_conf(s: &str) -> Result<()> {
    if s.len() > 20000 {
        return Err(anyhow!("ERR_CODE:nginx.extra_conf_too_long"));
    }
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(anyhow!("ERR_CODE:nginx.extra_conf_bad"));
    }
    Ok(())
}

/// Indent raw custom directives into the server block. Empty when blank.
fn render_extra_conf(raw: &str) -> String {
    let raw = raw.trim();
    if raw.is_empty() {
        return String::new();
    }
    let mut s = String::from("\n    # custom configuration\n");
    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            s.push('\n');
        } else {
            s.push_str("    ");
            s.push_str(line);
            s.push('\n');
        }
    }
    s
}

fn new_site_id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}{}",
        std::process::id() % 100000,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Remove panel-owned conf files that could shadow a fresh write: temporary
/// ACME challenge confs (always disposable) and orphaned `dn7-<id>.conf` files
/// whose site no longer exists (leftovers from an interrupted attempt). A stale
/// conf with the same `server_name` loading before the live one makes nginx
/// answer from the wrong block — which breaks HTTP-01 validation (404).
fn cleanup_orphan_confs(lo: &Layout) {
    use std::collections::HashSet;
    // Determine live site ids safely. If sites.json exists but can't be read or
    // parsed, do NOT treat every conf as an orphan (that would delete all site
    // configs) — skip cleanup this round.
    let path = sites_file();
    let live: HashSet<String> = if path.exists() {
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<Site>>(&s).ok())
        {
            Some(sites) => sites.into_iter().map(|s| s.id).collect(),
            None => return, // unreadable/corrupt — be safe, remove nothing
        }
    } else {
        HashSet::new() // no sites file → any dn7-*.conf is a genuine orphan
    };
    let rd = match std::fs::read_dir(&lo.confd) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(id) = name
            .strip_prefix("dn7-")
            .and_then(|s| s.strip_suffix(".conf"))
        {
            if !live.contains(id) {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if name.starts_with("acme-") && name.ends_with(".conf") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// True if another managed site (≠ `exclude_id`) already uses `server_name` —
/// two server blocks with the same name on :80 conflict (nginx serves the
/// first-loaded one), which silently breaks the other site + its HTTP-01.
fn server_name_taken(server_name: &str, exclude_id: &str) -> bool {
    load_sites()
        .iter()
        .any(|s| s.id != exclude_id && s.server_name == server_name)
}

/// Regenerate every managed site's conf from the *current* template and reload
/// once. Called at panel startup so a config written by an older build (e.g.
/// the legacy `http2 on;` directive that older nginx rejects) is healed
/// automatically after an upgrade — instead of lingering and failing `nginx -t`
/// for every subsequent operation. Best-effort: an SSL site whose cert file is
/// missing is regenerated as plain HTTP so one broken site can't fail the whole
/// `nginx -t`; per-site write errors (e.g. a container IP unresolvable while
/// Docker is still starting) are logged and skipped.
pub async fn resync_confs() {
    if !is_setup() {
        return;
    }
    let lo = match layout() {
        Ok(l) => l,
        Err(_) => return,
    };
    cleanup_orphan_confs(&lo);
    let mut wrote = false;
    for mut site in load_sites() {
        if site.ssl {
            let have = if site.cert_name.is_empty() {
                lo.cert_store.join(format!("{}.crt", site.id)).exists()
                    && lo.cert_store.join(format!("{}.key", site.id)).exists()
            } else {
                named_crt_file(&lo, &site.cert_name).exists()
            };
            if !have {
                site.ssl = false; // degrade to HTTP so the regenerated conf stays valid
            }
        }
        match write_site_conf(&lo, &site, &[]).await {
            Ok(()) => wrote = true,
            Err(e) => tracing::warn!(site = %site.server_name, "resync conf failed: {e}"),
        }
    }
    // Re-apply the default-site catch-all if it has been configured.
    if websettings_file().exists() {
        if let Err(e) = write_default_conf(&lo, &load_webglobal()).await {
            tracing::warn!("default-site conf resync failed: {e}");
        } else {
            wrote = true;
        }
    }
    if wrote {
        if let Err(e) = validate_and_reload(&lo).await {
            tracing::warn!("nginx conf resync reload failed: {e}");
        } else {
            tracing::info!("nginx site confs resynced to current template");
        }
    }
}

/// Days from `date` ("YYYY-MM-DD") until today (negative once past).
fn days_until(date: &str) -> Option<i64> {
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
fn cert_due(path: &std::path::Path, within_days: i64) -> bool {
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
    for site in load_sites() {
        if !site.ssl || !site.cert_name.is_empty() {
            continue; // named certs handled below; manual isn't auto-renewed
        }
        let crt = lo.cert_store.join(format!("{}.crt", site.id));
        if !cert_due(&crt, WITHIN) {
            continue;
        }
        match site.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&site.server_name));
                match issue_le(&op_id, &lo, &site).await {
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
                if gen_self_signed(&lo, &site).await.is_ok() {
                    let _ = write_site_conf(&lo, &site, &[]).await;
                    let _ = validate_and_reload(&lo).await;
                }
            }
            _ => {}
        }
    }
    for c in load_named_certs() {
        if c.domain.is_empty() {
            continue;
        }
        let crt = named_crt_file(&lo, &c.name);
        if !cert_due(&crt, WITHIN) {
            continue;
        }
        match c.cert_mode.as_str() {
            "le" => {
                let op_id = new_op_id();
                op_create(&op_id, "cert", &primary_host(&c.domain));
                match issue_le_named(&op_id, &lo, &c.name, &c.domain).await {
                    Ok(()) => op_finish(&op_id, "done", ""),
                    Err(e) => op_finish(&op_id, "error", &e.to_string()),
                }
            }
            "self" => {
                let host = primary_host(&c.domain);
                let _ = gen_self_signed_to(
                    &named_crt_file(&lo, &c.name),
                    &named_key_file(&lo, &c.name),
                    &host,
                )
                .await;
            }
            _ => continue,
        }
        // Sites reference the named cert files directly, so reload nginx to pick
        // up the freshly renewed certificate.
        let _ = validate_and_reload(&lo).await;
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

/// Add a site. For SSL with Let's Encrypt, issuance runs detached (returns an
/// op_id); otherwise the site is generated + validated synchronously.
async fn add_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    cleanup_orphan_confs(&lo);
    let site = site_from_req(req)?;
    if server_name_taken(&site.server_name, &site.id) {
        return Err(anyhow!("ERR_CODE:nginx.duplicate_domain"));
    }

    // Prepare certs.
    if site.ssl {
        if !site.cert_name.is_empty() {
            // Reference an existing standalone named cert — must already exist.
            if !named_crt_file(&lo, &site.cert_name).exists() {
                return Err(anyhow!("引用的证书「{}」不存在", site.cert_name));
            }
        } else {
            match site.cert_mode.as_str() {
                "self" => {
                    gen_self_signed(&lo, &site).await?;
                }
                "manual" => {
                    let cert = req.cert_pem.as_deref().unwrap_or("");
                    let key = req.key_pem.as_deref().unwrap_or("");
                    if cert.trim().is_empty() || key.trim().is_empty() {
                        return Err(anyhow!("ERR_CODE:nginx.need_cert_key"));
                    }
                    write_cert_files(&lo, &site, cert, key)?;
                }
                "le" => {
                    // Detached: write an HTTP-only site first so the ACME http-01
                    // challenge can be served, then issue, then rewrite with SSL.
                    return start_cert_issue(lo, site).await;
                }
                _ => {}
            }
        }
    }

    // Generate + validate.
    write_site_conf(&lo, &site, &[]).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back the conf we just wrote.
        let _ = std::fs::remove_file(conf_path(&lo, &site.id));
        return Err(e);
    }

    let mut sites = load_sites();
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(json!({ "site": site }))
}

async fn remove_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site_id = req
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_site_id"))?;
    let mut sites = load_sites();
    let before = sites.len();
    let removed: Vec<Site> = sites.iter().filter(|s| s.id == site_id).cloned().collect();
    sites.retain(|s| s.id != site_id);
    if sites.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.site_not_found"));
    }
    let _ = std::fs::remove_file(conf_path(&lo, site_id));
    // Clean up cert files for removed sites (best-effort).
    for s in &removed {
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.crt", s.id)));
        let _ = std::fs::remove_file(lo.cert_store.join(format!("{}.key", s.id)));
    }
    save_sites(&sites)?;
    let _ = validate_and_reload(&lo).await;
    Ok(json!({ "removed": site_id }))
}

/// Edit an existing site in place (same id). Mirrors `add_site`'s validation +
/// cert handling, but reuses the existing id and rolls back to the previous
/// config on a validation failure. To avoid needless churn (and Let's Encrypt
/// rate limits), an existing cert is reused when the SSL mode/host is unchanged
/// and a cert is already present; manual mode keeps the stored cert when no new
/// PEM is supplied.
async fn update_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let site_id = req
        .site_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_site_id"))?;
    let mut sites = load_sites();
    let old = sites
        .iter()
        .find(|s| s.id == site_id)
        .cloned()
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.site_not_found"))?;

    let mut site = site_from_req(req)?;
    site.id = old.id.clone();
    if server_name_taken(&site.server_name, &site.id) {
        return Err(anyhow!("ERR_CODE:nginx.duplicate_domain"));
    }
    cleanup_orphan_confs(&lo);

    if site.ssl {
        if !site.cert_name.is_empty() {
            if !named_crt_file(&lo, &site.cert_name).exists() {
                return Err(anyhow!("ERR_CODE:nginx.cert_not_found"));
            }
        } else {
            let have = lo.cert_store.join(format!("{}.crt", site.id)).exists()
                && lo.cert_store.join(format!("{}.key", site.id)).exists();
            match site.cert_mode.as_str() {
                "manual" => {
                    let cert = req.cert_pem.as_deref().unwrap_or("");
                    let key = req.key_pem.as_deref().unwrap_or("");
                    if !cert.trim().is_empty() && !key.trim().is_empty() {
                        write_cert_files(&lo, &site, cert, key)?;
                    } else if !have {
                        return Err(anyhow!("ERR_CODE:nginx.need_cert_key"));
                    }
                }
                "le" => {
                    let host_changed =
                        primary_host(&old.server_name) != primary_host(&site.server_name);
                    if !have || old.cert_mode != "le" || !old.cert_name.is_empty() || host_changed {
                        // Needs a (re)issue → detached.
                        return start_cert_issue(lo, site).await;
                    }
                    // else: reuse the existing LE cert as-is.
                }
                "self" => {
                    if !have || old.cert_mode != "self" || !old.cert_name.is_empty() {
                        gen_self_signed(&lo, &site).await?;
                    }
                }
                _ => {}
            }
        }
    }

    write_site_conf(&lo, &site, &[]).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back to the previous configuration.
        let _ = write_site_conf(&lo, &old, &[]).await;
        let _ = validate_and_reload(&lo).await;
        return Err(e);
    }
    sites.retain(|s| s.id != site.id);
    sites.push(site.clone());
    save_sites(&sites)?;
    Ok(json!({ "site": site }))
}

// ---------------------------------------------------------------------------
// Standalone named certificates: create / list / delete, independent of sites.
// ---------------------------------------------------------------------------

/// List standalone certs from the manifest, with on-disk presence + expiry.
async fn list_named_certs() -> Result<Value> {
    let lo = layout()?;
    let certs = load_named_certs();
    let in_use = sites_using_certs();
    let mut out = Vec::new();
    for c in &certs {
        let crt = named_crt_file(&lo, &c.name);
        let has_cert = crt.exists();
        let not_after = if has_cert {
            std::fs::read_to_string(&crt)
                .ok()
                .and_then(|pem| cert_not_after(&pem))
                .unwrap_or_default()
        } else {
            String::new()
        };
        out.push(json!({
            "name": c.name,
            "domain": c.domain,
            "cert_mode": c.cert_mode,
            "has_cert": has_cert,
            "not_after": not_after,
            "used_by": in_use.get(&c.name).cloned().unwrap_or_default(),
        }));
    }
    Ok(json!({ "certs": out }))
}

/// server_names of sites currently referencing each named cert.
fn sites_using_certs() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for s in load_sites() {
        if !s.cert_name.is_empty() {
            map.entry(s.cert_name).or_default().push(s.server_name);
        }
    }
    map
}

/// Create a standalone named certificate. Modes:
///   - "self":   self-signed for `domain` (synchronous)
///   - "manual": cert_pem + key_pem (synchronous)
///   - "le":     Let's Encrypt for `domain` (detached → returns {op_id})
async fn create_cert(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let name = req
        .cert_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_cert_name"))?
        .to_string();
    if !valid_cert_name(&name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_cert_name_chars"));
    }
    let mode = req.cert_mode.as_deref().unwrap_or("self");
    if !matches!(mode, "self" | "le" | "manual") {
        return Err(anyhow!("ERR_CODE:nginx.unknown_cert_mode"));
    }
    let mut certs = load_named_certs();
    if certs.iter().any(|c| c.name == name) {
        return Err(anyhow!("ERR_CODE:nginx.cert_exists"));
    }
    let domain = req
        .server_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    // One certificate per domain: reject a second named cert for the same host.
    if !domain.is_empty()
        && certs
            .iter()
            .any(|c| !c.domain.is_empty() && c.domain.eq_ignore_ascii_case(&domain))
    {
        return Err(anyhow!("ERR_CODE:nginx.cert_domain_exists"));
    }

    match mode {
        "self" => {
            if domain.is_empty() {
                return Err(anyhow!("ERR_CODE:nginx.need_cert_domain"));
            }
            if !valid_server_name(&domain) {
                return Err(anyhow!("ERR_CODE:nginx.bad_domain"));
            }
            let host = primary_host(&domain);
            gen_self_signed_to(
                &named_crt_file(&lo, &name),
                &named_key_file(&lo, &name),
                &host,
            )
            .await?;
        }
        "manual" => {
            let cert = req.cert_pem.as_deref().unwrap_or("");
            let key = req.key_pem.as_deref().unwrap_or("");
            if cert.trim().is_empty() || key.trim().is_empty() {
                return Err(anyhow!("ERR_CODE:nginx.need_cert_key"));
            }
            std::fs::create_dir_all(&lo.cert_store)?;
            std::fs::write(named_crt_file(&lo, &name), cert)?;
            write_key_file(&named_key_file(&lo, &name), key)?;
        }
        "le" => {
            if domain.is_empty() || !valid_server_name(&domain) {
                return Err(anyhow!("ERR_CODE:nginx.le_need_domain"));
            }
            return start_named_cert_issue(lo, name, domain);
        }
        _ => {}
    }

    certs.push(NamedCert {
        name: name.clone(),
        domain,
        cert_mode: mode.to_string(),
    });
    save_named_certs(&certs)?;
    Ok(json!({ "name": name }))
}

/// Delete a standalone named certificate. Refuses while a site still uses it.
async fn delete_cert(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let name = req
        .cert_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_cert_name"))?;
    let in_use = sites_using_certs();
    if let Some(sites) = in_use.get(name) {
        if !sites.is_empty() {
            return Err(anyhow!("证书仍被站点使用：{}", sites.join("、")));
        }
    }
    let mut certs = load_named_certs();
    let before = certs.len();
    certs.retain(|c| c.name != name);
    if certs.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.cert_not_found"));
    }
    let _ = std::fs::remove_file(named_crt_file(&lo, name));
    let _ = std::fs::remove_file(named_key_file(&lo, name));
    save_named_certs(&certs)?;
    Ok(json!({ "deleted": name }))
}

// ---------------------------------------------------------------------------
// Access lists: list / create-or-update / delete, plus default-site settings.
// ---------------------------------------------------------------------------

/// server_names of sites currently using each access list id.
fn sites_using_access() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for s in load_sites() {
        if !s.access_id.is_empty() {
            map.entry(s.access_id).or_default().push(s.server_name);
        }
    }
    map
}

/// List access lists (without password hashes), with usage info.
async fn list_access() -> Result<Value> {
    let lists = load_access();
    let in_use = sites_using_access();
    let out: Vec<Value> = lists
        .iter()
        .map(|a| {
            json!({
                "id": a.id,
                "name": a.name,
                "satisfy": if a.satisfy == "all" { "all" } else { "any" },
                "pass_auth": a.pass_auth,
                "users": a.users.iter().map(|u| json!({ "username": u.username })).collect::<Vec<_>>(),
                "clients": a.clients,
                "used_by": in_use.get(&a.id).cloned().unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({ "access": out }))
}

/// Create (no access_id) or update (existing access_id) an access list.
async fn save_access_op(req: &Req) -> Result<Value> {
    let _ = layout()?; // require setup
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_access_name"))?
        .to_string();
    if !valid_access_name(&name) {
        return Err(anyhow!("ERR_CODE:nginx.bad_access_name"));
    }
    let satisfy = match req.satisfy.as_deref().unwrap_or("any") {
        "all" => "all",
        _ => "any",
    }
    .to_string();
    let pass_auth = req.pass_auth.unwrap_or(false);

    // Validate clients.
    let mut clients = Vec::new();
    for c in req.clients.clone().unwrap_or_default() {
        let dir = if c.directive == "deny" {
            "deny"
        } else {
            "allow"
        };
        if !valid_client_address(&c.address) {
            return Err(anyhow!("ERR_CODE:nginx.bad_client_addr"));
        }
        clients.push(AccessClient {
            directive: dir.to_string(),
            address: c.address.trim().to_string(),
        });
    }

    let mut lists = load_access();
    let existing_id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let old = existing_id
        .as_ref()
        .and_then(|id| lists.iter().find(|a| &a.id == id).cloned());

    // Build the user list: a provided password (re)hashes; an empty password on
    // an existing username reuses the stored hash.
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for u in req.users.clone().unwrap_or_default() {
        let username = u.username.trim().to_string();
        if username.is_empty() {
            continue;
        }
        if !valid_auth_username(&username) {
            return Err(anyhow!("ERR_CODE:nginx.bad_auth_user"));
        }
        if !seen.insert(username.clone()) {
            return Err(anyhow!("ERR_CODE:nginx.dup_auth_user"));
        }
        let hash = if !u.password.is_empty() {
            if u.password.len() > 128 {
                return Err(anyhow!("ERR_CODE:nginx.bad_auth_pw"));
            }
            htpasswd_hash(&u.password)
        } else {
            // Reuse an existing hash for this username (edit without new pw).
            old.as_ref()
                .and_then(|o| o.users.iter().find(|x| x.username == username))
                .map(|x| x.hash.clone())
                .ok_or_else(|| anyhow!("ERR_CODE:nginx.need_auth_pw"))?
        };
        users.push(AccessUser { username, hash });
    }

    let id = existing_id.clone().unwrap_or_else(new_access_id);
    let list = AccessList {
        id: id.clone(),
        name,
        satisfy,
        pass_auth,
        users,
        clients,
    };
    write_htpasswd(&list)?;
    // Persist into the manifest (replace or append).
    lists.retain(|a| a.id != id);
    lists.push(list);
    save_access(&lists)?;

    // Rewrite the confs of any sites using this list, then reload.
    rewrite_sites_using_access(&id).await?;
    Ok(json!({ "id": id }))
}

/// Delete an access list (refused while a site still uses it).
async fn delete_access_op(req: &Req) -> Result<Value> {
    let id = req
        .access_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ERR_CODE:nginx.missing_access_id"))?;
    let in_use = sites_using_access();
    if let Some(sites) = in_use.get(id) {
        if !sites.is_empty() {
            return Err(anyhow!("访问列表仍被站点使用：{}", sites.join("、")));
        }
    }
    let mut lists = load_access();
    let before = lists.len();
    lists.retain(|a| a.id != id);
    if lists.len() == before {
        return Err(anyhow!("ERR_CODE:nginx.access_not_found"));
    }
    save_access(&lists)?;
    let _ = std::fs::remove_file(htpasswd_path(id));
    Ok(json!({ "deleted": id }))
}

/// Rewrite + reload the confs of every site referencing `access_id`.
async fn rewrite_sites_using_access(access_id: &str) -> Result<()> {
    let lo = layout()?;
    let mut touched = false;
    for site in load_sites() {
        if site.access_id == access_id {
            // Skip SSL sites whose cert is missing (keeps nginx -t valid).
            let mut s = site.clone();
            if s.ssl {
                let have = if s.cert_name.is_empty() {
                    lo.cert_store.join(format!("{}.crt", s.id)).exists()
                } else {
                    named_crt_file(&lo, &s.cert_name).exists()
                };
                if !have {
                    s.ssl = false;
                }
            }
            if let Err(e) = write_site_conf(&lo, &s, &[]).await {
                tracing::warn!(site = %s.server_name, "access rewrite failed: {e}");
            } else {
                touched = true;
            }
        }
    }
    if touched {
        validate_and_reload(&lo).await?;
    }
    Ok(())
}

/// Current website settings (default-site behaviour).
async fn get_web_settings() -> Result<Value> {
    let g = load_webglobal();
    Ok(json!({
        "default_site": { "mode": g.default_site.mode, "redirect_url": g.default_site.redirect_url },
        "configured": websettings_file().exists(),
    }))
}

/// Save the default-site behaviour and (re)write the catch-all conf.
async fn set_default_site(req: &Req) -> Result<Value> {
    let lo = layout()?;
    let mode = match req.default_mode.as_deref().unwrap_or("404") {
        m @ ("404" | "welcome" | "444" | "redirect") => m.to_string(),
        _ => return Err(anyhow!("ERR_CODE:nginx.bad_default_mode")),
    };
    let redirect_url = req
        .redirect_url
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();
    if mode == "redirect" && !valid_redirect_url(&redirect_url) {
        return Err(anyhow!("ERR_CODE:nginx.bad_redirect_url"));
    }
    let g = WebGlobal {
        default_site: DefaultSite { mode, redirect_url },
    };
    save_webglobal(&g)?;
    write_default_conf(&lo, &g).await?;
    if let Err(e) = validate_and_reload(&lo).await {
        // Roll back: remove the default conf so nginx stays valid.
        let _ = std::fs::remove_file(default_conf_path());
        let _ = reload().await;
        return Err(e);
    }
    Ok(json!({ "ok": true }))
}

// `valid_redirect_url` lives in the `validate` submodule.
fn default_conf_path() -> std::path::PathBuf {
    std::path::Path::new(HOST_CONFD).join("00-dn7-default.conf")
}

/// The per-mode response directives for the default (catch-all) server.
fn default_behavior(g: &WebGlobal) -> String {
    match g.default_site.mode.as_str() {
        "redirect" => format!("    return 301 {};\n", g.default_site.redirect_url),
        "444" => "    return 444;\n".to_string(),
        "welcome" => "    default_type text/html;\n    return 200 \"<!doctype html><html lang=en><head><meta charset=utf-8><title>DN7 Panel</title></head><body style='font-family:system-ui,sans-serif;text-align:center;padding:80px 20px;color:#333'><h1 style='margin:0 0 8px'>It works</h1><p style='color:#888'>This server is managed by DN7 Panel.</p></body></html>\";\n".to_string(),
        _ => "    return 404;\n".to_string(),
    }
}

/// Write the catch-all default-server conf (HTTP + HTTPS) per the saved
/// settings, generating a self-signed default cert for the HTTPS listener.
async fn write_default_conf(lo: &Layout, g: &WebGlobal) -> Result<()> {
    let behavior = default_behavior(g);
    // Default cert for the 443 catch-all (so unmatched SNI doesn't fall through
    // to the first real site's certificate).
    let crt = lo.cert_store.join("default.crt");
    let key = lo.cert_store.join("default.key");
    if !crt.exists() || !key.exists() {
        gen_self_signed_to(&crt, &key, "localhost").await?;
    }
    let crt_ref = format!("{}/default.crt", lo.cert_ref);
    let key_ref = format!("{}/default.key", lo.cert_ref);
    let conf = format!(
        "server {{\n    listen 80 default_server;\n    server_name _;\n{behavior}}}\n\n\
         server {{\n    listen 443 ssl default_server;\n    server_name _;\n\
         \x20   ssl_certificate {crt_ref};\n    ssl_certificate_key {key_ref};\n{behavior}}}\n"
    );
    std::fs::create_dir_all(HOST_CONFD)?;
    std::fs::write(default_conf_path(), conf)?;
    Ok(())
}

/// Best-effort parse of a PEM cert's notAfter (expiry) as an ISO date string.
/// Implemented in the `certparse` submodule (minimal ASN.1 walk).
fn cert_not_after(pem: &str) -> Option<String> {
    certparse::cert_not_after(pem)
}

/// Reload nginx (`nginx -s reload`).
async fn reload() -> Result<()> {
    let lo = layout()?;
    validate_and_reload(&lo).await
}

/// `nginx -t` then `nginx -s reload`. Errors carry nginx's own message so a bad
/// generated config is visible.
async fn validate_and_reload(_lo: &Layout) -> Result<()> {
    let (ok, _o, e) = run("nginx", &["-t"]).await?;
    if !ok {
        return Err(anyhow!(
            trim_msg(&e).unwrap_or_else(|| "nginx 配置无效".into())
        ));
    }
    let (ok, _o, e) = run("nginx", &["-s", "reload"]).await?;
    if !ok {
        return Err(anyhow!(trim_msg(&e).unwrap_or_else(|| "重载失败".into())));
    }
    Ok(())
}

/// Resolve a container's first reachable IPv4 address from the Docker daemon
/// (used in **host mode**, where the host's nginx can't resolve a container
/// *name* — only an IP works). Returns the IP from a user-defined network if
/// present, else the default bridge IP, else None.
async fn container_ip(target: &str) -> Option<String> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let networks = inspect.network_settings.and_then(|n| n.networks)?;
    // Prefer a user-defined network's IP; fall back to the bridge.
    let mut bridge_ip: Option<String> = None;
    for (name, ep) in networks {
        let ip = ep.ip_address.filter(|s| !s.is_empty());
        match ip {
            Some(ip) if name == "bridge" => bridge_ip = Some(ip),
            Some(ip) => return Some(ip), // user-defined network IP preferred
            None => {}
        }
    }
    bridge_ip
}

/// In **host mode**, find the host port that publishes the container's
/// `container_port` (so the host's nginx can proxy to `127.0.0.1:<host_port>`,
/// which is stable across container restarts — unlike the container IP). Returns
/// None when that port isn't published to the host.
async fn published_host_port(target: &str, container_port: i64) -> Option<u16> {
    let dkr = crate::docker::dkr().ok()?;
    let inspect = dkr.inspect_container(target, None).await.ok()?;
    let ports = inspect.network_settings.and_then(|n| n.ports)?;
    // Docker keys ports like "3000/tcp" -> [{HostIp, HostPort}, ...].
    let key_tcp = format!("{container_port}/tcp");
    let key_udp = format!("{container_port}/udp");
    for (key, binds) in ports {
        if key != key_tcp && key != key_udp {
            continue;
        }
        if let Some(binds) = binds {
            for b in binds {
                if let Some(hp) = b.host_port.and_then(|p| p.parse::<u16>().ok()) {
                    return Some(hp);
                }
            }
        }
    }
    None
}

/// Resolve the proxy upstream (`host:port`) for a site:
///  - **proxy_host**: the user-supplied host[:port] as-is.
///  - **proxy_container**: the host's nginx can't resolve a container name.
///    Prefer the published host port (`127.0.0.1:<hostport>`, stable across
///    restarts); otherwise fall back to the container's bridge IP.
async fn resolve_upstream(_lo: &Layout, site: &Site) -> Result<String> {
    match site.kind.as_str() {
        "proxy_host" => Ok(with_scheme_port(&site.target_url, &site.scheme)),
        "proxy_container" => resolve_container_upstream(&site.container, site.container_port).await,
        _ => Ok(String::new()),
    }
}

/// Resolve a container's `host:port` upstream for the host nginx: prefer the
/// published host port (`127.0.0.1:<hostport>`, restart-stable), otherwise fall
/// back to the container's bridge IP.
async fn resolve_container_upstream(container: &str, container_port: i64) -> Result<String> {
    if let Some(hp) = published_host_port(container, container_port).await {
        Ok(format!("127.0.0.1:{hp}"))
    } else {
        let ip = container_ip(container).await.ok_or_else(|| {
            anyhow!(
                "容器 {} 未映射端口 {} 到宿主机，且无法解析其 IP；请为容器发布该端口后重试",
                container,
                container_port
            )
        })?;
        Ok(format!("{ip}:{container_port}"))
    }
}

// ---------------------------------------------------------------------------
// Config generation. All values are pre-validated, so they're safe to embed.
// ---------------------------------------------------------------------------

/// Inline nginx locations that answer the ACME HTTP-01 challenge directly from
/// config (`return 200 "<keyAuthorization>"`). Serving the response inline —
/// rather than from a webroot file — means issuance never depends on a webroot
/// the nginx worker can read (file perms, SELinux context, path), which is the
/// usual cause of "domain validation failed" on existing/host nginx setups.
fn acme_challenge_locations(acme: &[(String, String)]) -> String {
    let mut s = String::new();
    for (token, keyauth) in acme {
        s.push_str(&format!(
            "\n    location = /.well-known/acme-challenge/{token} {{\n        auth_basic off;\n        allow all;\n        default_type text/plain;\n        return 200 \"{keyauth}\";\n    }}\n"
        ));
    }
    s
}

/// Generate the nginx server block(s) for a site and write the conf file. When
/// `acme` is non-empty, the port-80 block also answers those HTTP-01 challenges
/// inline (used during Let's Encrypt issuance).
async fn write_site_conf(lo: &Layout, site: &Site, acme: &[(String, String)]) -> Result<()> {
    // Resolve the assigned access list (if any) and build its directives.
    let access = if site.access_id.is_empty() {
        None
    } else {
        load_access().into_iter().find(|a| a.id == site.access_id)
    };
    let strip_auth = access.as_ref().map(|a| !a.pass_auth).unwrap_or(false);
    let auth = render_auth_block(access.as_ref());

    let body = render_location(lo, site, strip_auth).await?;
    let server_name = &site.server_name;
    let acme_loc = acme_challenge_locations(acme);

    let mut conf = String::new();
    let extra = render_extra_conf(&site.extra_conf);
    if site.ssl {
        let (crt, key) = if site.cert_name.is_empty() {
            (
                format!("{}/{}.crt", lo.cert_ref, site.id),
                format!("{}/{}.key", lo.cert_ref, site.id),
            )
        } else {
            // Referenced standalone named cert.
            (
                format!("{}/cert-{}.crt", lo.cert_ref, site.cert_name),
                format!("{}/cert-{}.key", lo.cert_ref, site.cert_name),
            )
        };
        // HTTP block: redirect to HTTPS (Force SSL) or serve the site over HTTP
        // too. The ACME challenge is always answered first.
        if site.force_ssl {
            conf.push_str(&format!(
                "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\
                 \n    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n\n"
            ));
        } else {
            conf.push_str(&format!(
                "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\n{auth}{extra}{body}}}\n\n"
            ));
        }
        // HTTPS block.
        let listen443 = if site.http2 {
            "listen 443 ssl http2;"
        } else {
            "listen 443 ssl;"
        };
        let mut sec = String::new();
        if site.trust_proxy {
            // Honour a trusted front proxy / CDN's real-client + protocol headers.
            sec.push_str(
                "    set_real_ip_from 0.0.0.0/0;\n    set_real_ip_from ::/0;\n\
                 \x20   real_ip_header X-Forwarded-For;\n    real_ip_recursive on;\n",
            );
        }
        if site.hsts {
            let sub = if site.hsts_sub {
                "; includeSubDomains"
            } else {
                ""
            };
            sec.push_str(&format!(
                "    add_header Strict-Transport-Security \"max-age=63072000{sub}\" always;\n"
            ));
        }
        conf.push_str(&format!(
            "server {{\n    {listen443}\n    server_name {server_name};\n\
             \n    ssl_certificate {crt};\n    ssl_certificate_key {key};\n{sec}\
             \n{auth}{extra}{body}}}\n"
        ));
    } else {
        conf.push_str(&format!(
            "server {{\n    listen 80;\n    server_name {server_name};\n{acme_loc}\n{auth}{extra}{body}}}\n"
        ));
    }

    std::fs::create_dir_all(&lo.confd)?;
    std::fs::write(conf_path(lo, &site.id), conf)?;
    Ok(())
}

/// Build the server-level access-control directives for an access list:
/// `satisfy`, `allow`/`deny` rules, and `auth_basic` + `auth_basic_user_file`.
/// Returns an empty string when the list is absent or has no rules.
fn render_auth_block(access: Option<&AccessList>) -> String {
    let a = match access {
        Some(a) => a,
        None => return String::new(),
    };
    let has_auth = !a.users.is_empty();
    let has_clients = !a.clients.is_empty();
    if !has_auth && !has_clients {
        return String::new();
    }
    let mut s = String::from("\n");
    // `satisfy` only matters when both factors are present, but it's harmless
    // otherwise and makes the intent explicit.
    if has_auth && has_clients {
        let mode = if a.satisfy == "all" { "all" } else { "any" };
        s.push_str(&format!("    satisfy {mode};\n"));
    }
    if has_clients {
        for c in &a.clients {
            let dir = if c.directive == "deny" {
                "deny"
            } else {
                "allow"
            };
            s.push_str(&format!("    {dir} {};\n", c.address));
        }
    }
    if has_auth {
        s.push_str(&format!(
            "    auth_basic \"{}\";\n",
            a.name.replace('"', "")
        ));
        s.push_str(&format!(
            "    auth_basic_user_file {};\n",
            htpasswd_path(&a.id).display()
        ));
    }
    s.push('\n');
    s
}

/// The location block(s) for a site's forwarding kind, plus any NPM-style
/// options (block-exploits / asset caching / websockets) and custom path rules.
/// Async because a `proxy_container` site in host mode must resolve the
/// container's IP (the host's nginx can't resolve a container name).
async fn render_location(lo: &Layout, site: &Site, strip_auth: bool) -> Result<String> {
    let mut out = String::new();

    // Optional: block common exploit patterns (server-scoped, before locations).
    if site.block_attacks {
        out.push_str(BLOCK_EXPLOITS);
    }

    let is_proxy = matches!(site.kind.as_str(), "proxy_host" | "proxy_container");
    // When trusting an upstream proxy, forward its declared protocol instead of
    // our own connection scheme.
    let fwd = if site.trust_proxy {
        "$dn7_fwd_proto"
    } else {
        "$scheme"
    };
    match site.kind.as_str() {
        "proxy_host" | "proxy_container" => {
            let upstream = resolve_upstream(lo, site).await?;
            out.push_str(&proxy_location(
                "/",
                &site.scheme,
                &upstream,
                site.websockets,
                false,
                fwd,
                strip_auth,
            ));
            // Optional: long-cache static assets (still proxied upstream).
            if site.cache {
                out.push_str(&proxy_location(
                    &format!("~* \\.({ASSET_EXT})$"),
                    &site.scheme,
                    &upstream,
                    site.websockets,
                    true,
                    fwd,
                    strip_auth,
                ));
            }
        }
        "static" => {
            let root = format!("{}/{}", lo.www_ref, site.root);
            out.push_str(&format!(
                "    root {root};\n    index index.html index.htm;\n\n    location / {{\n        try_files $uri $uri/ =404;\n    }}\n"
            ));
            if site.cache {
                out.push_str(&format!(
                    "    location ~* \\.({ASSET_EXT})$ {{\n        expires 7d;\n        add_header Cache-Control \"public, max-age=604800\";\n        try_files $uri =404;\n    }}\n"
                ));
            }
        }
        _ => {}
    }

    // Custom path rules (NPM-style custom locations): forward a prefix upstream.
    // Skip a rule whose path is "/" when the main block already serves "/" as a
    // proxy (it would duplicate the location and fail `nginx -t`).
    for l in &site.locations {
        if l.path == "/" && is_proxy {
            continue;
        }
        let upstream = if l.kind == "container" {
            resolve_container_upstream(&l.container, l.container_port).await?
        } else {
            with_scheme_port(&l.target, &l.scheme)
        };
        out.push_str(&proxy_location(
            &l.path,
            &l.scheme,
            &upstream,
            l.websockets,
            false,
            fwd,
            strip_auth,
        ));
    }

    Ok(out)
}

/// Common static-asset extensions for the "cache assets" option.
const ASSET_EXT: &str =
    "css|js|jpe?g|png|gif|ico|svg|webp|avif|woff2?|ttf|otf|eot|mp4|webm|mp3|map";

/// A modest set of "block common exploits" rules (query-string based), placed
/// at the top of the server block. Returns 403 on obvious probing patterns.
const BLOCK_EXPLOITS: &str = "    # block common exploits\n\
    if ($query_string ~* \"(<|%3C).*script.*(>|%3E)\") { return 403; }\n\
    if ($query_string ~* \"GLOBALS(=|\\[|%[0-9A-Z]{0,2})\") { return 403; }\n\
    if ($query_string ~* \"_REQUEST(=|\\[|%[0-9A-Z]{0,2})\") { return 403; }\n\
    if ($query_string ~* \"proc/self/environ\") { return 403; }\n\
    if ($query_string ~* \"base64_(en|de)code\\(.*\\)\") { return 403; }\n\n";

/// A reverse-proxy location with sane forwarded headers. `cache` adds long
/// expires for static assets; `websockets` adds the upgrade headers.
fn proxy_location(
    path: &str,
    scheme: &str,
    upstream: &str,
    websockets: bool,
    cache: bool,
    fwd_proto: &str,
    strip_auth: bool,
) -> String {
    let mut b = String::new();
    b.push_str(&format!("    location {path} {{\n"));
    b.push_str(&format!("        proxy_pass {scheme}://{upstream};\n"));
    b.push_str("        proxy_set_header Host $host;\n");
    b.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
    b.push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
    b.push_str(&format!(
        "        proxy_set_header X-Forwarded-Proto {fwd_proto};\n"
    ));
    // Access list with "Pass Auth" off: don't leak the Basic-Auth header upstream.
    if strip_auth {
        b.push_str("        proxy_set_header Authorization \"\";\n");
    }
    if websockets {
        b.push_str("        proxy_http_version 1.1;\n");
        b.push_str("        proxy_set_header Upgrade $http_upgrade;\n");
        b.push_str("        proxy_set_header Connection $dn7_conn_upgrade;\n");
    }
    if cache {
        b.push_str("        expires 7d;\n");
        b.push_str("        add_header Cache-Control \"public\";\n");
    }
    b.push_str("    }\n");
    b
}

/// Build `host:port` from a host token + scheme, defaulting the port to 80
/// (http) or 443 (https) when none is given.
fn with_scheme_port(host: &str, scheme: &str) -> String {
    if host.contains(':') {
        host.to_string()
    } else if scheme == "https" {
        format!("{host}:443")
    } else {
        format!("{host}:80")
    }
}

// ---------------------------------------------------------------------------
// Certificates.
// ---------------------------------------------------------------------------

/// Write user-supplied cert + key to the cert store (manual mode).
fn write_cert_files(lo: &Layout, site: &Site, cert_pem: &str, key_pem: &str) -> Result<()> {
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(lo.cert_store.join(format!("{}.crt", site.id)), cert_pem)?;
    write_key_file(&lo.cert_store.join(format!("{}.key", site.id)), key_pem)?;
    Ok(())
}

/// Write a private key file with owner-only (0600) permissions from creation,
/// so it never lands world-readable even briefly (default umask would make a
/// plain `write` 0644). All private-key writes go through here.
fn write_key_file(path: &std::path::Path, pem: &str) -> Result<()> {
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
async fn gen_self_signed(lo: &Layout, site: &Site) -> Result<()> {
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
async fn gen_self_signed_to(
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
fn set_key_perms(path: &std::path::Path) {
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
async fn start_cert_issue(lo: Layout, site: Site) -> Result<Value> {
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

async fn issue_le(op_id: &str, lo: &Layout, site: &Site) -> Result<()> {
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
    // covered by the named-cert auto-renewal loop. Reuse an existing same-domain
    // entry's name when present; otherwise derive a unique name from the host.
    let mut certs = load_named_certs();
    let cert_name = match certs.iter().find(|c| c.domain.eq_ignore_ascii_case(&host)) {
        Some(c) => c.name.clone(),
        None => {
            let base = if valid_cert_name(&host) {
                host.clone()
            } else {
                format!("le-{}", site.id)
            };
            let mut name = base.clone();
            let mut i = 1;
            while certs.iter().any(|c| c.name == name) {
                name = format!("{base}-{i}");
                i += 1;
            }
            name
        }
    };
    std::fs::create_dir_all(&lo.cert_store)?;
    std::fs::write(named_crt_file(lo, &cert_name), cert_chain_pem)?;
    std::fs::write(named_key_file(lo, &cert_name), &key_pem)?;
    set_key_perms(&named_key_file(lo, &cert_name));
    certs.retain(|c| c.name != cert_name);
    certs.push(NamedCert {
        name: cert_name.clone(),
        domain: host.clone(),
        cert_mode: "le".to_string(),
    });
    save_named_certs(&certs)?;

    // Point the site at the library cert and rewrite with SSL + reload.
    let mut site = site.clone();
    site.cert_mode = "named".to_string();
    site.cert_name = cert_name;
    op_push(op_id, &pmsg("ng.enable_https", &[]));
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
fn start_named_cert_issue(lo: Layout, name: String, domain: String) -> Result<Value> {
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

async fn issue_le_named(op_id: &str, lo: &Layout, name: &str, domain: &str) -> Result<()> {
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
    std::fs::write(named_key_file(lo, name), &key_pem)?;
    set_key_perms(&named_key_file(lo, name));
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
async fn acme_http01<F, Fut>(op_id: &str, host: &str, serve: F) -> Result<(String, String)>
where
    F: FnOnce(Vec<(String, String)>) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    };

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
    let key_pem;
    let cert_chain_pem = loop {
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
                let key_pair =
                    rcgen::KeyPair::generate().map_err(|e| anyhow!("生成私钥失败：{e}"))?;
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
                let chain = wait_for_cert(&mut order).await?;
                key_pem = key_pair.serialize_pem();
                break chain;
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

/// Pre-flight the HTTP-01 challenge against THIS host (localhost:80, with the
/// domain in the Host header) so we serve the same server block Let's Encrypt
/// will hit. A 404/mismatch here means a non-panel nginx vhost is shadowing the
/// domain (or `conf.d` isn't served) — fail with an actionable message rather
/// than burning a real validation attempt.
async fn self_check_challenge(host: &str, token: &str, expected: &str) -> Result<()> {
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
async fn acme_failure_detail(order: &mut instant_acme::Order) -> String {
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
async fn wait_for_cert(order: &mut instant_acme::Order) -> Result<String> {
    for _ in 0..15 {
        match order.certificate().await {
            Ok(Some(pem)) => return Ok(pem),
            Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            Err(e) => return Err(anyhow!("下载证书失败：{e}")),
        }
    }
    Err(anyhow!("ERR_CODE:nginx.le_issue_timeout"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_validation() {
        assert!(valid_server_name("example.com"));
        assert!(valid_server_name("a.example.com www.example.com"));
        assert!(valid_server_name("*.example.com"));
        assert!(valid_server_name("_"));
        assert!(!valid_server_name(""));
        assert!(!valid_server_name("bad;name"));
        assert!(!valid_server_name("a/b"));
    }

    #[test]
    fn host_token_validation() {
        assert!(valid_host_token("10.0.0.5"));
        assert!(valid_host_token("backend:3000"));
        assert!(valid_host_token("svc.local"));
        assert!(!valid_host_token("http://x"));
        assert!(!valid_host_token("a b"));
        assert!(!valid_host_token("a;b"));
    }

    #[test]
    fn container_and_root_validation() {
        assert!(valid_container_name("app"));
        assert!(!valid_container_name("-app"));
        assert!(!valid_container_name("a b"));
        assert!(valid_root_segment("site1"));
        assert!(!valid_root_segment(".."));
        assert!(!valid_root_segment("a/b"));
    }

    #[test]
    fn cert_name_validation() {
        assert!(valid_cert_name("mysite-2026"));
        assert!(valid_cert_name("a.b_c"));
        assert!(!valid_cert_name(""));
        assert!(!valid_cert_name(".."));
        assert!(!valid_cert_name("a/b"));
        assert!(!valid_cert_name("a b"));
    }

    #[test]
    fn with_port_defaults_80() {
        assert_eq!(with_scheme_port("host", "http"), "host:80");
        assert_eq!(with_scheme_port("host:8080", "http"), "host:8080");
        assert_eq!(with_scheme_port("host", "https"), "host:443");
    }

    fn lo_test() -> Layout {
        Layout {
            confd: std::path::PathBuf::from("/tmp/dn7-test-confd"),
            cert_ref: "/tmp/dn7-test-certs".into(),
            www_ref: "/tmp/dn7-test-www".into(),
            cert_store: std::path::PathBuf::from("/tmp/dn7-test-certs"),
            www_store: std::path::PathBuf::from("/tmp/dn7-test-www"),
        }
    }

    fn mk_site(kind: &str, ssl: bool) -> Site {
        Site {
            id: "s1".into(),
            server_name: "example.com".into(),
            kind: kind.into(),
            target_url: "10.0.0.5:8080".into(),
            container: "app".into(),
            container_port: 3000,
            root: "site1".into(),
            ssl,
            cert_mode: "self".into(),
            cert_name: String::new(),
            scheme: "http".into(),
            cache: false,
            block_attacks: false,
            websockets: true,
            force_ssl: true,
            http2: true,
            hsts: false,
            hsts_sub: false,
            trust_proxy: false,
            locations: Vec::new(),
            extra_conf: String::new(),
            access_id: String::new(),
        }
    }

    #[tokio::test]
    async fn renders_proxy_host() {
        let lo = lo_test();
        let site = mk_site("proxy_host", false);
        let body = render_location(&lo, &site, false).await.unwrap();
        assert!(body.contains("proxy_pass http://10.0.0.5:8080;"));
        assert!(body.contains("Upgrade $http_upgrade"));
    }

    #[tokio::test]
    async fn renders_static_root() {
        let lo = lo_test();
        let site = mk_site("static", false);
        let body = render_location(&lo, &site, false).await.unwrap();
        assert!(body.contains("root /tmp/dn7-test-www/site1;"));
    }

    #[tokio::test]
    async fn renders_https_scheme_and_options() {
        let lo = lo_test();
        let mut site = mk_site("proxy_host", false);
        site.scheme = "https".into();
        site.cache = true;
        site.block_attacks = true;
        site.websockets = false;
        let body = render_location(&lo, &site, false).await.unwrap();
        // https upstream, asset-cache location, exploit block, no ws headers.
        assert!(body.contains("proxy_pass https://10.0.0.5:8080;"));
        assert!(body.contains("location ~* \\.("));
        assert!(body.contains("block common exploits"));
        assert!(!body.contains("Upgrade $http_upgrade"));
    }

    #[tokio::test]
    async fn renders_custom_locations() {
        let lo = lo_test();
        let mut site = mk_site("proxy_host", false);
        site.locations = vec![Location {
            path: "/api".into(),
            scheme: "http".into(),
            target: "127.0.0.1:3001".into(),
            websockets: true,
            kind: "host".into(),
            container: String::new(),
            container_port: 0,
        }];
        let body = render_location(&lo, &site, false).await.unwrap();
        assert!(body.contains("location /api {"));
        assert!(body.contains("proxy_pass http://127.0.0.1:3001;"));
    }

    #[test]
    fn location_path_validation() {
        assert!(valid_location_path("/api"));
        assert!(valid_location_path("/"));
        assert!(valid_location_path("/a/b-c_d"));
        assert!(!valid_location_path("api")); // must start with /
        assert!(!valid_location_path("/a b"));
        assert!(!valid_location_path("/a;b"));
    }

    #[test]
    fn sanitize_rel_rejects_traversal() {
        assert!(sanitize_rel("a/b/c.html").is_some());
        assert!(sanitize_rel("../etc/passwd").is_none());
        assert!(sanitize_rel("a/../../b").is_none());
        assert!(sanitize_rel("").is_none());
        assert_eq!(
            sanitize_rel("./x/./y.js").unwrap(),
            std::path::PathBuf::from("x/y.js")
        );
    }

    #[test]
    fn htpasswd_is_bcrypt_and_verifies() {
        let h = htpasswd_hash("s3cret");
        assert!(h.starts_with("$2"), "expected a bcrypt hash, got {h}");
        assert!(bcrypt::verify("s3cret", &h).unwrap());
        assert!(!bcrypt::verify("wrong", &h).unwrap());
    }

    #[test]
    fn access_validators() {
        assert!(valid_access_name("Internal only"));
        assert!(!valid_access_name(""));
        assert!(!valid_access_name("bad\"quote"));
        assert!(valid_auth_username("bob.smith_1"));
        assert!(!valid_auth_username("has:colon"));
        assert!(valid_client_address("all"));
        assert!(valid_client_address("192.168.0.0/16"));
        assert!(valid_client_address("2001:db8::/32"));
        assert!(!valid_client_address("1.2.3.4; rm -rf"));
    }

    #[test]
    fn redirect_url_validation() {
        assert!(valid_redirect_url("https://example.com/path"));
        assert!(valid_redirect_url("http://a.test"));
        assert!(!valid_redirect_url("ftp://x"));
        assert!(!valid_redirect_url("https://a b.com"));
        assert!(!valid_redirect_url("javascript:alert(1)"));
    }
}
