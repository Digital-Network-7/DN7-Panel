# DN7 Panel

> ## 🙏 致谢 / Acknowledgements
>
> 特别感谢 **[LINUX DO](https://linux.do)** 社区 —— 一个真诚、专业、友善的技术社区。
> 本项目的诸多想法、反馈与打磨都受益于这里的伙伴们。
>
> Special thanks to the **[LINUX DO](https://linux.do)** community — *real,
> professional, kind.* Much of this project's direction and polish owes to the
> people there.

A small, single static Rust binary that turns a Linux host into a fully managed
node via an **on-box web console** — monitoring, a web terminal, and
containers / websites / files / users / audit logs — with no backend, no
separate control plane, and no runtime dependencies.

> Part of the Digital Network 7 suite ·
> <https://github.com/Digital-Network-7/DN7-Panel>

Current release: **Phanes 27.0.1 (build 3)**. Versions follow
`DN7 Panel <codename> <year>.<major>.<minor> (build <N>)`, with
[`release.toml`](release.toml) as the single source of truth.

中文文档：[`docs/README.zh-CN.md`](docs/README.zh-CN.md)

## Highlights

- **One static binary.** Pure Rust + rustls (musl build) — no system libraries
  and no `docker` / `nginx` / `openssl` CLI at runtime. The container runtime and
  the reverse proxy are both in-process Rust.
- **Self-managing.** Installs itself to a stable path, sets up redundant boot
  autostart, daemonizes, and self-heals via a two-half supervisor. Updates come
  from signed GitHub releases fetched over the fastest available mirror.
- **On-box, no backend.** The console authenticates locally and acts on the host
  directly; at-rest secrets are `0600`-only and the password is a one-way
  **Argon2id** verifier — the browser sends a hash, never the plaintext.

## Fit and trade-offs

DN7 Panel is designed for single-host or small-node operations where the person
using the console is also trusted to administer the machine. Its strengths are
simple deployment, no external control plane, and direct access to containers,
websites, files, users, and a terminal from one embedded UI.

That also defines its limits. It is not a multi-tenant SaaS control plane, and it
deliberately has a high local blast radius: many features operate with host
administrator privileges. The console is reached at an address and port you
choose during setup — the in-process edge fronts it on all interfaces (default
`:80` / `:443`). For internet-facing hosts, restrict access with the built-in
**IP allow-list** (Settings), a host firewall, an **SSH tunnel**, or a reverse
proxy, and turn on **HTTPS** and **TOTP 2FA**.

## Roles

The binary runs as one of two roles, chosen by argv:

- `dn7-panel` (no args) — **supervisor**: keeps the panel role alive by spawning
  *itself* with the `panel` subcommand and restarting it on exit.
- `dn7-panel panel` — **panel role**: runs the on-box web console.

The two halves guard each other (pid + heartbeat files under `DN7_RUNTIME_DIR`):
the supervisor restarts the panel if it exits, and the panel relaunches the
supervisor if it dies. Because it's a single binary, a self-update replaces one
file and both halves come back upgraded. In normal use you only run the no-arg
form — it splits off the panel itself.

## Quick start

**One-line install** — downloads the latest static binary (racing GitHub /
`ghfast.top` / `ghproxy.net` for the fastest source) and launches first-run setup:

```bash
curl -fsSL https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
```

> Behind a restrictive network, fetch the script through a mirror — the binary is
> still raced across all three sources:
>
> ```bash
> curl -fsSL https://ghfast.top/https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
> ```

**Or install manually** — grab the static binary for your architecture from the
[**Releases**](https://github.com/Digital-Network-7/DN7-Panel/releases) page
(musl builds for `x86_64` and `arm64`) and run it directly — no build step, no
dependencies:

```bash
chmod +x dn7-panel-linux-*        # the file you downloaded
sudo ./dn7-panel-linux-*
```

> **No release for your platform / version?** Build from source instead — it's
> pure Rust + rustls, so a release build needs no system libraries:
>
> ```bash
> cargo build --release
> sudo ./target/release/dn7-panel
> ```
>
> Hitting a problem, or missing a build for your platform? Please open an
> [**Issue**](https://github.com/Digital-Network-7/DN7-Panel/issues) — bug
> reports and requests are very welcome.

On the **first** launch in an interactive terminal, DN7 Panel runs a **setup
wizard**: after an environment check it lets you choose a deployment mode
(default **Quick**):

- **Quick** — auto-selects the UI language from the server's timezone, brings the
  panel up on your public IP (plain HTTP) with an `admin` account and a random
  password. Your first login then **forces** you to set your own username and
  password before you reach the console.
- **CLI custom** — an interactive terminal wizard for the full configuration:
  access address (public IP / LAN IP / domain), HTTPS (Let's Encrypt /
  self-signed / off), the website HTTP/HTTPS ports, an optional dedicated console
  port, and the admin account.
- **UI custom** — prints a one-time secure link (`http://<addr>/init?init_token=…`,
  both public and internal) and serves a **token-gated web wizard** so you can do
  the whole setup in a browser.

On a normal launch the binary **installs itself to `/var/dn7/panel/dn7-panel`**
and re-execs from there, so you can run the downloaded binary from anywhere — no
need to create directories by hand. It also installs the **`dn7` management CLI**
as `/usr/local/bin/dn7`. Runtime state is grouped under
`/var/dn7/panel/{data,run,log}`.

It installs **redundant boot autostart** so the panel returns after a reboot,
using whatever the host supports (best-effort, idempotent, root only): a
**systemd unit**, a **cron `@reboot`** entry, and an **`/etc/rc.local`** line.
Single-instance, so even if several fire at boot only one supervisor runs.

It then **detaches into the background**, appending logs to
`/var/dn7/panel/log/dn7-panel.log` (trimmed in place once past ~5 MiB). Pass
`--foreground` / `-f` (or `DN7_FOREGROUND=1`) to stay attached for debugging.

Locked out, or want to start over? `dn7-panel reset` (install owner / root only)
clears the account and stops the panel; run `dn7-panel` again to re-enter the
setup wizard.

## Command-line

The `dn7-panel` binary itself has a small surface — it exists to install,
supervise, and serve:

```bash
dn7-panel                 # start (installs + supervises the panel, then daemonizes)
dn7-panel --foreground    # run attached without daemonizing (-f)
dn7-panel version         # print "<version> (build <N>)"
dn7-panel reset           # reset to uninitialized (owner/root) — re-run to set up again
dn7-panel help            # usage
```

Day-to-day management uses the **`dn7` CLI** (installed at `/usr/local/bin/dn7`,
root-only), which drives the live panel over a loopback control channel:

```bash
dn7 status                          # panel / edge / container overview
dn7 container ls|images|pull|start|stop|rm|logs|exec|stats|net|volumes|...   # (alias: dn7 ct)
dn7 site ls|add|rm|setup|reload     # websites (add = guided wizard)
dn7 cert ls|issue|renew|rm          # TLS certs (issue le|self|manual <domain>)
dn7 edge status|restart|reload      # the built-in reverse proxy
dn7 user ls|add|passwd|rm           # panel accounts (add <name> [--admin])
dn7 logs | dn7 metrics | dn7 update # audit log / resource metrics / update status (--json)
dn7 panel start|stop|restart|status|logs|reset|rotate-token
dn7 service enable|disable|status   # boot autostart
dn7 uninstall                       # multi-confirm removal
```

## On-box web console

Reached at the address and port you chose during setup, served by the in-process
edge. Login is rate-limited and uses a **challenge-response**, so the password
never crosses the wire in cleartext (the browser sends a key-stretched verifier;
the server keeps only an Argon2id hash of it). Optional **HTTPS** (Let's Encrypt
or self-signed) and **TOTP 2FA** are available in Settings, along with an **IP
allow-list** that restricts which addresses can reach the console.

> **Exposure.** The edge binds all interfaces on your chosen ports, so the
> console is reachable from the network by default. For internet-facing hosts,
> put it behind the IP allow-list, a firewall, an SSH tunnel, or a reverse proxy,
> and enable HTTPS + 2FA.

Capabilities:

- **Monitoring** — CPU / memory / disk / network throughput, plus a history
  chart (CPU / memory / network over 15m / 1h / 6h / 1d / 7d), sampled in the
  background and persisted to `<data>/metrics-history.json`.
- **Terminal** — a browser PTY shell on the host, and per-container exec shells.
- **Containers** — a built-in **pure-Rust container runtime** (no Docker daemon
  required): images (pull, create), container lifecycle, logs, networks, volumes,
  backups, an in-container terminal, and file transfer.
- **Website** — the in-process edge reverse proxy (no external nginx): sites
  (proxy-host / proxy-container / static), custom path rules, HTTPS via Let's
  Encrypt / self-signed / manual / a named cert store, access lists, live reload.
- **Files** — browse / upload / download / edit / delete on the host and inside
  containers.
- **Users** — multiple panel accounts (admin / non-admin), backed by system
  accounts.
- **Logs** — a searchable, server-paginated **audit log** of console actions.
- **Updates** — one-click self-update from signed GitHub releases (manual or
  automatic), with rollback.

## Screenshots

### Monitoring

![Monitoring page](docs/images/1.png)

### Terminal

![Terminal page](docs/images/2.png)

### Containers

![Containers page](docs/images/3.png)

### Websites

![Websites page](docs/images/4.png)

### Files

![Files page](docs/images/5.png)

### Settings

![Settings page](docs/images/6.png)

## Configuration

Most operational settings are persisted by the console itself. Web-console
settings live in `<data>/web.json` (0600) and update preferences in
`<data>/update.json` (0600); they take precedence after the first initialization.
Environment variables are optional startup defaults or debug knobs; there is no
`.env` loader.

| Var | Default | Notes |
|-----|---------|-------|
| `DN7_RUNTIME_DIR` | `/var/dn7/panel` | base dir for `data/run/log`; mainly for special deployments/tests |
| `DN7_HEARTBEAT_TIMEOUT_SECS` | `15` | peer liveness threshold |
| `DN7_SUPERVISE_INTERVAL_SECS` | `3` | supervisor child-check interval |
| `DN7_RESTART_BACKOFF_SECS` | `2` | delay between panel restarts |
| `DN7_FOREGROUND` | — | set `1` / `true` / `yes` to stay attached (no daemonize) |
| `DN7_GITHUB_REPO` | `Digital-Network-7/DN7-Panel` | GitHub release repository the self-updater pulls from |
| `DN7_WEB_PORT` | `1080` | internal console loopback port (the edge fronts it on your chosen public ports); rarely set |
| `RUST_LOG` | `info,dn7_panel=info` | tracing filter for foreground/log output |

### Runtime / dev flags

A few flags select alternate runtime behavior or aid local development. They are
read directly from the environment (no `.env` loader):

| Var | Effect |
|-----|--------|
| `DN7_RUNTIME=docker` | Talk to an external Docker daemon instead of the built-in pure-Rust runtime, which is the **default** on Linux (any other value keeps the built-in runtime). |
| `DN7_NO_GUARDIAN=1` | Disable the supervisor/guardian relaunch so the process stays in the foreground without respawning — for dev/foreground runs only. Any non-empty value other than `0` enables this. |
| `DN7_UPDATE_DIRECT=1` | Fetch self-updates from GitHub directly, skipping the mirror-proxy lines (useful where the proxies are unreachable). |
| `DN7_ROOT_USERTEST=1` | Opt into the root-gated `/etc` account integration test (it edits the live `passwd`/`shadow`/`group`); run as root, e.g. `sudo DN7_ROOT_USERTEST=1 <testbin>`. When unset the test is skipped. |

## Security model

Standalone, on-box, no backend. The console authenticates locally and operates on
the host directly. At-rest secrets are protected by owner-only (`0600`) file
permissions, and the web password is never stored recoverably — it is kept as a
one-way **Argon2id** verifier (the browser sends a key-stretched hash, never the
plaintext), so the stored credential can't be reversed even with the file.
Private keys, session, and settings files are likewise written `0600`. Access can
be narrowed with an **IP allow-list** and **TOTP 2FA**, and high-risk operations
require a step-up re-auth. Self-updates are downloaded from GitHub and
**Ed25519-verified against keys embedded in the binary** before install, so a
compromised mirror cannot serve a binary the panel will accept. Security-sensitive
settings (proxy trust, container privileges, …) are wrapped in validators with
closed-by-default fallbacks — see [`ARCHITECTURE.md`](ARCHITECTURE.md) §13.

## Build

CI builds static **musl** binaries (x86_64 + arm64) on every push to `main` and
publishes a GitHub Release whenever the build number in
[`release.toml`](release.toml) advances (each build is its own release, tagged
`b<N>` and marked Latest; older builds are retained). Pure Rust + rustls, so the
static build needs no system libraries at runtime.

```bash
cargo build --release          # local build
cargo fmt && cargo clippy --workspace --all-targets && cargo test --workspace
node scripts/check_i18n.js     # UI string consistency (run from repo root)
```

## Development

- Architecture, layering rules, and code-structure standards live in
  [`ARCHITECTURE.md`](ARCHITECTURE.md). `tests/architecture.rs` enforces the
  dependency direction.
- UI strings are in `src/web/ui/js/i18n.js` (4 languages); validate with
  `scripts/check_i18n.js` (or `.py`) after touching the UI.

## License

Licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only).
See [`LICENSE`](LICENSE). If you run a modified version as a network service, the
AGPL requires you to offer its source to your users.
