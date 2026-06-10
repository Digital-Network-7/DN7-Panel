# DN7 Panel

A small, single static Rust binary that turns a Linux host into a fully managed
node via an **on-box web console** — monitoring, a web terminal, and Docker /
Nginx / MySQL / file management — with no backend, no panel token, and no
runtime dependencies.

> Part of the [Digital Network 7](https://dn7.cn) suite. Open source:
> https://github.com/Digital-Network-7/DN7-Panel

## Roles

The binary runs as one of two roles, chosen by argv:

- `dn7-panel` (no args) — **supervisor**: keeps the panel role alive by spawning
  *itself* with the `panel` subcommand and restarting it on exit.
- `dn7-panel panel` — **panel role**: runs the on-box web console.

The two halves guard each other (pid + heartbeat files under `DN7_RUNTIME_DIR`):
the supervisor restarts the panel if it exits, and the panel relaunches the
supervisor if it dies. Because it's a single binary, a self-update replaces one
file and both halves come back upgraded.

In normal use you only ever run the no-arg form (the supervisor); it splits off
the panel itself.

## Quick start

```bash
cargo build --release
sudo ./target/release/dn7-panel
```

On a normal launch the binary **installs itself to `/var/dn7/panel/dn7-panel`**
(creating `/var/dn7/panel` if needed) and re-execs from there, so you can run the
downloaded binary from anywhere — no need to create directories by hand. Runtime
state is grouped under `/var/dn7/panel/{data,run,log}`.

It also installs **redundant boot autostart** so the panel comes back after a
reboot, using whatever the host supports (best-effort + idempotent, root only):
a **systemd unit** (`/etc/systemd/system/dn7-panel.service`, `enable`d), a
**cron `@reboot`** entry (`/etc/cron.d/dn7-panel` or the root crontab), and an
**`/etc/rc.local`** line. Because the panel is single-instance, if more than one
fires at boot only one supervisor actually runs.

It then **detaches and keeps running in the background**, appending logs to
`/var/dn7/panel/log/dn7-panel.log`. Pass `--foreground` / `-f` (or set
`DN7_FOREGROUND=1`) to stay attached for debugging. The log is **trimmed in
place** by a background janitor (keeps the recent tail once it passes ~5 MiB).

## On-box web console

Bound to `0.0.0.0:<port>` (default **1080**) over plain HTTP, authenticated with
an auto-generated random password (shown in the log on first start; editable in
the console settings). Login is rate-limited and uses a challenge-response so
the password never crosses the wire in cleartext. Because traffic is plaintext,
firewall the port to trusted sources.

Capabilities:

- **Monitoring**: CPU / memory / disk / network throughput + a process ranking.
- **Terminal**: a browser PTY shell on the host, and per-container shells
  (`docker exec`).
- **Docker**: images (pull, create container), containers (create, start/stop/
  restart/remove, logs, networks, in-container terminal, file transfer),
  networks.
- **Nginx**: Docker-mode setup (DN7 Panel creates/manages an `dn7-nginx`
  container), add/remove sites (proxy-host / proxy-container / static), custom
  path rules, HTTPS via Let's Encrypt / self-signed / manual / a standalone
  cert store, reload.
- **MySQL**: create/manage ONE DN7 Panel-provisioned MySQL/MariaDB instance
  (fixed container `dn7-mysql`) — start/stop/restart/remove, connection info,
  multiple databases, account management, port remap, and mysqldump backup.
- **Files**: browse/upload/download/delete on the host and inside containers.

## Configuration

See `.env.example`. All settings are optional; the console's own settings page
persists port/username/password to `<data>/web.json` (0600) and takes precedence
at runtime.

| Var | Default | Notes |
|-----|---------|-------|
| `DN7_WEB_ENABLED` | `1` | serve the on-box web console (`0`/`false` to disable) |
| `DN7_WEB_PORT` | `1080` | web console TCP port (initial default) |
| `DN7_RUNTIME_DIR` | `/var/dn7/panel` | base dir for `data/run/log` |
| `DN7_HEARTBEAT_TIMEOUT_SECS` | `15` | peer liveness threshold |
| `DN7_SUPERVISE_INTERVAL_SECS` | `3` | supervisor child-check interval |
| `DN7_RESTART_BACKOFF_SECS` | `2` | delay between panel restarts |
| `DN7_FOREGROUND` | — | set `1` to stay attached (no daemonize) |
| `DN7_UPDATE_URL` | `https://api.teaops.dn7.cn` | self-update source (retained, not yet auto-triggered) |

## Build

CI builds static **musl** binaries (x86_64 + arm64) on every push to `main` and
publishes them as a GitHub Release `1.0.<run_number>`. Pure Rust + rustls, so
the static build needs no system libraries at runtime.

## Security model

Standalone, on-box, no backend. The console authenticates locally and operates
on the host directly. At-rest secrets (the web password once the user changes it
from the auto-generated default) are encrypted with a machine-bound AES-256-GCM
key (`<data>/.panel_key`), so a copied file can't be decrypted on another host.
