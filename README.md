# TeaOps Agent

A small Rust binary that runs on a Linux server (also works on macOS for dev),
collects system metrics with `sysinfo`, and pushes them to the TeaOps backend
every 3 seconds. No SSH is used at runtime.

## One binary, two roles (self-splitting supervisor)

The binary runs as one of two roles, chosen by argv:

- `teaops-agent` (no args) — **supervisor**: keeps the agent role alive by
  spawning *itself* with the `agent` subcommand and restarting it on exit.
- `teaops-agent agent` — **agent role**: collects and reports metrics.

The two halves guard each other (pid + heartbeat files in `TEAOPS_RUNTIME_DIR`):
the supervisor restarts the agent if it exits, and the agent relaunches the
supervisor if it dies. Because it's a single binary, a self-update replaces one
file and both halves come back upgraded.

In normal use you only ever run the no-arg form (the supervisor); it splits off
the agent itself. The previous separate `teaops-agentd` supervisor is no longer
needed — this binary is its own supervisor.

## Build & run

```bash
cd teaops-agent
cargo build --release
TEAOPS_BACKEND_URL=https://your-backend.example.com ./target/release/teaops-agent
```

On a normal launch the agent first **installs itself to `/var/ops/teaops-agent`**
(creating `/var/ops` if needed) and re-execs from there, so you can run the
downloaded binary from anywhere — no need to create directories by hand. All
runtime state (token, pid/heartbeat/lock, log) lives under `/var/ops`. If
`/var/ops` isn't writable (e.g. an unprivileged run) it just runs in place.

When it migrates from an old location it **stops any old instance running there,
moves the valuable files** (token, key, version) **into `/var/ops`, folds the
old log into the canonical one, deletes the old transient state** (pid /
heartbeat / lock files — so no stale `teaops-supervisor.heartbeat` is left
behind) **and removes the original downloaded binary**. From then on everything
is anchored at `/var/ops`.

On **every** launch it also sweeps the well-known legacy locations (`~`, `/`,
`/root`, the cwd) for leftover agent runtime files and applies the same cleanup
there — stopping a stale old supervisor (a common cause of a heartbeat file that
"won't delete") even after the host already adopted `/var/ops`. And the
long-lived supervisor periodically checks whether a self-update replaced the
on-disk binary with a newer version; if so it re-execs itself, so the supervisor
(not just the agent child) always ends up running the new code.

It also installs **redundant boot autostart** so the agent comes back after a
reboot, using whatever the host supports (all best-effort + idempotent, root
only): a **systemd unit** (`/etc/systemd/system/teaops-agent.service`,
`enable`d), a **cron `@reboot`** entry (`/etc/cron.d/teaops-agent` or the root
crontab), and an **`/etc/rc.local`** line. Because the agent is single-instance,
if more than one fires at boot only one supervisor actually runs.

It then prints its pairing QR + 8-digit code in the foreground (so you can
scan/copy it), then **detaches and keeps running in the background**, appending
logs to `/var/ops/teaops-agent.log`. Pass `--foreground` / `-f` (or set
`TEAOPS_FOREGROUND=1`) to stay attached for debugging. The log is **trimmed in
place** by a background janitor (keeps the recent tail once it passes ~5 MiB) so
it can't grow without bound.

If you run the binary again **while an instance is already running**, it does
not start a duplicate. Instead it reads the current server's token, asks the
backend for a fresh quick-add code (any old code is invalidated), re-prints the
QR + the new code, and exits. This is the easy way to re-display pairing info or
rotate the code.

On first run with no token, the agent registers and displays a QR code
(encoding the server's 128-char token) plus an 8-digit quick-add code:

```
========================================
  TeaOps Agent 配对
  用小程序扫描下方二维码即可添加本服务器：

   █▀▀▀▀▀█ ▀ ▄ █▀▀▀▀▀█
   █ ███ █ ▀▄▀ █ ███ █   (terminal QR, black-on-white)
   ...

  或在小程序中输入 8 位快速添加码：

        >>>  35054398  <<<

  (有效期至 ... 北京时间)
========================================
```

Add it in the mini program ("服务器" → 添加 → 手动添加): scan the QR or type the
8-digit code. Once claimed, the agent receives its `agent_token`, persists it to
`teaops-agent.token`, and starts reporting. The 自动添加 (SSH) flow skips this —
the backend installs and starts the agent for you.

The token is **encrypted at rest** (AES-256-GCM, stored as `nonce_hex:cipher_hex`)
with a key derived from a stable machine fingerprint (`/etc/machine-id`, falling
back to a persisted random key or the hostname). A token file copied to another
host therefore can't be decrypted there. Legacy plaintext token files are still
read and are re-encrypted on the next write.

## Configuration (env)

| Var | Default | Notes |
|-----|---------|-------|
| `TEAOPS_BACKEND_URL` | `https://api.teaops.dn7.cn` | backend base URL (use HTTPS in prod); ws/wss is derived from it |
| `TEAOPS_INTERVAL_SECS` | `3` | report interval |
| `TEAOPS_TOKEN_FILE` | `/var/ops/teaops-agent.token` | where the token is persisted |
| `TEAOPS_AGENT_TOKEN` | — | provide directly to skip pairing |
| `TEAOPS_RUNTIME_DIR` | `/var/ops` | shared pid/heartbeat/lock dir for the two roles |
| `TEAOPS_HEARTBEAT_TIMEOUT_SECS` | `15` | peer liveness threshold |
| `TEAOPS_SUPERVISE_INTERVAL_SECS` | `3` | supervisor child-check interval |
| `TEAOPS_RESTART_BACKOFF_SECS` | `2` | delay between agent restarts |
| `TEAOPS_WEB_ENABLED` | `1` | serve the on-box web console (set `0`/`false` to disable) |
| `TEAOPS_WEB_PORT` | `1080` | web console TCP port (initial default; user changes persist in `<data>/web.json`) |

## On-box web console

The agent serves a local management console (default **on**, `0.0.0.0:1080`)
that exposes the same capabilities directly on the host — no backend round-trip.
It reuses the same per-capability JSON dispatchers as the relay path. The single
embedded page (`web/ui/index.html`) is a left-right sci-fi UI with:

- **主题**: dark / light / follow-system, cycled by one icon in the top-right.
  The logged-in account + logout live in the top-right; the agent version sits
  in the bottom-left of the sidebar.
- **监控**: CPU/memory/disk/uptime cards plus a network card with big up/down
  readouts and a live dual sparkline, and a Top-CPU process table.
- **终端**: a built-in VT100/ANSI terminal emulator (no library/CDN). Click the
  screen to type directly — proper backspace/erase, cursor movement, colors,
  scroll region and alt-screen so `top`/`vim` work; window-resize aware.
- **Docker**: image / container / network management — pull (with mirror),
  create, start/stop/restart/remove, logs, connect/disconnect networks, an
  **in-container terminal** (`docker exec`), and **container file transfer**.
- **Nginx**: host/docker setup, add/remove sites (proxy-host / proxy-container /
  static), HTTPS via Let's Encrypt / self-signed / manual, reload.
- **MySQL**: create/manage TeaOps-provisioned MySQL/MariaDB instances —
  start/stop/restart/remove, connection info, account management, a SQL runner,
  port remap and mysqldump backup.
- **文件**: a host file browser (list / mkdir / delete / upload / download); the
  same browser is reused scoped to a container from the Docker page.

Auth: an access **password is auto-generated on first run** and logged once (and
viewable on the settings page); login mints an in-memory bearer session. Login
attempts are rate-limited. The **account is `admin` (editable)**. Owners can also
**log in by WeChat scan** — the page renders a QR the server owner scans with the
mini-program 扫一扫 (validated against existing server ownership, no separate
binding). Port, password, account and the enabled flag are editable on the
settings page and persisted in `<data>/web.json` (0600); changing the port or
disabling the console takes effect after an agent restart.

> ⚠️ Security: the console binds to all interfaces over **plain HTTP** by
> product decision, so the password and session token travel unencrypted.
> Restrict the port with a firewall to trusted sources; anyone who can reach it
> and brute-force/observe the password gains full control of the host.

## Transport

The agent streams metrics over a WebSocket (`wss://<backend>/agent/ws`, derived
from `TEAOPS_BACKEND_URL`). Each tick it sends one JSON report and waits for the
backend ack. If the socket can't connect or a send fails, it automatically falls
back to the HTTP `POST /agent/report` endpoint for that tick and retries the
socket on the next one. Pairing (register/poll) always uses HTTP.

## Self-update

The backend is the single source of agent binaries and decides *when* each
server upgrades (a staggered 1-server/second rollout, rate-limited). The backend
can push an `upgrade` command over the WebSocket (manual, or when this server's
rollout slot opens), and the agent also polls `/agent/should-upgrade` — which
acts as the rollout gate, so a server offline during its slot picks the upgrade
up on its next poll. On upgrade, the agent role:

1. downloads the latest Linux binary for its CPU arch from the backend
   (`GET /agent/dist/download?arch=`) — the agent no longer contacts GitHub or
   the retired downloader directly; the backend mirrors releases itself,
2. atomically replaces its own executable, and
3. exits cleanly so the supervisor role restarts it on the new version.

## Terminal relay (intranet-friendly SSH)

The backend can also push an `open-terminal` command. The agent then dials back
`GET /agent/terminal?session=` (its token travels in the `Authorization: Bearer`
header, not the URL), opens a **local PTY shell** (the user's
login shell), and relays it to the backend byte-for-byte. Because the agent
connects *outbound*, this gives the web/mini-program terminal full access to
**intranet / NAT'd servers** the backend can't reach directly — no inbound SSH
or public IP required. The PTY honors window-resize frames so full-screen apps
(vim/top) render correctly.

## Docker management (agent-relayed)

The backend can push an `open-docker` command. The agent dials back
`GET /agent/docker?session=` (token in the `Authorization` header) and serves a
request/response JSON protocol backed by the **Docker daemon API** (via the
`bollard` crate over the local socket — no `docker` CLI required): detect Docker +
versions, auto-install (official get.docker.com script with the Aliyun mirror,
then national registry mirrors in `daemon.json`), list/pull/remove images,
list/start/stop/restart/remove containers + tail logs, and list/remove networks.
Container terminals use the daemon's exec-attach API and container file transfer
uses the archive (tar) API, so neither needs the `docker` CLI on the host.
Pulls can go through an accelerated mirror (e.g. `m.daocloud.io`): the agent
pulls `<mirror>/docker.io/<image>` then re-tags it to the clean image name. Image
pulls and the Docker install run as **detached operations** in a process-global
registry, so they keep running even if the client leaves the page; the client
polls `list_ops`/`op_log` to watch progress and pick up the result on reconnect.
The operations are a fixed whitelist — there is no arbitrary command
pass-through, and user-supplied references are validated and passed as separate
argv entries (never interpolated into a shell).

## Metrics collected

- CPU usage (% averaged across cores)
- Memory usage (% used / total)
- Disk usage (% used across all mounted disks)
- Network throughput (bytes/sec received & transmitted, summed across interfaces)
- Uptime (seconds)
- Hostname, OS name + version
- Local IP (best-effort)
- Agent version (so the backend can prompt an upgrade)

## Running as a service (systemd)

systemd can supervise it too. Run it with `--foreground` so it stays attached
(systemd does the backgrounding); the no-arg form's self-daemonize would make a
`Type=simple` unit think the process exited. It still self-splits the agent role,
and systemd restarts the whole thing if the supervisor ever dies:

```ini
# /etc/systemd/system/teaops-agent.service
[Unit]
Description=TeaOps Agent
After=network-online.target

[Service]
Environment=TEAOPS_BACKEND_URL=https://your-backend.example.com
Environment=TEAOPS_TOKEN_FILE=/var/lib/teaops/agent.token
Environment=TEAOPS_RUNTIME_DIR=/var/lib/teaops
ExecStart=/usr/local/bin/teaops-agent --foreground
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now teaops-agent
journalctl -u teaops-agent -f   # view the pairing code on first start
```

In Docker or environments without systemd, just run the no-arg binary directly —
its supervisor role keeps the agent alive across crashes and self-updates, so no
external process manager is required.

## Bootstrap via SSH (optional, V1 compatibility only)

You may SSH into a server once to copy the binary and install the systemd unit.
After installation, SSH is not used again — all monitoring is agent-push.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE). You may obtain a
copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.
