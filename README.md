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

It then prints its pairing QR + 8-digit code in the foreground (so you can
scan/copy it), then **detaches and keeps running in the background**, appending
logs to `/var/ops/teaops-agent.log`. Pass `--foreground` / `-f` (or set
`TEAOPS_FOREGROUND=1`) to stay attached for debugging.

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
| `TEAOPS_BACKEND_URL` | `https://wxapi.dn7.cn` | backend base URL (use HTTPS in prod); ws/wss is derived from it |
| `TEAOPS_INTERVAL_SECS` | `3` | report interval |
| `TEAOPS_TOKEN_FILE` | `/var/ops/teaops-agent.token` | where the token is persisted |
| `TEAOPS_AGENT_TOKEN` | — | provide directly to skip pairing |
| `TEAOPS_RUNTIME_DIR` | `/var/ops` | shared pid/heartbeat/lock dir for the two roles |
| `TEAOPS_HEARTBEAT_TIMEOUT_SECS` | `15` | peer liveness threshold |
| `TEAOPS_SUPERVISE_INTERVAL_SECS` | `3` | supervisor child-check interval |
| `TEAOPS_RESTART_BACKOFF_SECS` | `2` | delay between agent restarts |
| `TEAOPS_REPO` | `simonsmithmd/Teaops-agent` | upstream repo for self-update |
| `TEAOPS_DOWNLOAD_URL` | `https://downloader.teaops.dn7.cn` | fallback binary source |

## Transport

The agent streams metrics over a WebSocket (`wss://<backend>/agent/ws`, derived
from `TEAOPS_BACKEND_URL`). Each tick it sends one JSON report and waits for the
backend ack. If the socket can't connect or a send fails, it automatically falls
back to the HTTP `POST /agent/report` endpoint for that tick and retries the
socket on the next one. Pairing (register/poll) always uses HTTP.

## Self-update

The backend can push an `upgrade` command over the WebSocket (triggered by the
owner in the mini program, immediately or via the per-server auto-update
toggle), and the agent also polls `/agent/should-upgrade` periodically. On
upgrade, the agent role:

1. fetches the latest Linux binary **GitHub-first** — it parses the upstream
   `releases.atom`, picks the highest version, and downloads that release asset;
   if GitHub is unreachable it falls back to the download/CDN service
   (`downloader.teaops.dn7.cn`),
2. atomically replaces its own executable, and
3. exits cleanly so the supervisor role restarts it on the new version.

## Terminal relay (intranet-friendly SSH)

The backend can also push an `open-terminal` command. The agent then dials back
`GET /agent/terminal?token=&session=`, opens a **local PTY shell** (the user's
login shell), and relays it to the backend byte-for-byte. Because the agent
connects *outbound*, this gives the web/mini-program terminal full access to
**intranet / NAT'd servers** the backend can't reach directly — no inbound SSH
or public IP required. The PTY honors window-resize frames so full-screen apps
(vim/top) render correctly.

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
