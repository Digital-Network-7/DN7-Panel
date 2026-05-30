# TeaOps Agent

A small Rust daemon that runs on a Linux server (also works on macOS for dev),
collects system metrics with `sysinfo`, and pushes them to the TeaOps backend
every 5 seconds. No SSH is used at runtime.

## Build & run

```bash
cd teaops-agent
cargo build --release
TEAOPS_BACKEND_URL=https://your-backend.example.com ./target/release/teaops-agent
```

On first run with no token, it registers and prints a 6-digit pairing code:

```
========================================
  TeaOps Agent Pairing
  Enter this code in the Mini Program:

        >>>  123456  <<<

  (valid until ...)
========================================
```

Enter the code in the mini program ("服务器" → 添加 → 配对码添加). Once claimed,
the agent receives its `agent_token`, persists it to `teaops-agent.token`, and
starts reporting.

## Configuration (env)

| Var | Default | Notes |
|-----|---------|-------|
| `TEAOPS_BACKEND_URL` | `http://127.0.0.1:8080` | backend base URL (use HTTPS in prod) |
| `TEAOPS_INTERVAL_SECS` | `5` | report interval |
| `TEAOPS_TOKEN_FILE` | `teaops-agent.token` | where the token is persisted |
| `TEAOPS_AGENT_TOKEN` | — | provide directly to skip pairing |

## Metrics collected

- CPU usage (% averaged across cores)
- Memory usage (% used / total)
- Disk usage (% used across all mounted disks)
- Uptime (seconds)
- Hostname, OS name + version
- Local IP (best-effort)

## Running as a service (systemd)

```ini
# /etc/systemd/system/teaops-agent.service
[Unit]
Description=TeaOps Agent
After=network-online.target

[Service]
Environment=TEAOPS_BACKEND_URL=https://your-backend.example.com
Environment=TEAOPS_TOKEN_FILE=/var/lib/teaops/agent.token
ExecStart=/usr/local/bin/teaops-agent
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

## Bootstrap via SSH (optional, V1 compatibility only)

You may SSH into a server once to copy the binary and install the systemd unit.
After installation, SSH is not used again — all monitoring is agent-push.
