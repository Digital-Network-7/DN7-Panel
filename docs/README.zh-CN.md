# DN7 Panel

> ## 🙏 致谢
>
> 特别感谢 **[LINUX DO](https://linux.do)** 社区，一个真诚、专业、友善的技术社区。
> 本项目的诸多想法、反馈与打磨都受益于这里的伙伴们。

一个小巧的、单文件静态 Rust 二进制程序，通过**机上 Web 控制台**把 Linux 主机变成可完整管理的节点，提供监控、Web 终端，以及容器 / 网站 / 文件 / 用户 / 审计日志管理；无需后端、无独立控制面、无运行时依赖。

> Digital Network 7 产品套件的一部分 ·
> <https://github.com/Digital-Network-7/DN7-Panel>

当前版本：**Phanes 27.0.1（build 3）**。版本号遵循
`DN7 Panel <代号> <年>.<大>.<小>（build <N>）`，以
[`release.toml`](../release.toml) 为唯一真相源。

## 亮点

- **单个静态二进制。** 基于纯 Rust + rustls（musl 构建），运行时不依赖系统动态库，也不依赖 `docker` / `nginx` / `openssl` CLI——容器运行时与反向代理都是进程内的纯 Rust 实现。
- **自管理。** 自动安装到稳定路径，设置冗余开机自启，守护化运行，并通过双半部 supervisor 机制自愈。更新来自签名的 GitHub Release，经最快的镜像线路拉取。
- **机上运行，无需后端。** 控制台直接在本机完成认证并操作主机；静态敏感信息以 0600 权限保护，口令保存为单向 **Argon2id** 校验值——浏览器只发送哈希，从不发送明文。

## 适用场景与取舍

DN7 Panel 面向单机或少量节点运维场景：使用控制台的人，也应当是这台机器的可信管理员。它的优势是部署简单、无需外部控制平面，并且可以在一个嵌入式 UI 中直接管理容器、网站、文件、用户和终端。

相应地，它也不是多租户 SaaS 控制面。许多能力会以宿主机管理员权限执行，爆炸半径较高。控制台在你初始化时选定的地址与端口上提供服务——进程内的 edge 会在所有网卡上（默认 `:80` / `:443`）代理它。面向公网主机时，建议用内置的 **IP 白名单**（设置页）、主机防火墙、**SSH 隧道**或反向代理来收窄访问，并开启 **HTTPS** 与 **TOTP 双因素认证**。

## 运行角色

程序会根据启动参数以两种角色之一运行：

- `dn7-panel`（无参数）: **supervisor**，负责拉起面板角色；它会用 `panel` 子命令再次启动*自身*，并在退出时重启。
- `dn7-panel panel`: **panel 角色**，负责运行机上 Web 控制台。

这两个半部会互相守护（`DN7_RUNTIME_DIR` 下的 pid 与 heartbeat 文件）：supervisor 会在 panel 退出后将其重启；panel 也会在 supervisor 死掉时重新拉起它。由于整个系统只有一个二进制，自更新只需要替换这一个文件，两个半部都会以新版本恢复运行。正常使用时只需要执行无参数形式，程序会自行分离出 panel。

## 快速开始

**一行安装** —— 下载最新的静态二进制（在 `ghfast.top` / `ghproxy.net` / GitHub 之间自动竞速选最快的源），并进入首次初始化向导：

```bash
curl -fsSL https://ghfast.top/https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
```

> 能直连 GitHub 时，也可以直接用官方源（二进制仍会在三个源之间竞速）：
>
> ```bash
> curl -fsSL https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
> ```

**或手动安装** —— 从 [**Releases**](https://github.com/Digital-Network-7/DN7-Panel/releases) 页面下载与你架构匹配的静态二进制（提供 `x86_64` 和 `arm64` 的 musl 构建），直接运行即可，无需构建，也无额外依赖：

```bash
chmod +x dn7-panel-linux-*        # 你下载的文件
sudo ./dn7-panel-linux-*
```

> **没有适用于你平台或版本的发行包？** 也可以从源码构建。项目基于纯 Rust + rustls，因此 release 构建不需要系统库：
>
> ```bash
> cargo build --release
> sudo ./target/release/dn7-panel
> ```
>
> 如果你遇到问题，或者缺少适用于你平台的构建，请到 [**Issue**](https://github.com/Digital-Network-7/DN7-Panel/issues) 提交反馈，欢迎报告 bug 与提出需求。

**首次**在交互式终端启动时，DN7 Panel 会运行一个**初始化向导**：环境检测之后，让你选择部署方式（默认 **快速部署**）：

- **快速部署** —— 按服务器时区自动选择界面语言，以公网 IP（明文 HTTP）直接起面板，账号 `admin` + 随机密码。首次登录会**强制**你先改成自己的用户名和密码，才能进入控制台。
- **命令行自定义** —— 在终端里逐项配置：访问地址（公网 IP / 内网 IP / 域名）、HTTPS（Let's Encrypt / 自签名 / 关闭）、网站 HTTP/HTTPS 端口、可选的独立面板端口，以及管理员账号。
- **网页自定义** —— 打印一条一次性安全链接（`http://<地址>/init?init_token=…`，公网与内网各一条），并提供一个**令牌保护的网页向导**，让你在浏览器里完成全部配置。

正常启动时，程序会**自动将自身安装到 `/var/dn7/panel/dn7-panel`**，然后从该位置重新执行。因此你可以在任意目录运行下载下来的文件，无需手动创建目录。它还会把 **`dn7` 管理 CLI** 安装为 `/usr/local/bin/dn7`。运行时状态统一位于 `/var/dn7/panel/{data,run,log}`。

它还会安装**冗余开机自启**，确保系统重启后面板自动恢复。具体采用主机所支持的机制（尽力而为、幂等、仅 root 可用）：包括 **systemd unit**、**cron `@reboot`** 项，以及 **`/etc/rc.local`** 中的一行。程序采用单实例机制，即使多种启动方式同时生效，最终也只会运行一个 supervisor。

随后程序会**转入后台运行**，日志追加写入 `/var/dn7/panel/log/dn7-panel.log`（超过约 5 MiB 时会原地裁剪）。如需调试，可传入 `--foreground` / `-f`，或设置 `DN7_FOREGROUND=1` 以前台方式保持附着。

被锁在外面、或想重新来过？`dn7-panel reset`（仅安装所有者或 root）会清除账号并停止面板；再次运行 `dn7-panel` 即可重新进入初始化向导。

## 命令行

`dn7-panel` 二进制本身只有很小的命令面——它的职责是安装、守护、提供服务：

```bash
dn7-panel                 # 启动（安装并守护面板，然后守护化）
dn7-panel --foreground    # 前台运行、不守护化（-f）
dn7-panel version         # 输出 “<版本> (build <N>)”
dn7-panel reset           # 重置为未初始化（仅所有者/root）——再次运行以重新配置
dn7-panel help            # 查看用法
```

日常管理使用 **`dn7` CLI**（安装于 `/usr/local/bin/dn7`，仅 root），它通过回环控制通道驱动正在运行的面板：

```bash
dn7 status                          # 面板 / edge / 容器总览
dn7 container ls|images|pull|start|stop|rm|logs|exec|stats|net|volumes|...   # （别名：dn7 ct）
dn7 site ls|add|rm|setup|reload     # 网站（add 为引导式向导）
dn7 cert ls|issue|renew|rm          # TLS 证书（issue le|self|manual <域名>）
dn7 edge status|restart|reload      # 内置反向代理
dn7 user ls|add|passwd|rm           # 面板账号（add <名称> [--admin]）
dn7 logs | dn7 metrics | dn7 update # 审计日志 / 资源指标 / 更新状态（--json）
dn7 panel start|stop|restart|status|logs|reset|rotate-token
dn7 service enable|disable|status   # 开机自启
dn7 uninstall                       # 多重确认卸载
```

## 机上 Web 控制台

在你初始化时选定的地址与端口上，由进程内的 edge 提供服务。登录过程带有限速，并使用 **challenge-response** 机制，因此密码不会以明文形式在链路上传输（浏览器发送经过密钥拉伸的校验值，服务端只保存它的 Argon2id 哈希）。设置页中可启用 **HTTPS**（Let's Encrypt 或自签名）与 **TOTP 双因素认证**，还提供 **IP 白名单**来限制哪些地址可以访问控制台。

> **暴露面。** edge 会在你选定的端口上绑定所有网卡，因此控制台默认可从网络访问。面向公网主机时，请用 IP 白名单、防火墙、SSH 隧道或反向代理把它挡在后面，并开启 HTTPS + 2FA。

功能包括：

- **监控**：CPU / 内存 / 磁盘 / 网络吞吐，以及历史图表（CPU / 内存 / 网络的 15 分钟 / 1 小时 / 6 小时 / 1 天 / 7 天视图）；后台持续采样，并持久化到 `<data>/metrics-history.json`。
- **终端**：浏览器内主机 PTY Shell，以及容器内 exec Shell。
- **容器**：内置**纯 Rust 容器运行时**（无需 Docker daemon）：镜像（拉取、创建）、容器生命周期、日志、网络、卷、备份、容器内终端与文件传输。
- **网站**：进程内 edge 反向代理（无需外部 nginx）：站点（proxy-host / proxy-container / static）、自定义路径规则、Let's Encrypt / 自签名 / 手动证书 / 命名证书仓库、访问列表、热重载。
- **文件**：浏览 / 上传 / 下载 / 编辑 / 删除主机与容器内文件。
- **用户**：多个面板账号（管理员 / 非管理员），以系统账户为后端。
- **日志**：可搜索、服务端分页的控制台操作**审计日志**。
- **更新**：一键从签名的 GitHub Release 自更新（手动或自动），支持回滚。

## 页面截图

### 监控页

![监控页](images/1.png)

### 命令行页

![命令行页](images/2.png)

### 容器页

![容器页](images/3.png)

### 网站页

![网站页](images/4.png)

### 文件页

![文件页](images/5.png)

### 设置页

![设置页](images/6.png)

## 配置

大多数运行配置由控制台自身持久化。Web 控制台设置保存在 `<data>/web.json`（权限 0600），更新偏好保存在 `<data>/update.json`（权限 0600），初始化后优先于环境变量生效。环境变量只作为启动默认值或调试开关；项目没有 `.env` 加载器。

| 变量 | 默认值 | 说明 |
|-----|---------|-------|
| `DN7_RUNTIME_DIR` | `/var/dn7/panel` | `data/run/log` 的基础目录，主要用于特殊部署或测试 |
| `DN7_HEARTBEAT_TIMEOUT_SECS` | `15` | 对端存活判定超时阈值 |
| `DN7_SUPERVISE_INTERVAL_SECS` | `3` | supervisor 检查子进程的轮询间隔 |
| `DN7_RESTART_BACKOFF_SECS` | `2` | panel 重启前的退避延迟 |
| `DN7_FOREGROUND` | — | 设为 `1` / `true` / `yes` 时以前台方式运行（不守护化） |
| `DN7_GITHUB_REPO` | `Digital-Network-7/DN7-Panel` | 自更新拉取的 GitHub release 仓库 |
| `DN7_WEB_PORT` | `1080` | 控制台内部回环端口（edge 会在你选定的公网端口上代理它）；通常无需设置 |
| `RUST_LOG` | `info,dn7_panel=info` | 前台/日志输出的 tracing 过滤器 |

### 运行时 / 开发开关

少数开关用于选择不同的运行时行为或辅助本地开发。它们直接从环境变量读取（没有 `.env` 加载器）：

| 变量 | 效果 |
|-----|------|
| `DN7_RUNTIME=docker` | 连接外部 Docker daemon，而不是使用内置的纯 Rust 运行时（后者在 Linux 上为**默认**；任何其它取值都保留内置运行时）。 |
| `DN7_NO_GUARDIAN=1` | 关闭 supervisor/guardian 重新拉起机制，使进程保持前台运行且不再重生——仅用于开发/前台运行。任意非空且不为 `0` 的值都会启用。 |
| `DN7_UPDATE_DIRECT=1` | 直连 GitHub 拉取自更新，跳过镜像代理线路（在代理不可达时有用）。 |
| `DN7_ROOT_USERTEST=1` | 启用受 root 限制的 `/etc` 账户集成测试（会修改在线的 `passwd`/`shadow`/`group`）；需以 root 运行，例如 `sudo DN7_ROOT_USERTEST=1 <testbin>`。未设置时该测试会被跳过。 |

## 安全模型

独立部署、机上运行、无需后端。控制台在本机完成认证并直接操作主机。静态存储的敏感信息以属主专属（`0600`）权限保护；Web 密码不以可还原形式存储——它保存为单向 **Argon2id** 校验值（浏览器只发送经密钥拉伸的哈希、从不发送明文），因此即使拿到文件也无法还原口令。私钥、会话与设置文件同样以 `0600` 写入。可用 **IP 白名单**与 **TOTP 双因素认证**收窄访问，高风险操作还需要二次提权认证。自更新从 GitHub 下载，并在安装前用**编译进二进制的 Ed25519 公钥验签**，因此被攻陷的镜像也无法让面板接受一个被篡改的二进制。与安全相关的设置（如代理信任、容器权限等）都通过校验器包裹，并以默认拒绝的方式回退。详细说明见 [../ARCHITECTURE.md](../ARCHITECTURE.md) 第 13 节。

## 构建

CI 会在每次推送到 `main` 时构建静态 **musl** 二进制（x86_64 + arm64），并在 [`release.toml`](../release.toml) 中的 build 号递增时发布 GitHub Release（每个 build 是一个独立 release，打上 `b<N>` 标签并标记为 Latest；旧 build 保留）。由于项目基于纯 Rust + rustls，静态构建在运行时不需要系统库。

```bash
cargo build --release          # 本地构建
cargo fmt && cargo clippy --workspace --all-targets && cargo test --workspace
node scripts/check_i18n.js     # UI 文案一致性检查（在仓库根目录执行）
```

## 开发

- 架构设计、分层规则与代码结构标准见 [../ARCHITECTURE.md](../ARCHITECTURE.md)。`tests/architecture.rs` 用于强制校验依赖方向。
- UI 文案位于 `src/web/ui/js/i18n.js`（4 种语言）；修改 UI 后请运行 `scripts/check_i18n.js`（或 `.py`）进行校验。

## 许可证

本项目采用 **GNU Affero General Public License v3.0**（AGPL-3.0-only）授权。详见 [../LICENSE](../LICENSE)。如果你以网络服务形式运行修改后的版本，AGPL 要求你向该服务的用户提供对应源码。
