# DN7 Panel

> ## 🙏 致谢
>
> 特别感谢 **[LINUX DO](https://linux.do)** 社区，一个真诚、专业、友善的技术社区。
> 本项目的诸多想法、反馈与打磨都受益于这里的伙伴们。

一个小巧的、单文件静态 Rust 二进制程序，通过**机上 Web 控制台**把 Linux 主机变成可完整管理的节点，提供监控、Web 终端，以及 Docker / Nginx / MySQL / 文件管理能力；无需后端、无需面板令牌、无运行时依赖。

> Digital Network 7 产品套件的一部分 ·
> <https://github.com/Digital-Network-7/DN7-Panel>

## 亮点

- **单个静态二进制。** 基于纯 Rust + rustls（musl 构建），运行时不依赖系统动态库，也不依赖 `docker` / `nginx` / `openssl` CLI。
- **自管理。** 自动安装到稳定路径，设置冗余开机自启，守护化运行，并通过双半部 supervisor 机制自愈。
- **机上运行，无需后端。** 控制台直接在本机完成认证并操作主机；敏感信息使用与机器绑定的密钥加密。

## 适用场景与取舍

DN7 Panel 面向单机或少量节点运维场景：使用控制台的人，也应当是这台机器的可信管理员。它的优势是部署简单、无需外部控制平面，并且可以在一个嵌入式 UI 中直接管理 Docker、Nginx、MySQL/MariaDB、文件和终端。

相应地，它也不是多租户 SaaS 控制面。许多能力会以宿主机管理员权限执行，爆炸半径较高。控制台默认监听所有网卡，但首次启动会生成随机高端口、随机安全入口路径和只显示一次的随机密码。面向公网主机时，建议初始化后关闭“Allow public access”，通过 SSH 隧道或配置好的反向代理访问。

## 运行角色

程序会根据启动参数以两种角色之一运行：

- `dn7-panel`（无参数）: **supervisor**，负责拉起面板角色；它会用 `panel` 子命令再次启动*自身*，并在退出时重启。
- `dn7-panel panel`: **panel 角色**，负责运行机上 Web 控制台。

这两个半部会互相守护（`DN7_RUNTIME_DIR` 下的 pid 与 heartbeat 文件）：supervisor 会在 panel 退出后将其重启；panel 也会在 supervisor 死掉时重新拉起它。由于整个系统只有一个二进制，自更新只需要替换这一个文件，两个半部都会以新版本恢复运行。正常使用时只需要执行无参数形式，程序会自行分离出 panel。

## 快速开始

从 [**Releases**](https://github.com/Digital-Network-7/DN7-Panel/releases) 页面下载最新的静态二进制（提供 `x86_64` 和 `arm64` 的 musl 构建），直接运行即可，无需构建，也无额外依赖：

```bash
# 选择与你架构匹配的发行文件，然后执行：
chmod +x dn7-panel
sudo ./dn7-panel
```

> **没有适用于你平台或版本的发行包？** 也可以从源码构建。项目基于纯 Rust + rustls，因此 release 构建不需要系统库：
>
> ```bash
> cargo build --release
> sudo ./target/release/dn7-panel
> ```
>
> 如果你遇到问题，或者缺少适用于你平台的构建，请到 [**Issue**](https://github.com/Digital-Network-7/DN7-Panel/issues) 提交反馈，欢迎报告 bug 与提出需求。

正常启动时，程序会**自动将自身安装到 `/var/dn7/panel/dn7-panel`**，然后从该位置重新执行。因此你可以在任意目录运行下载下来的文件，无需手动创建目录。运行时状态统一位于 `/var/dn7/panel/{data,run,log}`。

它还会安装**冗余开机自启**，确保系统重启后面板自动恢复。具体采用主机所支持的机制（尽力而为、幂等、仅 root 可用）：包括 **systemd unit**、**cron `@reboot`** 项，以及 **`/etc/rc.local`** 中的一行。程序采用单实例机制，即使多种启动方式同时生效，最终也只会运行一个 supervisor。

随后程序会**转入后台运行**，日志追加写入 `/var/dn7/panel/log/dn7-panel.log`（超过约 5 MiB 时会原地裁剪）。如需调试，可传入 `--foreground` / `-f`，或设置 `DN7_FOREGROUND=1` 以前台方式保持附着。

启动横幅会把生成的访问地址、账号和密码**打印一次**。首次端口是随机高端口，登录页还会带一个随机安全入口路径（例如 `/abcd12`）。如果忘记密码，可使用 `dn7-panel reset`（仅安装所有者或 root）重新生成。

常用 CLI 命令（仅安装所有者或 root 可执行管理类命令）：

```bash
dn7-panel reset              # 重置控制台账号与密码
dn7-panel port [N]           # 设置指定端口；省略 N 时生成随机端口
dn7-panel access [/path]     # 设置安全入口路径；省略时生成随机路径
dn7-panel version            # 输出当前二进制版本
dn7-panel help               # 查看命令帮助
```

## 机上 Web 控制台

控制台通过明文 HTTP 在生成的端口提供服务，并使用自动生成的随机密码和安全入口路径。登录过程带有限速，并使用 challenge-response 机制，因此密码不会以明文形式在链路上传输；设置页中还可启用自签名 HTTPS 与 TOTP 双因素认证。

> **暴露面。** 默认情况下控制台会绑定到 `0.0.0.0`（即任意网络均可访问）。设置中的 **“Allow public access”**（设置 → 通用）可以让它只绑定到回环地址 `127.0.0.1`。这通常更安全，建议通过 **Nginx 反向代理（域名）** 或 **SSH 隧道** 来访问面板。

功能包括：

- **监控**：CPU / 内存 / 磁盘 / 网络吞吐，以及历史图表（CPU / 内存 / 网络的 15 分钟 / 1 小时 / 6 小时 / 1 天 / 7 天视图）；后台持续采样，并持久化到 `<data>/metrics-history.json`。
- **终端**：浏览器内主机 PTY Shell，以及容器内 Shell（`docker exec`）。
- **Docker**：镜像（拉取、创建）、容器（生命周期、日志、网络、容器内终端、文件传输）、网络、卷、备份。
- **Nginx**：Docker 模式安装、站点（proxy-host / proxy-container / static）、自定义路径规则、Let's Encrypt / 自签名 / 手动证书 / 命名证书仓库、访问列表、重载。
- **MySQL**：一个由 DN7 接管的 MySQL/MariaDB 实例，支持生命周期管理、连接信息、多数据库、账户管理、端口改映射、`mysqldump` 备份。
- **文件**：浏览 / 上传 / 下载 / 删除主机与容器内文件。

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
| `DN7_FOREGROUND` | — | 设为 `1` 时以前台方式运行（不守护化） |
| `DN7_GITHUB_REPO` | `Digital-Network-7/DN7-Panel` | GitHub 更新源使用的 release 仓库 |
| `DN7_SITE_URL` | `https://dn7.cn` | 默认更新源使用的 Digital Network 7 镜像/API 地址 |
| `DN7_WEB_PORT` | 会被解析，通常无需设置 | 运行时配置兜底；当前首次初始化会生成并持久化随机高端口，建议用 `dn7-panel port` 或设置页修改 |
| `RUST_LOG` | `info,dn7_panel=info` | 前台/日志输出的 tracing 过滤器 |

## 安全模型

独立部署、机上运行、无需后端。控制台在本机完成认证并直接操作主机。静态存储的敏感信息（例如将 Web 密码从初始随机值修改后的持久化内容）会使用与机器绑定的 AES-256-GCM 密钥（`<data>/.panel_key`）加密，因此即使把配置文件复制到其他机器上，也无法解密。与安全相关的设置（如代理信任、绑定暴露范围、容器权限等）都通过校验器包裹，并以默认拒绝的方式回退。详细说明见 [../ARCHITECTURE.md](../ARCHITECTURE.md) 第 13 节。

## 构建

CI 会在每次推送到 `main` 时构建静态 **musl** 二进制（x86_64 + arm64），并发布为 GitHub Release。由于项目基于纯 Rust + rustls，静态构建在运行时不需要系统库。

```bash
cargo build --release          # 本地构建
cargo fmt && cargo clippy --all-targets && cargo test
node scripts/check_i18n.js     # UI 文案一致性检查（在仓库根目录执行）
```

## 开发

- 架构设计、分层规则与代码结构标准见 [../ARCHITECTURE.md](../ARCHITECTURE.md)。`tests/architecture.rs` 用于强制校验依赖方向。
- UI 文案位于 `src/web/ui/js/i18n.js`（4 种语言）；修改 UI 后请运行 `scripts/check_i18n.js`（或 `.py`）进行校验。

## 许可证

本项目采用 **GNU Affero General Public License v3.0**（AGPL-3.0-only）授权。详见 [../LICENSE](../LICENSE)。如果你以网络服务形式运行修改后的版本，AGPL 要求你向该服务的用户提供对应源码。
