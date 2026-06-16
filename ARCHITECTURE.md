# DN7 Panel — Architecture & Code-Structure Guide

Single binary, single crate. Team-scale boundaries come from **directory
layers + a dependency rule + an architecture test** (`tests/architecture.rs`),
not from Cargo workspaces. This document is enforceable at PR granularity: a
change that violates the dependency direction, the "禁止项" lists, or the
structure limits should fail review.

> This file was previously two Kiro steering files; it is now a normal repo
> doc. It is **not** auto-loaded by any tool — read it as the project
> constitution before making structural changes.

---

# Part I — Architecture Constitution

## 1. Core rules

> **core 不懂传输 · contracts 不懂业务 · infra 不决定规则**

Everything below is a consequence of these three sentences. When a rule here is
ambiguous, fall back to them.

## 2. Layers & directory responsibilities

```
src/
  main.rs        组合根:装配 infra→service→router,spawn(唯一允许 import 所有层)
  core/          纯规则:error / identity / authz(最核心)+ 各能力模型与校验
  contracts/     对外协议唯一来源:req/resp DTO、命令枚举、错误码注册表
  app/           用例服务(一个用例一个入口)+ ports(仅重外部依赖的 trait)
  infra/         adapters(docker/nginx/mysql/system/store)+ support(json_store/crypto/…)
  web/           交付层:DTO 解析、调 service、响应映射、中间件、嵌入 UI(web/http + web/routes)
  platform/      宿主运行时:daemon/supervisor/update/signing/paths/banner/autostart
```

**core/** — pure business rules, unit-testable without any runtime.
- 放:领域值对象、领域错误(`core::Error`)、校验结果、纯授权判定(`can_manage`/`level`)。
- **返回什么**:只返回领域值对象 / 领域错误 / 校验结果。**不返回** HTTP 语义、DTO、或面向前端拼好的字符串(禁止 `"ERR_CODE:..."`、`"settings.bad_old_password"` 这类半协议内容出现在 core)。
- error/identity/authz 是最稳定的核心,变更需格外谨慎。

**contracts/** — the single source of truth for the *external* protocol only.
- 放:对外 `req/resp` DTO、按操作分组的命令枚举、错误码注册表(对齐 `err.*`)。
- 字段变更默认视为兼容性变更;错误码可新增,重命名/复用需谨慎;DTO **不得**承载派生业务规则(否则会长成第二套 core)。
- contracts 引用 core 的基础类型可以;但 contracts **不依赖 app/infra/web**。

**app/** — use-cases. One use-case = one explicit entry point.
- 例:`app/account/` 暴露 `change_password`、`enable_2fa`、`disable_2fa`,每个入口负责完整编排:鉴权后的业务校验 → 端口调用顺序 → 持久化 → 审计 → 会话撤销。
- 不把底层存储细节泄漏给 web;不堆零散 helper 充当事实上的用例。
- `app/ports/` 只为真正跨层的重外部依赖建 trait(见第 5 节)。
- **app↔contracts 边界**:app 可依赖 contracts 的**命令枚举**与**错误码注册表**;**默认不以对外 `req/resp` DTO 作为 use-case 的入参/出参**。DTO ↔ 命令/领域类型的映射归 **web 边界**。
- **细粒度授权出口**:细粒度授权统一经 app/core 暴露的显式判定接口(如 `core::authz::can_manage`),不散落在 handler/adapter。

**infra/** — side effects. Two kinds, kept in separate directories:
- **adapters**:`docker`(bollard)、`nginx`(confgen/写盘/reload/htpasswd)、`mysql`、`system`(useradd/sudo/chpasswd/PTY/fs)、`store`(manifest 持久化)、`metrics`、`file`。实现 `app::ports` 或被 app 直接调用。
- **support**:`json_store`、`crypto`、`op_registry`、`audit`、`procs`、`totp`、`fetch` —— 技术支撑,不是外部系统适配器,**不建端口**,infra 内直接用。
- infra 实现规则,**不决定**规则(规则在 core/app)。

**web/** — delivery (the only layer allowed to `use axum`).
- `web/http/` 是 Http 内核(`kernel`:WebState/Account/鉴权守卫/bootstrap)+ `controllers/`(handler)+ `middleware/`(gate/CSP)+ `exceptions`(Error→HTTP 映射);`web/routes/` 是独立路由表。
- 可做:DTO 解析、粗粒度 authn/路由门禁、响应映射、中间件。
- **不做能力级业务决策、不直接判断领域规则**(handler 里不得出现 `if role == "admin"` 或 `if site.trust_proxy && ...` 这类分支——归 app/core)。
- `WebState` facade 只承载 facade(auth/settings/collector/cfg + 访问器),不堆共享对象。

**platform/** — host runtime/lifecycle only. 不写业务编排。

## 3. Dependency direction

```
web ─→ app ─→ core
infra ─→ app(实现 ports)─→ core
contracts ←─ web, app        (contracts 不依赖 app/infra/web)
platform 独立;跨层装配仅限"受控组合根集合"
```

反向依赖一律禁止。**受控组合根集合**:`main.rs` 为默认组合根,可跨层 import 装配;其他需跨层装配的入口(集成测试 bootstrap、平台启动封装)**必须显式列入架构测试 allowlist**,不得隐式绕过。

## 4. 禁止项清单(architecture test 的依据)

| 层 | 该层文件中禁止出现 |
|---|---|
| `core/**` | `axum`、`bollard`、`reqwest`、`tokio::process`、`std::process`、`std::fs` 写操作、`serde` 派生(默认禁止,仅白名单实体例外)、`"ERR_CODE:"` / 面向前端的错误字符串 |
| `contracts/**` | `tokio`、`axum`、业务编排、领域不变量、依赖 `app/infra/web` |
| `app/**` | `axum`、`bollard`、`reqwest`(外部系统只能经 `ports`)、`crate::web` |
| `infra/**` | `axum`、`crate::web`、`crate::app` |
| `web/**` | `bollard`、`tokio::process`、`std::process`、反向 `use` infra 具体适配器(应经 app facade)、细粒度授权/领域分支 |

豁免:`platform/**`(宿主层)、`#[cfg(test)]`、re-export/type alias。跨层装配豁免仅限受控组合根集合。

## 5. 端口抽象标准(何时建 trait)

只有**同时**满足下面两条才在 `app/ports/` 建端口:
1. 有真实外部副作用(Docker daemon、nginx 文件+reload、useradd/chpasswd、会话存储、审计落盘);**且**
2. 需要在测试中 mock,或需要可替换实现。

`json_store`/`crypto`/`paths` 这类纯工具**不建端口**。
**物理结构**:端口按能力分子模块(`app/ports/<capability>.rs`,由 `app/ports/mod.rs` 聚合),**不要**收敛成单个总表文件。

## 6. 错误码归口规则

- core/app 内部用 `core::Error`(富语义枚举),**不**用魔法字符串。
- 线上响应仍是 `{ ok:false, code, error }`,`code` 对齐前端 `err.*`——**格式不变**。
- `Error` → 线上 code 的映射**只允许存在于一处**(web 边界的 `map_core_err`)。
- 能力层尚保留过渡期的 `ERR_CODE:` 字符串通道(`op_err_body` 解析);新代码一律走 `core::Error`,旧通道逐步收口。

## 7. 必须主动防的三种退化

1. **contracts 长成第二套领域模型** → 靠 §2 的 app↔contracts 边界挡。
2. **arch-allow 长成永久例外池** → 靠架构测试的三条硬规则 + 数量单调下降挡。
3. **app/ports 长成新的大总线** → 靠 §5 的按能力分子模块挡。

任何 PR 若让这三项之一变差,即使编译通过也应被拒。

## 8. 架构测试策略(`tests/architecture.rs`)

解析 `use` 行(跳过注释/字符串/`#[cfg(test)]`/组合根),不做脆弱的裸 grep。三层:
1. **目录级 deny**:按 §4 禁止项锁死各层。
2. **模块级 allowlist**:`bollard` 仅 `src/infra/`,`axum` 仅 `src/web/`。
3. **语义级**:`core` 默认禁 serde,仅白名单持久化实体文件可 derive
   (`core/identity/model.rs`、`core/settings/model.rs`、`core/mysql/catalog.rs`、`core/nginx/model.rs`)。

迁移期对未达标目录可加 `// arch-allow(<阶段/工单>): <原因>` 例外,但必须带原因、带可追溯标识、迁移完成后删除;架构测试统计其数量,应单调下降。

---

# Part II — Code Structure Standards

适用于 `src/` 下全部 Rust 代码与 `src/web/ui/js/` 下的 JS 模块。

## 9. Hard limits

- **文件 ≤ 500 行。** 接近上限的文件拆成模块目录(`foo.rs` → `foo/` 内聚子模块)。生成/数据表(i18n 串表、整套 CSS 主题)是唯一例外。
- **函数体 ≤ 40 行**(不含签名与收尾大括号)。超了就抽 helper。
- **参数 ≤ 4。** 更多参数改用单个 `struct`(`XxxParams`/`XxxReq`),字段带文档。

这些是**上限,不是目标**。更小更好。

## 10. 目录与 `mod.rs` 约定

每个能力模块是一个目录;`mod.rs` 是**纯装配**——只含 `mod` 声明、`use` 导入、`pub use` 再导出,**不含任何条目定义**(`fn`/`struct`/`enum`/`impl`/`const`/`static`/`trait`)。共享类型、dispatch/路由入口、跨子模块 helper 一律放进**命名兄弟文件**(`model.rs`/`kernel.rs`/`dispatch.rs`/`api.rs`/`service.rs`/`shared.rs`),由 `mod.rs` 再导出。

```rust
// foo/mod.rs  — 纯装配
use anyhow::Result;            // 子模块经 `use super::*` 复用的导入

mod model;                     // 共享类型
mod dispatch;                  // op 路由 / 入口
mod validate;

pub(crate) use dispatch::*;    // 对外暴露面
pub(crate) use model::*;       // 共享类型,子模块经 super::* 取得
```

```rust
// foo/dispatch.rs  — 承载定义的兄弟
use super::*;                  // 见到父模块的导入 + 其它兄弟
pub(crate) async fn run_op(...) -> Result<...> { ... }
```

子模块仍经 `use super::*` 取共享项——`mod.rs` 的 `pub(crate) use model::*` 把兄弟的条目放回父命名空间。**被多个子模块读取字段的共享 struct**搬到兄弟文件时,字段须 `pub(crate)`(它不再是读取方的祖先,后代可见性失效)。跨模块项保持 `pub(crate)`/`pub(super)`,不超出必要。

### 拆 "God file" 的缝
- **`model` / types** — 请求结构、响应 DTO、存储记录、枚举。
- **`validate`** — 纯输入校验(无 I/O),易单测。
- **`store` / persistence** — 读写磁盘 JSON/状态、路径 helper。
- **`exec` / operations** — 真正的副作用(起进程、调 Docker daemon、写 nginx conf)。
- **`render` / response mapping** — 拼 JSON/HTTP 响应、错误映射。
- **`dispatch`** — `op`/路由表,只做路由,保持小。

## 11. 重构工作纪律

- **每次提交保持 build green。** 一次拆一组,跑 `cargo fmt && cargo clippy --all-targets && cargo test`,再提交。
- **结构性拆分内不改行为。** 代码逐字搬移;重命名/抽取放到*单独*提交,diff 才好审。
- **让编译器驱动。** 搬代码、build、按报错修、重复。被搬条目默认 `pub(crate)`,过度暴露后续再收紧。
- 用机械工具(sed/awk/git mv)搬行范围,别手敲。
- 动 UI 时跑 `scripts/check_i18n.*`(i18n 一致性)与嵌入式 JS / CSP 自检。

## 12. 当 40 行确实不可行

若一个函数确实无法在不损害清晰度的前提下降到 40 行(如一长串扁平的 op `match`),优先把各臂拆成命名函数。任何有意保留的例外用 `// NOTE:` 简述原因——例外应稀少且经评审。

### 已接受的例外(经评审)
仍超 40 行但属内聚单一职责、拆开反伤可读性的函数:
- **双向 I/O 循环** — PTY/exec/tar/stream 桥接,单个 `select!`/`while` 读写交织:
  `web::terminal::run_web_pty` / `run_web_container_exec`、
  `infra/file/ctn::upload_tar_stream`、`infra/file/ctnfs::web_ctn_read_stream`、
  `platform/supervisor::supervise_loop`。
- **自包含算法** — 如 `infra/nginx/htpasswd::apr1_with_salt`(Apache apr1 MD5-crypt)。
- **Config / DTO 组装** — 输入算完后基本是一大坨结构体/JSON:
  `infra/docker/create/build::build_create_spec`、
  `infra/mysql/provision/install::create_mysql_container`、
  `infra/docker/containers/{list::container_row, inspect::inspect_container}`、
  `infra/nginx/sites/build::site_from_req`。
- **Op 分发表** — 扁平 `match`,每臂一行调用:
  `infra/docker/dispatch::run_op`、`infra/mysql/dispatch::run_op`、
  `infra/docker/containers/actions::container_action`、`web/routes::build_router`。
- **编排管线** — 一串带进度上报的 await 步骤:
  `infra/nginx/certs/acme::acme_http01`、
  `infra/mysql/provision/install::run_install_detached`、
  `web/http/controllers/settings_controller::apply_settings_update`。
- **单遍解析器** — 对外部输出的有状态单循环:`infra/metrics/host::detect_mem_model`。

往这些里加东西时,优先把*新的*逻辑独立步骤抽出去,而不是把函数养更大。其它类别的新函数仍须满足 40 行上限。

## 13. 安全敏感配置(能力护栏)

这是远程管理控制台:产品级配置(站点开关、allow-list、原始 nginx 指令)可直接移动基础设施安全边界。任何这类旋钮必须**用策略包裹**,不能直通底层系统,且四点齐备:

1. **校验** — 纯校验器在入文件/命令前拒绝畸形/过宽输入(放 `validate` 模块,规则可审计)。
2. **安全默认** — 输入空/未设时回退到*封闭*选项,绝不是开放项(空 trusted-proxy 列表只信私网+回环,不是 `0.0.0.0/0`;allow-list 解析不出 peer IP 时 fail closed)。
3. **审计** — 状态变更经 `web/http/controllers/capability_controller`,调 `audit::record_op`(请求/响应脱敏)。
4. **授权** — op 在正确门禁后(`require_admin`/`require_super`),能力暴露面不超出其爆炸半径。

当前敏感旋钮与护栏(新增时同步本表):

| Knob | Validator | Safe default |
|------|-----------|--------------|
| `trust_proxy_cidrs` | `nginx/sites/build::sanitize_trusted_cidrs` | 仅私网 + 回环 |
| nginx `extra_conf` | `validate_extra_conf` + `nginx -t` + 回滚 | 空(无指令) |
| static `local_root` | `valid_local_root`(绝对、存在、deny-list) | 上传托管目录 |
| `allow_ips` | `settings::normalize_allow_ips` | 空=放行任意;未知 peer 时门禁 fail closed |
| `public_access`(面板绑定) | 设置项;关闭则绑 `127.0.0.1` 而非 `0.0.0.0` | 开(`0.0.0.0`);建议关并经 nginx/SSH 隧道 |
| `redirect_url` | `core/nginx::valid_redirect_url`(仅 http/https) | n/a |
| proxy target / `server_name` / location path | `core/nginx` token 校验 | n/a |
| docker 容器 bind 挂载 | `core/docker::host_bind_denied`(拒 docker.sock、`/`、`/etc` `/root` `/boot` `/proc` `/sys` `/dev` 及子路径) | 具名卷 / 非敏感路径 |
| docker `privileged` | `infra/docker/create/build::enforce_create_policy` — 仅 super,默认拒 | `false`(非特权) |
| docker `network` = host/`container:` | `core/docker::network_mode_privileged` 经 `enforce_create_policy` — 仅 super | bridge(隔离) |
| mysql `expose` 宿主端口 | `mysql/provision/install::validate_port`;发布端口绑 `127.0.0.1` | 仅回环(非 `0.0.0.0`) |

新增触及 nginx/系统/网络配置的旋钮时,补一行并确认四点齐备。能不暴露原始基础设施原语就不暴露;一个窄而经校验的产品设置,比直通安全得多。

---

# Part III — Current state

分层迁移已完成:`src/` 顶层只有 `main.rs` + 六个分层目录(`core`/`contracts`/`app`/`infra`/`web`/`platform`),每个能力都是目录,所有 `mod.rs` 纯装配,无超 500 行文件。`tests/architecture.rs` 落地三层检查(目录级 deny + 模块 allowlist + core serde 白名单)。能力用例统一经 `app::<cap>` 入口(web→app→infra),`contracts` 为 nginx/mysql 提供 typed 命令,错误经 `core::Error` 在 web 边界单点映射。维护时按本文档继续守规则即可。
