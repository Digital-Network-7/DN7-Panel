---
inclusion: always
---

# DN7 Panel — Architecture Constitution

Single binary, single crate. We get team-scale boundaries from **directory
layers + a dependency rule + an architecture test**, not from Cargo workspaces.
This document is enforceable at PR granularity: a change that violates the
"禁止项" lists or the dependency direction should fail review (and, increasingly,
`tests/architecture.rs`).

## 1. Core rules (the constitution)

> **domain 不懂传输 · contracts 不懂业务 · infra 不决定规则**

Everything below is a consequence of these three sentences. When a rule here is
ambiguous, fall back to them.

## 2. Layers & directory responsibilities

```
src/
  main.rs        组合根:装配 infra→service→router,spawn(唯一允许 import 所有层)
  domain/        纯规则:error / identity / authz(最核心)+ 各能力模型与校验
  contracts/     对外协议唯一来源:req/resp DTO、命令枚举、错误码注册表
  app/           用例服务(一个用例一个入口)+ ports(仅重外部依赖的 trait)
  infra/         adapters(docker/nginx/mysql/system/store)+ support(json_store/crypto/paths)
  web/           交付层:DTO 解析、调 service、响应映射、中间件、嵌入 UI;state 只做 facade
  platform/      宿主运行时:daemon/supervisor/update/signing/paths/banner/autostart
```

**domain/** — pure business rules, unit-testable without any runtime.
- 放:领域值对象、领域错误(`domain::Error`)、校验结果、纯授权判定(`can_manage`/`level`)。
- **返回什么**:只返回领域值对象 / 领域错误 / 校验结果。**不返回** HTTP 语义、DTO、或面向前端拼好的字符串(禁止 `"ERR_CODE:..."`、`"settings.bad_old_password"` 这类半协议内容出现在 domain)。
- error/identity/authz 是最稳定的核心,放在 domain 顶层,变更需格外谨慎。

**contracts/** — the single source of truth for the *external* protocol only.
- 放:对外 `req/resp` DTO、按操作分组的命令枚举、错误码注册表(对齐 `err.*`)。
- 稳定性要求:字段变更默认视为兼容性变更;错误码可新增,重命名/复用需谨慎;DTO **不得**承载派生业务规则(否则会长成第二套 domain)。
- contracts 引用 domain 的基础类型可以;但 contracts **不依赖 app**。

**app/** — use-cases. One use-case = one explicit entry point.
- 例:`app/account.rs` 暴露 `change_password`、`enable_totp`、`reset_user_password`,每个入口负责完整编排:鉴权后的业务校验 → 端口调用顺序 → 持久化 → 审计 → 会话撤销。
- 不把底层存储细节泄漏给 web;不堆零散 helper 充当事实上的用例。
- `app/ports.rs` 只为真正跨层的重外部依赖建 trait(见第 5 节)。
- **app↔contracts 边界**:app 可依赖 contracts 的**命令枚举**与**错误码注册表**;**默认不以对外 `req/resp` DTO 作为 use-case 的入参/出参**。DTO ↔ 命令/领域类型的映射归 **web 边界**——否则传输模型会漏进用例层。
- **细粒度授权出口**:细粒度授权(谁能管谁、能力门禁)统一经 app/domain 暴露的显式授权判定接口(如 `domain::authz::can_manage`)完成,不散落在 handler/adapter。

**infra/** — side effects. Two kinds, keep them mentally (and ideally directory-) separate:
- **adapters**:`docker`(bollard)、`nginx`(confgen/写盘/reload/htpasswd)、`mysql`、`system`(useradd/sudo/chpasswd/PTY/fs)、`store`(manifest 持久化)。实现 `app::ports`。
- **support**:`json_store`、`crypto`、`paths` —— 技术支撑,不是外部系统适配器,**不建端口**,infra 内直接用。
- infra 实现规则,**不决定**规则(规则在 domain/app)。

**web/** — delivery (the only layer allowed to `use axum`).
- 可做:DTO 解析、粗粒度 authn/路由门禁(是否登录、是否管理员)、响应映射、中间件(gate/CSP/audit scope)。
- **不做能力级业务决策、不直接判断领域规则**(handler 里不得出现 `if role == "admin"` 之类的细粒度授权,或 `if site.trust_proxy && ...` 之类的领域分支——这些归 app/domain)。细粒度授权一律调用 app/domain 暴露的授权判定接口。
- `web/state.rs` 只承载 facade,不再堆共享对象。

**platform/** — host runtime/lifecycle only. 不写业务编排。

## 3. Dependency direction

```
web ─→ app ─→ domain
infra ─→ app(实现 ports)─→ domain
contracts ←─ web, app        (contracts 不依赖 app/infra/web)
platform 独立;跨层装配仅限"受控组合根集合"
```

反向依赖一律禁止。

**受控组合根集合**:`main.rs` 为默认组合根,可跨层 import 装配。其他需要跨层装配的入口(集成测试 bootstrap、一次性维护入口、平台启动封装)**必须显式列入 allowlist**(见架构测试),不得隐式绕过。

## 4. 禁止项清单(architecture test 的依据)

| 层 | 该层文件中禁止出现 |
|---|---|
| `domain/**` | `axum`、`bollard`、`reqwest`、`tokio::process`、`std::process`、`std::fs` 写操作、`serde::{Serialize,Deserialize}` 派生(默认禁止,仅经评审批准的值对象例外白名单)、`"ERR_CODE:"` / 面向前端的错误字符串 |
| `contracts/**` | `tokio`、`axum`、业务编排、领域不变量 |
| `app/**` | `axum`、`bollard`、`reqwest`(外部系统只能经 `ports`) |
| `infra/**` | `axum`、`web::` |
| `web/handlers/**` | `bollard`、`std::process::Command`、直接写 nginx 配置文件、细粒度授权/领域分支 |
| `web/**` | 反向 `use` infra 具体适配器(应经 app facade) |

豁免:`platform/**`(宿主层)、`#[cfg(test)]`、re-export/type alias。跨层装配豁免仅限"受控组合根集合"(默认 `main.rs`,其余须显式入 allowlist)。

## 5. 端口抽象标准(何时建 trait)

只有**同时**满足下面两条才在 `app/ports.rs` 建端口:
1. 有真实外部副作用(Docker daemon、nginx 文件+reload、useradd/chpasswd、会话存储、审计落盘);**且**
2. 需要在测试中 mock,或需要可替换实现。

`json_store`/`crypto`/`paths` 这类纯工具**不建端口**。不要为每个小工具造空壳 trait。

**物理结构**:端口按能力分子模块(`app/ports/<capability>.rs`,由 `app/ports/mod.rs` 聚合),**不要**长期收敛成单个 `ports.rs` 总表文件——否则半年后会重新长成总线文件。原则不变,只是防止物理结构再次失控。

## 6. 错误码归口规则

- domain/app 内部用 `domain::Error`(富语义枚举),**不**用魔法字符串。
- 线上响应仍是 `{ ok:false, code, error }`,`code` 对齐前端 `err.*`——**格式不变**。
- `Error` → 线上 code 的映射**只允许存在于一处**(web 边界的 `From<Error> for ApiError`),杜绝两份码漂移。
- 迁移期可保留旧 `ERR_CODE:` 字符串通道作为过渡,但新代码一律走 `domain::Error`。

## 7. 迁移顺序(绞杀式,每步独立提交,1.96 下 fmt+clippy+test 全绿)

0. steering(本文档)+ `tests/architecture.rs`(只开"目录级 deny")+ `domain/{error,identity,authz}` + 纯校验器 + 错误码归口规则。**零行为变更。**
1. **account**:`web/handlers → app/account → infra/system + infra/store`,定义最小 ports(`SystemAccounts`/`SessionStore`/`AuditSink`)。团队参考样板。
2. **settings**:领域规则+持久化先迁;**运行时副作用(session ttl 热应用、https/port 重启语义)必须在 `app/settings` 编排**,不得退回 web/infra。
3. **nginx**:`domain/nginx`(Site+校验)、`contracts` 命令枚举替大 `Req`、`app/nginx` 编排、`infra/nginx`。
4. **docker**:同构(`infra/docker` 包 bollard)。
5. **files**。
6. **mysql**(最后:同时涉及容器、凭据、实例状态、查询,边界最易反复)。

## 8. 架构测试策略(`tests/architecture.rs`,宽松→严格三层递进)

解析 `use` 行(跳过注释/字符串/`#[cfg(test)]`/组合根),不要做脆弱的裸 grep。

1. **目录级 deny(第 0 步先落地,最稳)**:如 `web/**` 禁 `bollard`/`tokio::process`/`std::process`/nginx 低层模块。
2. **模块级 allowlist(随迁移补)**:如只有 `infra/docker/**` 可 `bollard`,只有 `web/**` 可 `axum`。比全局 deny 更可靠。
3. **语义级(最后补)**:如 `domain/**` 禁 `serde::{Serialize,Deserialize}`、`axum`、`reqwest`、`tokio::process`。不要第 0 步就全开红。

每一层都从"宽松起步、逐步收紧",新增违规即测试失败。迁移期允许对尚未迁移的目录加显式例外标记,但例外**不是永久豁免池**,必须遵守三条硬规则:

```
// arch-allow(<迁移阶段或工单号>): <原因>
```
1. **必须带原因**(为什么暂时违规)。
2. **必须带工单/迁移阶段标识**(可追溯到哪一步会消除它)。
3. **迁移完成后必须删除**——架构测试统计 `arch-allow` 数量,迁移阶段推进时该数应单调下降;遗留的过期例外视为债务。

## 9. 必须主动防的三种退化

这版分层思想本身不是风险,真正要防的是三种缓慢腐化:
1. **contracts 长成第二套领域模型** → 靠 §2 的 app↔contracts 边界 + contracts 稳定性要求挡。
2. **arch-allow 长成永久例外池** → 靠 §8 的三条硬规则 + 数量单调下降挡。
3. **app/ports 长成新的大总线** → 靠 §5 的按能力分子模块挡。

任何 PR 若让这三项之一变差,即使编译通过也应被拒。

## 10. 迁移现状(随推进更新)

**已完成**
- 分层骨架与依赖规则:`domain` / `app` / `infra` / `web` / `platform` 目录 + `tests/architecture.rs` tier-1 治理 `domain`/`infra`/`app`。
- `domain`:`authz`、`identity`(校验器 + `PanelUser` + `Principal`)、`settings`(`WebSettings`)、`error`(`domain::Error` + 唯一 web 边界映射 `map_domain_err`)。
- `infra`:`audit`、`auth`(会话/challenge/ticket/限流)、`store`(users/settings 持久化)。
- `app`:`account` 用例 `change_password` / `enable_2fa` / `disable_2fa`(经 `AccountEnv` 端口,内存 mock 单测);账户自助凭据域 + settings 改密的错误全部走 `domain::Error`。

**待办(建议按能力分阶段做,勿一次性强塞)**
- 管理员用户管理(`users_create/update/delete`)迁入 app 用例(字段多、role/sudo/OS/会话/审计纠缠,需保持原子写语义)。
- 能力竖切 `nginx` / `docker` / `mysql` / `files`:这些模块已有 `validate/store/exec` 内部分层 + `web_dispatch` 薄缝;**命令模型(大 Req→按操作命令枚举)属高改动面、低收益(见 §5 取向),且涉及 bollard/nginx/系统调用、本地无法运行期验证**,务必逐能力小步推进、各自验证,不要在单次改动中全量重写。
