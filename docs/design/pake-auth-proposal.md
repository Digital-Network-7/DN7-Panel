# 方案书：以 PAKE 关闭 P1a「线上 verifier 重放」残留风险

> 状态：**提案（未实现）** · 目标读者：DN7 维护者 · 关联：`auth-hardening-decisions` 备忘、`src/infra/auth/verifier.rs`、`src/app/auth/service.rs`、`src/web/ui/js/core.js`
>
> 本文只做**设计与取舍**，不含实现改动。文末给出**待决策问题**，请拍板后再进入编码。

---

## 1. 背景与残留风险的精确定义

DN7 的登录是「浏览器算 verifier、服务器只见 hash」的挑战应答：

1. `GET /api/login/challenge?username=…`（`login_controller.rs:28`）返回 `{ nonce, salt, kdf }`。
   `nonce` 是一次性随机数（`infra/auth/state.rs` 的 `issue_challenge`/`consume_challenge`，单用、短 TTL）。
2. 浏览器算 `verifier = deriveVerifier(salt, password, kdf)`（`core.js:110`），其中 `kdf = "s256:30000"` 是 3 万次加盐 SHA-256 的密钥拉伸。
3. `POST /api/login` 送 `{ username, nonce, verifier, code }`（`core.js:232` / `login.js:18`）。
4. 服务器：`verify_login`（`app/auth/service.rs:60`）先 `consume_challenge(nonce)`（一次性），再 `verify_verifier(exp_hash, verifier)`（`infra/auth/verifier.rs`，比对 `Argon2id(verifier)`）。

**关键事实**：线上传输的 `verifier` 是**静态口令等价物**——它只由 `salt+password+kdf` 决定，**与 nonce 无关**。nonce 只防「同一请求逐字节重放」。

> ⚠️ 顺带修一个注释：`infra/auth/state.rs:139` 写着客户端返回 `sha256(nonce:password)`，与实现（送裸 `verifier`）**不符**，是一处过时/aspirational 注释。无论本方案是否采纳，都应更正该注释以免误导。

### 残留攻击（P1a）

明文 HTTP 暴露（公网 + 未配 TLS）下，被动窃听者：

1. 抓到一次登录的 `verifier`（静态值）。
2. 所抓的 `nonce` 已被消费，无法直接重放。
3. 但攻击者只需**自己** `GET /challenge` 拿一个**新** `nonce`，再 `POST {new_nonce, 抓到的 verifier}` → **登录成功**。

即：单用 nonce 挡不住「verifier 本身被截获后配新 nonce 重放」。这正是备忘 `auth-hardening-decisions` 里标注的、**只有 PAKE 能真正关闭**的一项。

### 为什么「便宜的修法」此路不通

最自然的补丁是让客户端送 `H(nonce : verifier)` 而非裸 `verifier`——这样线上值随 nonce 变化，截获即失效。**但它与我们已经落地的 Argon2-at-rest 互斥**：

- 服务器为防库泄露，存的是 `Argon2id(verifier)`，**不再持有 verifier**（`verifier.rs` 的设计初衷）。
- 要校验 `H(nonce : verifier)`，服务器必须**重算**它，就得知道 verifier 明文 → 与「不存 verifier」矛盾。

于是形成一个**三选二的三角**：

| 目标 | 裸 verifier + 存明文(旧) | 裸 verifier + Argon2(现状) | `H(nonce:verifier)` + 存明文 | **PAKE** |
|---|---|---|---|---|
| 抗库泄露离线爆破 | ❌ | ✅ | ❌ | ✅ |
| 抗线上窃听重放 | ❌ | ❌ ← **P1a** | ✅ | ✅ |
| 服务器不持口令等价物 | ❌ | ✅ | ❌ | ✅ |

现状停在中间列（拿到了「抗库泄露」，代价是放弃了「抗线上重放」）。**只有 PAKE 三者兼得**——这就是本方案的动机。

---

## 2. 威胁模型（PAKE 能关什么、不能关什么）

**能关闭：**
- 明文/降级信道上的**被动窃听 + verifier 重放**（P1a 本体）。
- 服务器**认证库泄露**后的登录重放（PAKE 的 verifier 不是口令等价物，无法直接登录）。
- （OPAQUE 额外）**离线预计算 / 用户名枚举**——服务器不再向未认证客户端下发 per-user salt。

**不能关闭（需在文档中对运维明示）：**
- **端点沦陷**：浏览器或服务器被植入恶意代码 → 明文口令仍会泄露。PAKE 不防端点。
- **首次 TLS 的主动 MITM**：若运维就是裸 HTTP，主动中间人可注入恶意 JS 抓明文口令；PAKE 只在纯 JS 未被篡改时有意义。**结论：PAKE 是明文场景的「纵深防御」，不能替代 TLS。** DN7 的正解仍是 edge 强制 TLS + loopback 默认。
- **在线字典攻击**：任何口令方案都需靠限速/锁定（`verify_login` 已有 per-source 限速）来压制在线猜测；PAKE 不改变这点。

> 定位建议：**P1a 属于「中等、且已被 loopback 默认 + TLS 大幅缓解」的残留**。上 PAKE 的收益是「即使运维错误地裸 HTTP 公网暴露，被动窃听也拿不到可复用凭证」。请以此权衡工作量。

---

## 3. 候选方案对比

四条路线（含「不做 PAKE」的诚实基线）：

- **方案 O（基线，不做 PAKE）**：维持现状 + 把 TLS 变成硬约束（公网暴露且无证书时**拒绝启动**，而非仅告警）。
- **方案 A：SRP-6a**（RFC 5054/2945，经典 aPAKE，基于离散对数大整数模幂）。
- **方案 B：OPAQUE**（RFC 9497 OPRF + 3DH，现代 aPAKE，基于椭圆曲线 ristretto255）。
- **方案 R（已否决）**：放弃 Argon2-at-rest，改回存明文 verifier + 线上 `H(nonce:verifier)`。**否决理由**：等于用「抗库泄露」换「抗窃听」，倒退回三角另一角，非全赢。

### 对比矩阵

| 维度 | O 基线 | A SRP-6a | B OPAQUE |
|---|---|---|---|
| 抗窃听重放 | ⚠️ 仅靠 TLS | ✅ | ✅ |
| 抗库泄露离线爆破 | ✅(Argon2) | ⚠️ 需把拉伸折进 x（见 §4） | ✅（最强，需 OPRF key） |
| 抗预计算/用户名枚举 | ⚠️ 已有 `decoy_salt` 缓解 | ⚠️ 仍下发 salt（`decoy_salt` 缓解） | ✅ 天然不下发 salt |
| 前向保密（会话密钥） | N/A | ➖ 可选 | ✅ 自带 |
| **浏览器纯 JS 可实现（无 WASM）** | ✅ 无变化 | ✅ **big-int 模幂即可** | ❌ 需 ristretto255，实务上要 WASM 或手写曲线 |
| 服务器纯 Rust / 零外部依赖 / musl 静态 | ✅ | ✅ `num-bigint`（纯 Rust） | ✅ 已有 `curve25519-dalek`（`ed25519-dalek` 依赖树里） |
| 生态成熟度 / 可审计 | ✅ | ✅ 老而稳、测试向量齐（RFC 5054） | ⚠️ 较新、正确实现门槛高 |
| 与现有 `s256` 拉伸 + 迁移框架契合 | ✅ | ✅ 可复用 `deriveVerifier` 作内层 | ⚠️ 拉伸并入 envelope，改造更大 |
| 实现/审计工作量 | 极小 | **中** | 高 |
| 每登录往返数 | 2（现状） | 2（可与现有 challenge 端点对齐） | 2–3 |
| 服务器需暂存的每会话临时态 | nonce | nonce + 服务器临时 `b`（可挂在 challenge store） | OPRF 交换态 |

### 关键判断

- **客户端可实现性是硬约束**。DN7 的前端是**自带的纯 JS 资源**（`include_dir!` 内嵌，无构建期打包、无 npm）。
  - SRP 只需 big-int 模幂——纯 JS 用 `BigInt` 即可实现，无第三方、无 WASM，与现有 `core.js` 风格一致。
  - OPAQUE 需要 ristretto255 群运算 + OPRF。纯 JS 手写椭圆曲线**风险极高**（易出常量时间/正确性问题）；实务上得内嵌一个 WASM blob → 破坏「纯 JS、易审计、静态二进制体积可控」的项目气质。
- **服务器侧两者都可行**：`num-bigint`（SRP）是纯 Rust；`curve25519-dalek`（OPAQUE）已经在 `ed25519-dalek` 依赖树里，musl 安全。**瓶颈在浏览器，不在服务器。**
- **OPAQUE 的核心额外收益是「抗预计算/枚举」**，而 DN7 **已用 `decoy_salt`（`login_controller.rs:49`）缓解枚举**——OPAQUE 在此的边际收益打折。
- SRP 的「库泄露仍可离线字典」短板，可通过**把 `s256:30000` 拉伸折进 SRP 的 `x`**（§4）显著抬高爆破成本，接近 Argon2 现状的水平。

---

## 4. 推荐：方案 A（SRP-6a），把现有拉伸折进 `x`

**推荐 SRP-6a**。理由：在 DN7 的「纯 JS 前端 + 零依赖 + 静态 musl」约束下，它是**唯一能全赢三角、又不引入 WASM/曲线手写风险**的方案；OPAQUE 的额外收益（抗预计算）与 DN7 已有的 `decoy_salt` 缓解**高度重叠**，不足以抵消其实现与审计成本。

> 若将来接受「内嵌一个经过审计的 WASM 密码学模块」这一取向，OPAQUE 是可升级的更高上限；本方案的迁移框架（scheme 协商 + 逐账户迁移）对 OPAQUE 同样适用，不会锁死。

### 4.1 参数选型

- **群**：RFC 5054 的 **3072-bit** 或 **4096-bit** 安全素数群（`N`, `g`）。取 4096 更保守；3072 在 JS `BigInt` 模幂下延迟更低。**建议 3072**（约当前 128-bit 安全线，浏览器端单次登录模幂在可接受毫秒级）。
- **散列**：`H = SHA-256`（已全项目可用，`sha2 = "0.10"`）。
- **`x` 的推导（关键）**：标准 SRP 是 `x = H(salt, H(username:password))`。DN7 改为
  `x = H(salt, deriveVerifier(salt, password, kdf))`，即**把现有 `s256:30000` 拉伸当作内层**。这样：
  - 复用 `core.js` 现成的 `deriveVerifier`，零新增拉伸代码；
  - SRP 存的 verifier `v = g^x mod N` 一旦泄露，攻击者做离线字典需对每个候选口令跑一遍 `s256:30000` + 一次模幂 → 成本远高于裸 SHA-256 的 SRP，逼近现状 Argon2 的量级。
- **verifier 存储**：`v = g^x mod N`（大整数，hex/base64）。**替换** `pw_hash` 里现有的 `Argon2id(verifier)`；`pw_salt` 复用为 SRP salt；新增标记 `pw_scheme = "srp-3072-sha256"`。

### 4.2 协议流程（映射到现有端点，仍 2 往返）

```
浏览器                                            服务器（panel）
  |  GET /api/login/challenge?username=U          |
  |---------------------------------------------->|  取 (salt, v, scheme)；生成临时 b、B=k·v+g^b
  |                                               |  把 (challengeId, b, B, U) 暂存进 challenge store
  |  <-- { challengeId, salt, N_id, g, B, scheme }|
  |  算 a、A=g^a、u=H(A,B)、x、S=(B−k·g^x)^(a+u·x)  |
  |  M1 = H(H(N)⊕H(g), H(U), salt, A, B, K),K=H(S)|
  |  POST /api/login { U, challengeId, A, M1, code}|
  |---------------------------------------------->|  取回 b/B；同法算 S、K、期望 M1'
  |                                               |  常量时间比对 M1==M1'；consume(challengeId)
  |  <-- { ok, M2=H(A,M1,K) }  (+会话Cookie)       |  可回 M2 让客户端验服务器（双向认证）
```

- **A=0 / A mod N=0 拒绝**、**B 计算含 `k=H(N,g)`**、**`u=0` 拒绝**、**M1 常量时间比对**——SRP-6a 的标准安全校验点，实现时逐条落。
- 线上只出现 `A`、`M1`、`M2`——**均为一次性、与本次 `b` 绑定**；截获无法配新 challenge 重放（换了 challenge 就换了 `B`，旧 `M1` 失效）。**P1a 关闭。**
- `code`（TOTP）位置不变，仍在 `POST /api/login` 一并校验。

### 4.3 服务器临时态

SRP 需要服务器在两条消息间记住本次的 `b`（及 `B`, `U`）。**直接扩展现有 challenge store**（`infra/auth/state.rs` 已经是「服务器侧、单用、带 TTL、有数量上限」的存储）：把 challenge 从「一个 nonce」升级为「一条 SRP 会话记录 `{U, b, B, exp}`」。数量上限（`state.rs:31` 附近的 caps）天然限制临时态膨胀 DoS。

---

## 5. 迁移策略（逐账户、与 `s256` 迁移同构）

复用现有「新方案随下次改密自然迁移」的成熟范式（见 `auth-hardening-decisions`）：

1. **新增 `pw_scheme` 字段**（`WebSettings` + `PanelUser`，`#[serde(default)]` → 老库读作空）。空 = 走现状 Argon2 路径；`"srp-3072-sha256"` = 走 SRP 路径。
2. **`/challenge` 按账户协商**：账户是 SRP → 返回 `{challengeId, salt, N_id, g, B, scheme:"srp…"}`；否则返回现状 `{nonce, salt, kdf}`。客户端按 `scheme` 分支。
3. **迁移时机**：只有当服务器**能拿到 verifier 明文**时才能算出 SRP 的 `v`。而现状登录时客户端**恰好送来了 verifier**——于是可在「一次成功的旧式登录」里，用刚收到的 verifier 计算 `v=g^H(salt,verifier)`、CAS 写回（**同 `migrate_stored_hash` 的守卫式 compare-and-swap**，`login_controller.rs:196`，避免与改密竞态）。改密/新建账户则直接走 SRP。
4. **双轨期**：两套 scheme 并存直到所有账户迁移；不设强制截止（与 `s256` 一致）。
5. **CLI 侧**：`dn7 user add/passwd`（`crates/dn7-cli`）走的是同一 `deriveVerifier` KDF（`dn7-cred`）——迁移到 SRP 需让 CLI 在本地算 `v` 后经控制通道写入；`dn7-cred` 作为 KDF 单一事实源，新增 `srp_verifier(salt, verifier)` 于此，供浏览器 JS、服务器、CLI 三方保持字节一致（沿用现有「golden vector 测试」保证跨实现一致）。

---

## 6. 对现有代码的影响面（估算，非改动）

| 层 | 文件 | 改动性质 |
|---|---|---|
| KDF 事实源 | `crates/dn7-cred/src/lib.rs` | 新增 SRP `x`/`v` 计算 + golden vectors（纯 Rust `num-bigint`） |
| 前端 | `src/web/ui/js/core.js`、`login.js` | 新增纯 JS SRP 客户端（BigInt 模幂）；login 流程按 `scheme` 分支 |
| 控制器 | `src/web/http/controllers/login_controller.rs` | `/challenge` 返回 SRP 参数 + 暂存 `b`；`/login` 收 `A,M1` 校验、回 `M2`；迁移 hook |
| 应用层 | `src/app/auth/service.rs` | `verify_login`/step-up 增加 SRP 校验分支（M1 常量时间比对） |
| 会话/临时态 | `src/infra/auth/state.rs` | challenge store 承载 SRP 会话记录；修正 §1 的过时注释 |
| 存储 | `src/infra/auth/verifier.rs`、settings/user 模型 | 存 `v` + `pw_scheme`；保留 Argon2 旧路径至迁移完成 |
| CLI | `crates/dn7-cli/src/{user,kdf}.rs` | `user add/passwd` 生成并上送 `v` |
| 新依赖 | `Cargo.toml` | `num-bigint`（纯 Rust、musl 安全）；无 C 链接 |
| 架构测试 | `tests/architecture.rs`、`core` serde 白名单 | `pw_scheme` 入白名单 |

step-up（`app/auth/service.rs:140` 一带）与登录同构，需一并迁移，否则高危操作二次验证仍走裸 verifier。

---

## 7. 风险与测试计划

- **JS BigInt 模幂性能**：3072-bit 模幂在低端设备可能数十毫秒级；需实测。可用 Montgomery/滑窗优化，或退到 2048-bit（安全性权衡）。**验收：** 目标设备登录端到端 < 300ms。
- **常量时间**：`M1` 比对、服务器侧模幂——Rust 侧用 `subtle` 常量时间比较；JS 侧比对无时序泄露价值（M1 本身是公开的一次性值）但仍按常量比对写。
- **临时态 DoS**：`/challenge` 会创建服务器 `b`；靠 challenge store 现有数量上限 + TTL + 限速兜底。**验收：** 洪泛 `/challenge` 不致内存膨胀。
- **跨实现一致性**：以 **RFC 5054 测试向量**为准，`dn7-cred` 加 golden 单测；浏览器 JS 与 Rust 对同一 `(salt,pw)` 必须算出同一 `v`、同一 `M1`（Node 侧交叉验证，沿用现有做法）。
- **降级与并存**：迁移期两 scheme 并存的分支覆盖；改密与迁移的 CAS 竞态（复用 `migrate_stored_hash` 的守卫思路）。
- **静态 musl 复核**：引入 `num-bigint` 后重跑 `DT_NEEDED` 为空的 CI 门禁。
- **回归门禁**：`cargo fmt && clippy -D warnings && test`；`node scripts/check_i18n.js`（若登录页文案有增）。

---

## 8. 工作量与里程碑（粗估）

1. `dn7-cred` SRP `x`/`v` + golden vectors（RFC 5054 向量对齐）——**小-中**。
2. 服务器 `/challenge`+`/login` 双阶段 + challenge store 承载临时态 + verify 分支——**中**。
3. 纯 JS SRP 客户端 + login/setup/改密/step-up 四处流程——**中**（前端最费时）。
4. 逐账户迁移 hook + CLI 上送 `v` + 双轨并存——**中**。
5. 端到端 + 跨实现 + 静态/门禁验证——**中**。

整体**中等工程量**，前端与「四处口令流程」的一致性是主要成本；无第三方依赖引入（仅纯 Rust `num-bigint`）。

---

## 9. 待决策问题（请拍板）

1. **是否值得现在做？** 鉴于 loopback 默认 + edge TLS 已大幅缓解，P1a 是「明文误配下的纵深防御」。可选：
   - (a) **上 SRP-6a**（本方案推荐）；
   - (b) **先做方案 O**——把「公网暴露且无 TLS」从告警升级为**拒绝启动**，以极小成本消掉「明文暴露」这个前提，PAKE 延后；
   - (c) 维持现状，仅修 §1 的过时注释 + 文档明示残留。
2. **群大小**：SRP **3072-bit**（推荐，延迟友好）还是 **4096-bit**（更保守）？
3. **是否需要双向认证 / 会话密钥**：SRP 的 `M2` 可让客户端验证服务器身份，`K` 可派生会话密钥。DN7 目前用 Cookie 会话，是否要引入 `K`（例如绑定后续请求）？默认建议只用 `M2` 做服务器认证，不改现有会话机制。
4. **OPAQUE 的门**：是否**原则上排除内嵌 WASM 密码学模块**？若排除，则 OPAQUE 出局、SRP 是终局；若不排除，可把 OPAQUE 列为「二期上限」。

---

*附：本方案不改动任何代码。经批准后再拆分为可门禁的实现任务。*
