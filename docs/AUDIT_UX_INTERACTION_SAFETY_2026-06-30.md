# Kurrent 后端模型 — 用户体验与交互安全审计

**审计范围**:站在钱包 / 客户端 / 非技术用户视角,看 Kurrent 状态机、settle
verifier、receipt / sponsor interface 在"用户实际操作"层面暴露出的接缝。
本审计**不复审**已经在 rigor / security / design 三份审计里覆盖过的内部
协议正确性问题(Δ 边界、`required_signatures` 下限、`PreferLater`
vs thesis 矛盾、MuSig2 系数 fallback、refund 时钟、accept_update
的 strict-adjacency 等,均已在 `audit-rigor-2026-06-28.md` /
`audit-security-2026-06-28.md` / `AUDIT_KURRENT_FULL_2026-06-28.md`
中讨论)。本审计的轴向是**"模型刻意保持沉默、但用户操作层面必须有信号"**
的那些地方。

**审计对象**:`src/lib.rs`、`src/client.rs`、`docs/KURRENT_THESIS.tex`
中描述的协议状态机 + 钱包侧 API。

---

## Headline 结论

Kurrent 后端模型作为协议规格,在 rigor / security / design 三条轴上
是站得住的(具体边界见前置审计)。但从**用户体验和交互安全**这一条轴
上,模型有 **12 处**留给钱包层"自己想办法"的接缝 — 它们不是模型
逻辑错,而是**模型故意不说话**(典型如 thesis §"non-confiscatory"段
"The covenant does not classify the publisher's behaviour")。
用户/钱包必须独立地把这些留白翻译成可执行的 UI 决策,否则会出现
"协议认为合规、用户实际受害"的不一致。

下面把每条接缝列成 F1…F12,严重度按"用户实际资金可见风险"标注,
与 protocol-correctness 严重度独立。

---

## Findings

### F1 [P1] Displacement 信号不区分"过期状态攻击"与"对方诚实升级"

**位置**:`src/lib.rs` `evaluate_settlement_eligibility` 输出
`SettlementEligibilityDecision { status, displaced_by, … }`,其中
`status = Displaced` 时只携带 `displaced_by: Option<txid>`。

**问题**:钱包看到一个本地状态被 `Displaced` 时,**协议不会**
告诉钱包这条 displacement 候选属于哪一种情况:

| 实际情况 | 用户需要的应对 |
| --- | --- |
| 对方在线,推了 n+1 的新 state-update 后被广播 | 信任,无操作 |
| 对方离线,但签名了 n+1 然后诚意结算 | 信任,无操作 |
| 对方 stale-publishing 老 state,试图抢 settlement | 必须广播自己的更新 |
| 第三方 dust attack | 忽略,无操作 |

`SettlementEligibilityDecision` **不区分这四种**。钱包只能凭"displaced_by
的 txid 在不在本地已签状态集里"自行推断,但这是一个**外部推断**,不是
协议信号。用户面对同一种"你的状态被替代了"的提示,实际风险与应对完全
不同 — 这是 UX 失稳面。

**推荐**:钱包在拿到 `Displaced` 时,自行展开"displaced_by txid → 我有没有
签过这条"与"对方是否在线"两条信号,渲染为四种对应文案之一,并要求
"第三/四种"必须显示在屏幕上由用户主动确认,不允许静默跳过。
模型侧无需改。

---

### F2 [P1] `SameNumberConflict` 把"诚实网络竞速"和"作恶等数伪造"压成同一信号

**位置**:`src/lib.rs:1005` 等号同 n 但 commitment 不同 → 返回
`KurrentError::SameNumberConflict { state_number }`。

**问题**:同一 n 出现两条不同 commitment,可能来自:

1. 双方并发签名同一 n(网络竞速)— **双方都不是坏**;
2. 对方在 n 上给你一种 state,但给链广播了另一种 — **典型作恶**;
3. 钱包软件 bug 导致同 n 重复 encode — **用户属性非恶意**。

`state_number` 这一项对钱包渲染没有帮助。用户看到"SameNumberConflict: 5"
不会知道下一步该"忽略、报警、还是重新签名"。

**推荐**:钱包展示时必须并列显示两条 commitment 的余额表 + 对方签名
时间戳 + 链上接受顺序,人为分类后再让用户决定。如果两条 commitment
余额一致,几乎可以确认情况 1 或 3 — 但模型不替你判,钱包必须自己判。

---

### F3 [P2] 同一条 channel 暴露两种互相矛盾的注册语义,钱包必须独立选

**位置**:`src/lib.rs:980-1058` `accept_update_with_rule` 强制
`state_number == next_state_number`(严格 +1);
`src/lib.rs:1529-1654` `evaluate_settlement_eligibility` 注释明写
"predecessor-independent"、允许跳号,只要"更高 n 的合法替换 +
response window 内被接受即可"。

**问题**:`SettlementRegistry` 的 strict-adjacency 是 harness-本地;
`evaluate_settlement_eligibility` 的 candidate-set 才是 thesis §6
的 production 语义。代码注释(`lib.rs:1520-1528` 处的 harness-scope
caveat)自己就点了这是局部简化,但**没有任何 API 表面告诉外部 caller
"走这条路径而不是那条"**。一个粗心的钱包把 strict-adjacency 当
production 用,**会在 n=3 替换 n=1 时被静默拒掉**,而那条 n=3
的交易对用户是有利的 — 用户实际会失去资金可达性。

**推荐**:钱包必须只走 `evaluate_settlement_eligibility` 这一条路做
"我能不能用这个状态",不要内部维护一套 +1 严格邻接簿记。模型侧
建议显式把 `accept_update` 标为 `pub(crate)` 或加文档说明,降低
误用概率。

---

### F4 [P2] `SameNumberConflictRule::PreferLater` 在 spec 层面与 thesis 矛盾

**位置**:`src/lib.rs:570` enum 定义 + `accept_update_with_rule` 行为;
thesis §"Two different roots at the same (scope_id, n) cannot replace
each other because neither satisfies strict progress"。

**问题**:`PreferLater` 在 registry 层"overwrites the previously-stored
commitment";thesis 却说"cannot replace each other"。钱包把
`PreferLater` 当默认打开,会出现"模型通过的 state 与 thesis 拒绝
的 state 被并列接受"的链路,用户 UI 上看见"对方给我看了 state A,
链上我也接受 state B",两者撞车时钱包无法解释。

**前置审计 SEC-013 / DESIGN-013 已点名**。从 UX 角度补一刀:
钱包必须在 UI 上不让用户切换这条规则 — 默认只允许 `RejectConflict`,
并且任何允许 `PreferLater` 的 wallet 必须显著标注"与 thesis 规范
不一致"。

---

### F5 [P2] `required_signatures >= 1` 在类型层合法,钱包必须强制 `>= 2`

**位置**:`src/lib.rs:1383-1394` `AccessManifest::required_signatures: u16`,
仅校验 `>= 2`(实际上:校验 `>= 2` 是协议校验,但**小于 2 仍可通过
type system**;只有 `validate_channel_update` 会在 1 时拒绝)。

**问题**:如果钱包在**装载对方发来的 `KurrentChannelConfig` JSON**时
不能立即拒绝 `required_signatures = 1`,用户就会在 UI 上看到"双签
通道"实际上只要 1 个签名就够。从用户视角,这是关键 U I 信号,
丢了就丢了对"双签通道"的信任基础。前置 SEC-005 已从协议层指出。

**推荐**:钱包 loader 层在 deserialize 后、`validate_channel_update`
前,先做 `if required_signatures < 2 { reject with UI error }`,
**不**依赖 `validate_channel_update` 的拒绝路径,因为它会吐
`InsufficientSignatures { required: 2, actual: 1 }` — 用户看到了
会以为是临时错误,而实际是对方配置错的。

---

### F6 [P2] 状态更新签名与最终结算签名在用户层面无可视差异

**位置**:`StateUpdate` 与 `ChannelReceipt` 都是 64-byte 单签
(在 production 看 MuSig2 aggregate) — 用户按一次"签名键"时,
钱包弹出的提示必须告诉用户**这次签名是用来推进状态、还是用来终结
通道**。模型不强制这种 UI 区分。

**问题**:用户视角,签 state-update 是"动一下余额数字";签 settlement
是"通道关闭、资金出账"。两者经济意义完全不同,而模型只给两个同等
形态的 digest + signature 对。钱包如果不在 UI 层强制以不同 modal /
不同颜色区分,误签结算的代价是直接的。

**推荐**:钱包必须**禁止**在同一个"签名审批"流程中混排两种签名:
状态更新走"快速签名/自动签名"路径(可配置),结算走独立 modal,
要求二次确认 + 显示结算后余额分布。这条不被模型层覆盖。

---

### F7 [P2] Sponsor-fee policy 是对用户的隐式税收,模型没有给用户层保护

**位置**:`src/lib.rs` `SettlementFeePolicy { max_sponsor_fee, sponsor_mode,
policy_id }` 与 `validate_sponsor_evidence` 仅检查
`sponsor_fee <= max_sponsor_fee`,且 `max_sponsor_fee` 是部署方
任填值。

**问题**:`max_sponsor_fee = 100 KAS` 在 `total_principal = 1 KAS` 的小
通道里 100 倍蒸发;在 `total_principal = 1000 KAS` 通道里 10%。
**钱包没有义务**把对方提交的 fee policy 翻译成"用户视角的占比"。
模型保留了一个 `max_sponsor_fee`,但**经济边界**留给钱包自己理解。

**前置 SEC 已指出 fee-market / sponsor-policy 是 named protocol
requirement**;从 UX 角度补一条:钱包应在载入对方 `SettlementFeePolicy`
时,基于 `funding.total_principal` 给出"占比"显示,并对占比高于
阈值(例如 5%)强制 UI 二次确认。

---

### F8 [P2] Refund 成熟判断完全信任本地 `current_daa`,clock-skew 直接变攻击面

**位置**:`src/lib.rs:1146-1159` `refund_claim(current_daa, required_daa)`,
仅校验 `current_daa < required_daa`。

**问题**:钱包传给 verifier 的 `current_daa` 是本地 RPC 拉的。
NTP 错位、本地时钟被改、RPC 节点报告落后,任意一个都会让
`current_daa` 失真 — refund 提前或推后成熟。前置 SEC-023 已点。

**从 UX**:wallet 必须把 verifier 的 DAA 源单独展示给用户做"健康检查",
任何与第二节点交叉验证偏差 > Δ/4 都视为故障,冻结 refund UI。
模型不会替你做这件事。

---

### F9 [P2] `KurrentError` 没有 `Display` impl,每个钱包都要自己写文案

**位置**:`src/lib.rs:210-350` `KurrentError` 仅 derive `Debug, Clone,
PartialEq, Eq`,没有 `fmt::Display`。

**问题**:这是模型**结构性**留白:40 多种错误变体覆盖了状态机所有
失败模式,**但模型不强制**给用户一个面向人的串。早期钱包最容易
fallback 到 `format!("{:?}", err)`,把 `expected/actual` 这种半结构化
信息直接渲染给用户 — `WrongScriptHash { expected, actual }` 让用户
看到一长串 hex,既不安全(用户截图外泄)也难懂。

**推荐**:钱包写自己的 `&str` 文案 + 维护一个**对外安全字段**
白名单(只渲染给用户 `state_number`、`current_daa`、`required_daa`
等量级信息,不渲染 `expected` script hash 等敏感 hash)。模型侧建议
加 `pub fn user_safe_summary(&self) -> String`,把这条规范固化。

---

### F10 [P3] 可选自由文本字段被用户看见,无长度 / 字符白名单

**位置**:`ChannelReceipt { swap_id, direction }`、`SettlementFeePolicy
{ sponsor_mode, policy_id }`、`ChallengePolicy { mode }`、
`SettlementTemplate { template_id }`、`AccessManifest { authorised_participants }`
等位置。

**问题**:这些都是 `String`,协议校验只比对 hash,不校验值本身。
钱包把它们渲染到 UI 时,会面对:

- `swap_id = "<script>alert(1)</script>"`(如果钱包走 HTML 渲染);
- `direction = "向 Alice 转"`(本地化未对齐、显示串长度无上限);
- `mode = "RejectConflict"`(协议枚举,不该让用户编辑);
- `template_id = ""`(空串、过短)。

**推荐**:钱包在渲染前对每个自由文本字段做 sanitize:
长度上限(例如 64 字节)、字符白名单(字母数字 + 标点固定集)、
所有空字段不渲染、协议枚举字段用对应 enum 显示。
这条纯钱包层。

---

### F11 [P3] `ChannelReceipt::output_id` 是自由串,UI 没有验证手段

**位置**:`src/lib.rs:619` `pub output_id: String` — 注释无;
没有任何校验确认它是某个 outpoint 的标准 36 字节 hex。

**问题**:user 面对 receipt UI 看到的 output_id 不能被验证,因为
没有任何"参考输出点"坐标可以比对。钱包如果把它当作结算回执的
"出账位置"展示,用户无法核对。

**推荐**:钱包在显示 output_id 时,如果它代表 P2SH / outpoint,
做格式校验(36 字节 hex for outpoint;P2SH 32 字节 hex)。不通过即
标红"未校验"。

---

### F12 [P3] `participant_set_hash` 对大小写 / 空白差异无 normalize

**位置**:`src/lib.rs:1195-1199`
```rust
let mut sorted: Vec<&str> = participants.iter().map(String::as_str).collect();
sorted.sort_unstable();
hash_json(DOMAIN_PARTICIPANT_SET, &sorted)
```

**问题**:Alice 端的 participant 列表写 `["Alice", "Bob"]`,Bob 端写
`["alice", "bob"]`,两份 JSON **算成两个不同的 channel_id** —
因为 hash 区分大小写。从用户视角,他们以为"我们在同一个通道",
实际是两条不同的通道;钱包内部就需要为"看起来相同"的两条 channel
维护两套独立 UI。**用户操作**两个表面上相同的 channel,签名时
如果钱包选错了 channel,后果是另一条 channel 的 state 自己签不出来。

**推荐**:
- 模型侧:加 normalize step(trim + NFC + lowercase)后再 hash;
- 钱包侧:在 UI 上把 participant label 颜色绑定到归一化形式,
  显示两边的归一化名,而不是原始字面量。

---

## Wallet-Level UX Guardrails 清单

下面把上面 12 条 finding 折叠成一条**任何 Kurrent 钱包都必须实现**
的 guardrail 列表。这不是 audit finding,是从 finding 抽出的工程契约:

| # | Guardrail | 对应 Finding |
| --- | --- | --- |
| G1 | 拒绝 `response_window_daa` 低于部署推荐下限(自设硬阈值,例如 3600) | (前置审计已加固类型层;UX 层兜底) |
| G2 | `required_signatures < 2` 必须在 loader 阶段直接拒,不走 `validate_channel_update` | F5 |
| G3 | 展示 `Displaced` 时,本地判定四象限之一(诚实升级 / 老状态攻击 / dust / 未知)并显示 | F1 |
| G4 | `SameNumberConflict` 渲染并列对比,不允许自动选 | F2 |
| G5 | 默认只允许 `RejectConflict`;任何启用 `PreferLater` 的 UI 必须显著警告 | F4 |
| G6 | 状态签名走"快速签名"通道;结算签名走独立 modal + 二次确认,两种 UI 严禁混排 | F6 |
| G7 | Sponsor-fee policy 加载时按 `total_principal` 给出占比;占比 > 阈值需二次确认 | F7 |
| G8 | Refund UI 启用前必须完成 DAA 源健康检查(交叉节点偏差 > Δ/4 即冻结) | F8 |
| G9 | `KurrentError` 在向用户渲染前必须经过安全字段白名单 | F9 |
| G10 | 自由文本字段渲染前 sanitize(长度上限 + 字符白名单 + 空字段不渲染) | F10、F11 |
| G11 | Participant label 归一化后做 hash,UI 显示归一化形式 | F12 |
| G12 | 钱包**只走** `evaluate_settlement_eligibility` 这条 candidate-set 语义做"我能不能用这个状态",内部不要维护 +1 严格邻接簿记 | F3 |

---

## 不在范围 / 已被前置审计覆盖

下面这些**已经在前置三份审计里讨论过**,本审计不复述,以免重复:

- RIGOR-002/003/028/031 + SEC-015:Δ / response_window 边界(MIN 已
  从 0 抬到 1,但 UX 层 1 仍过低 — G1 是工程层兜底,不重复审计
  类型层)。
- RIGOR-011: MuSig2 系数 fallback 不一致(密码工程问题,不在 UX 轴)。
- SEC-001:Claim 4 前件的 deployment-level 取舍(协议真值问题,不在 UX 轴)。
- SEC-004:per-participant Schnorr vs aggregate MuSig2 形式 drift
  (实现层 issue,但钱包 UX 表现是"G6 的输入是否符合" — 此处归 G6)。
- SEC-005 / F5:`required_signatures` 下限,协议层 + UX 层互补。
- SEC-010 / F3:registry strict-adjacency vs candidate-set 语义。
- SEC-013 / F4:`PreferLater` 与 thesis 矛盾。
- SEC-023 / F8:refund 时钟信任。
- DESIGN-009 / 012 / 013 / 014 / 016:文档语义层级 / status 字段 / reader
  误读风险,这些不是 wallet-side 行为,是 doc-side 信号一致性。
- KIP-21 / Toccata 字节形式 / lane id 内部编码:加密层细节。

---

## 总结

**协议规格正确**(rigor / security / design 三轴通过),**协议 UX 模型
未自包含**(12 条接缝 + 12 条 guardrail)。任何生产钱包实现必须把
上表 G1–G12 当作**最低门槛 UX 工程契约**,否则会出现"模型合规、
用户受害"的不一致。严重度最高的是 F1 / F2(资金可达性 + 用户决策
阻塞面)和 F6(签名上下文混淆)。
