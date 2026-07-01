# Kurrent 合理性审计 — 2026-06-28

(Status: research boundary, internal review)

> 设计合理性维度审查 — naming 一致性、research note vs protocol spec 边界、假设暴露程度、术语与外部规范对齐、model 域层级、boundary 标记、内部矛盾、P0/P1 blocker 表达清晰度。
> 范围:命名/边界/术语/一致性,不重打 attack surface(那是 audit-security)、不重打形式化证明严密度(那是 audit-rigor)、不重跑 evidence。
> 报告本身就是 prose:本报告自身遵守"research boundary vs production claim"分层,自身使用一致的命名(channel_id/scope_id、KURRENT_*_V1/KurrentXxx/v1、state_number、SettlementMask、EncodedSpk),自身不混说 architecture fit 与 production evidence,自身不写 v1/v2/rev N。

---

## 1. 执行摘要

Kurrent 在 commit `dfc1b49ac7945a907b05bb7901c85eeaf8afc5ef`(参见 `evidence/kurrent-acceptance.json::git_commit`)上把 "prototype marker evidence path" 与 "normative bilateral contest-output channel" 在 `src/lib.rs` 中做了物理分层(LIB:1-26 模块 docstring 显式声明),并把 invoice 设计、factory 压缩承诺、KIP-21 ordering 等未来工作用"研究笔记 / 设计边界 / 未来工作"等显式标签切出(THESIS:607-630, README:18-26)。这一分层是诚实的。

但本审计在 8 个探针下找到 18 条 finding(严重度分布:P0=0, P1=8, P2=10, P3=0),核心问题集中在 3 处:

1. **同一概念在同一文件内并列两套命名约定** — `channel_id`(JSON harness 域,LIB:353-831)与 `scope_id`(commitment 域,LIB:2704-2816)从未被映射;`KURRENT_*_V1`(JSON domain hashes,LIB:192-202)与 `KurrentXxx/v1`(BLAKE2b-keyed commitment tags,LIB:2285-2290)在 `evidence/` JSON 与 `tests/` 中以并列身份出现,但两套 digest 形式不可互换。(DESIGN-001, DESIGN-002, DESIGN-009, DESIGN-010)
2. **关键操作假设在 prose 中分散而未交叉引用** — 响应窗口的概率下界、watchtower/KIP-21 substrate、监测与及时包含义务在 thesis、SECURITY_ASSUMPTIONS、README、runbook 中各以不同措辞陈述,无交叉引用,且 SECURITY_ASSUMPTIONS.md(44 行)从未引用 thesis §"Race and Monitoring Model" 的具体概率形式。(DESIGN-005, DESIGN-008, DESIGN-013, DESIGN-018)
3. **"Status: passed" 在 runbook 头与 production-readiness blockers 列表中存在两层可读性陷阱** — 4 个 PRODUCTION_*.md 头都标 "Status: passed",但 `kurrent-production-readiness.json::blockers` 只列 1 项(security review),而 `AUDIT_CONSOLIDATED_2026-06-27.md` 显式承认 4 项 P0/P1 blocker — production-readiness 证据的 blockers 列表比合并审计窄 3 条,被隐藏的 3 条是 normative contest-output graph(P0)、harness domain 命名(P1)、dirty worktree acceptance(P1)。(DESIGN-016, DESIGN-017)

**verdict**:probe 1-8 共发现 18 条 finding(严重度:P0=0, P1=8, P2=10, P3=0);**无 P0 设计合理性 blocker**,但有 8 条 P1 建议在下一次 commit 中修正(命名域映射、SECURITY_ASSUMPTIONS 跨链、runbook 头语义、production-readiness blockers 列表扩列),以避免 reader 误把 harness 当 commitment 或误把 runbook header 当 production claim。**整体上 Kurrent 的设计合理性在 "research specification + local evidence harness" 的 self-declared 边界内是站得住的**,但 reader 在跨越 harness/commitment 与 research/production 边界时,需要在每一处自行作翻译,而不是由 prose 显式分界。

---

## 2. 范围和方法

### 2.1 In-scope

- `docs/KURRENT_THESIS.tex` (773 lines) 与 `docs/KURRENT_THESIS.pdf` — 协议模型 prose 边界
- `docs/KURRENT_SECURITY_ASSUMPTIONS.md` (44 lines) — 信任/操作假设
- `docs/PRODUCTION_SECURITY_REVIEW.md` + 4 个 `docs/PRODUCTION_*.md` (51-59 lines each) — 边界清晰度
- `docs/KURRENT_FACTORY_COMMITMENT_DESIGN.md` (72 lines) + `docs/KURRENT_INVOICE_DESIGN_RESEARCH.md` (169 lines) — 内部一致性,与 thesis 术语对齐
- `src/lib.rs` (3093 lines)、`src/bin/kurrentctl.rs` (5748 lines) — 命名与 thesis 一致性
- `tests/protocol_model.rs` (1966 lines) + `tests/normative_construction.rs` (774 lines) — harness 测试与 normative 测试的命名分裂
- `evidence/*.json` — `KURRENT_*_V1` harness 域标记;`evidence/production/target-profile.json` 的 `protocol_domains` 列表

### 2.2 Out-of-scope

- `docs/AUDIT_AGGREGATE_6134cad.md` 已记录的 9 条已 resolved finding 与 51 条 aggregate finding(任务已声明 out-of-scope,除非能证明未修)
- 攻击面与 fund-safety 论断(那是 audit-security 范围,见 `docs/audit-security-2026-06-28.md`)
- 形式化证明严密度(那是 audit-rigor 范围)
- 重新跑 evidence、部署、上线路径
- `drivers/kaspa-devnet/src/main.rs` 的内部实现(本审计只读 evidence JSON 中露出的 domain 字符串)

### 2.3 方法

8 个探针各自由 2-3 个独立证据点交叉验证,naming finding 的引用全部在 `file:line` 级别。每条 finding 由以下流程产出:定位 2 个以上的 `file:line` 证据;核对 thesis 命名规范(LIB:192-202 与 LIB:2285-2290 两域、THESIS:222-246 commitment 域、THESIS:159 reader map);核对 README/SECURITY_ASSUMPTIONS boundary 声明;写入 finding 字段。**不读源文件的实现细节,只读命名/字符串/状态行/prose 边界**。

### 2.4 8 探针覆盖矩阵

| 探针 | 范围 | finding 数 | 状态 |
| --- | --- | --- | --- |
| 1. Naming 一致性 | src/lib.rs / tests/ / kurrentctl.rs / evidence/ / thesis 中 5 个概念名 | 2 | covered |
| 2. Research note vs protocol spec 边界 | thesis §1+§13 vs §3-§7; invoice note 自我定位 vs README 列出方式 | 2 | covered |
| 3. 假设暴露程度 | SECURITY_ASSUMPTIONS vs thesis §"Race and Monitoring Model" vs README §"Non-Claims" vs runbook 头 | 2 | covered |
| 4. 术语与外部规范对齐 | Toccata / Kaspa / KIP / bech32m / BOLT 11 / MuSig2 在 prose 与代码中的使用 | 2 | covered |
| 5. Model 域的层级性 | harness 域 (`KURRENT_*_V1`) vs commitment 域 (`KurrentXxx/v1`) 是否被显式分层 | 2 | covered |
| 6. Boundary 标记 (architecture fit vs production evidence) | evidence JSON 的 status 字段、kurrent-production-readiness.json 的 blockers 列表、thesis §13 | 2 | covered |
| 7. 内部矛盾显式化 | probability bound / finality / factory boundary 在多文档间的一致性 | 3 | covered |
| 8. P0/P1 blocker 表达清晰度 | 4 PRODUCTION_*.md runbook 头 vs production-readiness blockers vs 合并审计的 4 P0/P1 | 3 | covered |
| **Total** | | **18** | |

8 探针全部 covered,均≥1 条 finding。**无干净探针**。

---

## 3. 探针 1: Naming 一致性

### Findings

#### DESIGN-001 [P1] `channel_id` 与 `scope_id` 同一角色,无 derivation 桥

- **Evidence A (harness 域)**: `src/lib.rs:353` `KurrentChannelConfig.channel_id`; `src/lib.rs:379` `LatestStateHeader.channel_id`; `src/lib.rs:421` `SettlementCandidateEvidence.channel_id`; `src/lib.rs:598, 705, 831` 多处继续使用 `channel_id` 作为 channel 标识字段。
- **Evidence B (commitment 域)**: `src/lib.rs:2704` `StateCertMessage.scope_id: [u8; 32]`; `src/lib.rs:2762` `CoopCloseMessage.scope_id: [u8; 32]`; `src/lib.rs:2803-2816` `ScopeInputs` 接收 `chain_context`, `covenant_id`, `agg_key`, `delta`, `programme_version`, `policy_hash` 并通过 `compute_scope_id()`(LIB:2835)产出 32 字节 BLAKE2b-keyed digest,与 thesis §3.1 `scope_id` 公式(THESIS:222-235)字节对字节一致。
- **Evidence C (测试分裂)**: `tests/protocol_model.rs:66, 109, 142, 302, 746, 1085, 1092, 1901` 全部使用 `channel_id`;`tests/normative_construction.rs:313-315, 386, 519, 534, 547` 全部使用 `scope_id`。两个测试文件不共享 fixture 命名。
- **Evidence D (kurrentctl 实证)**: `src/bin/kurrentctl.rs:3345, 3371, 3575, 3581, 3596, 3933-3934, 3989, 5059` 写死合成字符串如 `"channel-a"`, `"channel-vc-1"`, `"soak-channel-{N}"`。**没有任何调用点**把 harness 字符串 `channel_id` 喂给 `ScopeInputs::compute_scope_id` 来推导 `scope_id`(`rg -n 'compute_scope_id' src/bin/kurrentctl.rs` 零结果)。
- **Description**: harness JSON 字段 `channel_id` 装的是合成字符串("channel-a"等),commitment 字段 `scope_id` 装的是 32 字节 BLAKE2b-keyed digest。两者概念上是同一角色(channel identity),但代码里**没有 derivation 桥**:harness 测试从不调用 `ScopeInputs::compute_scope_id`,kurrentctl 不读 `ScopeInputs`,reader 看到的 `LatestStateHeader.channel_id = "channel-a"` 与 `ScopeInputs::compute_scope_id()` 产出形式上不可比较。模块 docstring(LIB:1-26)只声明"两个 surface 是不同 artefacts",但未给出 `channel_id` → `scope_id` 的命名映射或显式"harness 域通道身份字段"标签。
- **Suggested direction**: 在 `LatestStateHeader` / `KurrentChannelConfig` 上加 `#[doc = "harness-domain channel identity; not equal to thesis commitment scope_id"]` 文档注释;在 `kurrentctl.rs` 的合成 channel 处写明"harness 域标识,与 thesis 的 scope_id 不可互换";或在 `kurrentctl.rs` 路径中加一个 `harness_channel_id_to_scope_inputs(channel_id: &str, ...)` 桥函数,显示标"harness 域,not normative"。

#### DESIGN-002 [P2] `KURRENT_*_V1` 与 `KurrentXxx/v1` 两域在同一文件并列存在,无显式 "harness / commitment" 分层文档

- **Evidence A (harness 域)**: `src/lib.rs:192-202` 11 个 `DOMAIN_*_V1` 常量(SCREAMING_SNAKE),用于 `hash_json(DOMAIN_STATE, ...)` 等 JSON-digest 调用(LIB:401, 484, 523, 545, 637, 642, 917, 1168, 1173, 1276, 1330, 2137)。
- **Evidence B (commitment 域)**: `src/lib.rs:2285-2290` 6 个 `DOMAIN_KURRENT_*` 常量(PascalCase + `/v1` 后缀),用于 `blake2b_256_keyed(DOMAIN_KURRENT_SCOPE, ...)`(LIB:2836)等 BLAKE2b-keyed 摘要,与 thesis ASCII tag 列表(THESIS:243-245)字节对字节一致。
- **Evidence C (digest 形式不可互换)**: JSON-digest 路径(LIB:401 `LatestStateHeader::hash` = `hash_json(DOMAIN_STATE, self)`)输出十六进制 SHA256-of-canonical-JSON,32 字节 hex;BLAKE2b-keyed 路径(LIB:2836 `ScopeInputs::compute_scope_id` = `blake2b_256_keyed(DOMAIN_KURRENT_SCOPE, payload)`)输出 32 字节原始 BLAKE2b 摘要。两种 digest 长度相等(32 字节)但**算法不同**。
- **Evidence D (模块 docstring 隐式说明)**: `src/lib.rs:1-26` 提到 `compute_scope_id`、`StateCertMessage`、`CoopCloseMessage`、`PolicyEncoding`、`EncodedSpk`、`BoundedShape` 是 normative section;marker/registry 段是 prototype evidence path。但 docstring 没有显式说"DOMAIN_STATE = KURRENT_STATE_V1 是 harness 域,DOMAIN_KURRENT_SCOPE = KurrentScope/v1 是 commitment 域"。
- **Description**: 11 + 6 = 17 个 ASCII domain tag 常量共存于 `src/lib.rs`,但 reader 在第 192-202 行看到的是 SCREAMING_SNAKE 模式,在第 2285-2290 行看到的是 PascalCase/v1 模式;两者都是 32 字节摘要输入,但**没有注释、模块分段标题、或 README 表格说明 harness/commitment 分层**。reader 可能把 `KURRENT_STATE_V1` JSON-hash 当作 thesis commitment 摘要的同义词,但实际 digest 算法不同(JSON canonicalization + SHA256 vs BLAKE2b-keyed)。
- **Suggested direction**: 在 `src/lib.rs:192` 上方加一行 `// === HARNESS DOMAIN TAGS (JSON-evidence hashing, not thesis commitment tags) ===`,在 `src/lib.rs:2285` 上方加一行 `// === COMMITMENT DOMAIN TAGS (BLAKE2b-keyed, matches THESIS §3.1 ASCII tag list) ===`;或者在 README 的 "Repository Map" 加一段把两域映射写明。

---

## 4. 探针 2: Research note vs protocol spec 边界

### Findings

#### DESIGN-003 [P1] Thesis §3-§7 写"normative spec"形式但 §1 abstract 与 §13 是唯一声明"未实现"的边界

- **Evidence A (abstract)**: THESIS:143 "A prototype harness exercising the marker-and-verifier path is reported as evidence of model-level displacement behaviour; it does not implement the normative contest-output transaction graph."
- **Evidence B (§3 协议 prose)**: THESIS:161-201 "The Problem: Keeping an Old State Dead" 与 THESIS:203-209 "Why Kaspa-Style Covenants" 写为结论性 prose,无 "future work" / "not yet implemented" 标记。
- **Evidence C (§6 Normative Transaction State Machine)**: THESIS:368-533 完整描述 OpenOutput, ContestOpening, Replacement, Settlement, Cooperative Close 的 covenant predicates 与 bounded shape,无 "prototype only" / "not implemented" 标记。
- **Evidence D (§13 边界声明)**: THESIS:650-689 把 prototype marker evidence path 与 normative bilateral channel 并列;THESIS:686 "It does not implement the normative contest-output transaction graph; it is the prototype evidence path."
- **Description**: thesis 在 §1 abstract 与 §13 两次声明"prototype evidence 不实现 normative contest-output 交易图",但 §3-§7(163-533 行,共 370 行)的协议模型 prose 写得如同"已部署的 normative spec"。reader 第一次读到 §3-§7 时,可能认为这是已实现规范的描述,直到 §13 才看到边界声明。**研究笔记 → 协议 spec 的边界仅在 abstract 与结论段各出现一次**,中间 370 行 prose 是连续 normative spec 形式。
- **Suggested direction**: 在 §3 起始(THESIS:163 附近)插入一段"Spec style: §3-§7 描述 normative bilateral contest-output channel,**当前 prototype 尚未实现完整交易图**;reader 区分规范与已实现请结合 §1 abstract 与 §13 production-readiness scope"。或者把 §3-§7 的 prose 改成"the spec says X" 形式而非"the protocol does X"。

#### DESIGN-004 [P2] Invoice 研究笔记自我定位清晰但 README "Repository Map" 把它当作 substantive 文档列出

- **Evidence A (note 自我定位)**: `docs/KURRENT_INVOICE_DESIGN_RESEARCH.md:3-12` "Status: research note, not normative. This document sketches a possible Kurrent invoice (KI) offer format. It is not part of the Kurrent protocol specification, not an implementation contract, and not a wire format that tooling should parse today."
- **Evidence B (README Repository Map)**: README:227-234 列出 9 个文档,其中 `docs/KURRENT_INVOICE_DESIGN_RESEARCH.md - non-normative invoice design research` 是描述子句,但与 `docs/KURRENT_THESIS.pdf - current research note` 平级;两行没有用视觉标记(粗体/分隔线/颜色)区分"thesis 规范"与"research sketch"。
- **Evidence C (合并审计历史)**: `docs/AUDIT_AGGREGATE_6134cad.md:128-156` (B3, B4) 记录了 `kikaspa*` HRP、零实现、零 `KurrentInvoice` 类型等问题;本审计时这些已被 self-demoted 文本(当前 note 头 3-12 行)收回。
- **Description**: note 本身边界是清晰的(自标 "research note, not normative",且 note:16-19, 21-28 显式列出"此 note 不承诺"清单)。但是 README:227 的 Repository Map 列表没有用任何视觉或语义分层把 thesis 规范与 research sketch 分开,reader 通过 README 跳到 note 时,需要自己读 note 头 3-12 行才知道这是 research sketch。
- **Suggested direction**: 在 README:227-234 的 9 行 Repository Map 中,给 thesis/production/spec 一类 doc 加 `**[normative]**` 前缀,给 research/边界一类 doc 加 `**[research, non-normative]**` 前缀;或者把 research 笔记单独移到 "## Future / Research" 子节。

---

## 5. 探针 3: 假设暴露程度

### Findings

#### DESIGN-005 [P1] SECURITY_ASSUMPTIONS.md(44 行)从不引用 thesis §"Race and Monitoring Model" 的概率下界形式

- **Evidence A (thesis 概率形式)**: THESIS:571-578 "Pr[T_detect + T_construct + T_propagate + T_include < T_Δ] ≥ 1 - ε" 给出概率下界,且"T_Δ is the expected wall-clock duration of the DAA-score interval Δ at the target network profile, with stated confidence"。
- **Evidence B (SECURITY_ASSUMPTIONS)**: `docs/KURRENT_SECURITY_ASSUMPTIONS.md:18-22` "The fund-safety argument assumes ... a response window long enough for an honest party or watchtower to publish a higher-state replacement before stale settlement is accepted" — 无概率符号,无 ε,无具体子项(T_detect / T_construct / T_propagate / T_include)分解。
- **Evidence C (README 简版)**: README:59 "Monitoring and timely inclusion remain part of the security model" — 简化为单句。
- **Evidence D (无交叉引用)**: SECURITY_ASSUMPTIONS.md 全文 44 行,**无任何 thesis §/line 引用**;thesis 571-578 段无 SECURITY_ASSUMPTIONS.md 引用;README 头无 SECURITY_ASSUMPTIONS.md 引用,虽然 README "Repository Map" 列出了该 doc(README:228)。
- **Description**: 关键操作假设("响应窗口概率下界 ≥ 1 - ε")在 thesis 与 SECURITY_ASSUMPTIONS 中以**两种不同形式**出现(thesis 量化、SECURITY_ASSUMPTIONS 定性),且两个文档**不互相引用**。reader 只读 SECURITY_ASSUMPTIONS.md 会得到一个模糊的"response window long enough"假设,无法知道 T_Δ 是什么、T_detect + T_construct + T_propagate + T_include 是哪些子项、ε 是部署级还是 consensus 级。
- **Suggested direction**: SECURITY_ASSUMPTIONS.md 假设段落加一句 "See thesis §'Race and Monitoring Model' (THESIS:571-578) for the formal probability form Pr[T_detect + T_construct + T_propagate + T_include < T_Δ] ≥ 1 - ε";或者把 thesis 的概率段在 SECURITY_ASSUMPTIONS.md 中**逐字重述并加链接**。

#### DESIGN-006 [P2] PRODUCTION_*.md runbook 头部"Status: passed" 与 README "Kurrent does not claim production readiness" 是双层信号,无显式 header 解释

- **Evidence A (runbook 头)**: `docs/PRODUCTION_KEY_MANAGEMENT.md:3` "Status: passed"; `docs/PRODUCTION_MONITORING.md:3` "Status: passed"; `docs/PRODUCTION_RECOVERY.md:3` "Status: passed"; `docs/PRODUCTION_ROLLOUT.md:3` "Status: passed"。
- **Evidence B (runbook 内文)**: 4 个 runbook 第 4-7 行都有一句"does not claim that Kurrent is production-ready, mainnet-ready, or externally reviewed"或类似 disclaimer(PRODUCTION_KEY_MANAGEMENT.md:5-7, PRODUCTION_MONITORING.md:5-6, PRODUCTION_RECOVERY.md:5-6, PRODUCTION_ROLLOUT.md:5-6)。
- **Evidence C (README 头 disclaimer)**: README:178-180 "Kurrent does not claim production readiness"。
- **Description**: 4 个 runbook 同时存在两个相互矛盾的信号:头部 "Status: passed" 表明该 runbook 文档**自身**(key-management 程序、监测程序等)的写作完成度;内文 "does not claim production-ready" 表明 runbook 描述的程序未被外部验证。reader 若只读 header,会以为 production 状态是 passed;若只读 body,会明白 disclaimer。**两个信号之间无显式 header 注释**(如 "Status of this *document*, not of production readiness")。
- **Suggested direction**: 把 4 个 runbook 头的 "Status: passed" 改为 "Status: runbook drafted (document-level, not production gate)" 或加一行 "Note: 'passed' refers to runbook completeness; production gate is `kurrent-production-readiness.json`, currently `failed/blocked`"。

---

## 6. 探针 4: 术语与外部规范对齐

### Findings

#### DESIGN-007 [P2] KIP reference snapshot 在 thesis 中显式命名,4 个 PRODUCTION_*.md runbook 不引用同一 snapshot

- **Evidence A (thesis)**: THESIS:121-135 显式定义 `\newcommand{\kipsnapshot}{1aba3b8}` 并在 THESIS:135 写 "Any KIP text referenced in this note is the version vendored at kaspanet/kips@1aba3b8; later KIP revisions may differ."
- **Evidence B (thesis §6 covenant 引用)**: THESIS:207-209 引用 KIP-10/KIP-17/KIP-20/KIP-21,所有引用都依赖 `1aba3b8` snapshot。
- **Evidence C (runbook)**: `docs/PRODUCTION_KEY_MANAGEMENT.md`, `docs/PRODUCTION_MONITORING.md`, `docs/PRODUCTION_RECOVERY.md`, `docs/PRODUCTION_ROLLOUT.md` 全文 `rg -n 'kaspanet/kips|1aba3b8|KIP reference'` **零结果**。4 个 runbook 引用 KIP-17 / KIP-20 / KIP-21 时不附带 snapshot 锚点。
- **Description**: thesis 显式 pin 到 `kaspanet/kips@1aba3b8`,但 4 个 production runbook 在引用相同 KIP 编号时不附带 snapshot 锚点。reader 知道"我读的 runbook 是基于哪个 KIP 版本"需要自己回到 thesis 找 snapshot。
- **Suggested direction**: 在 4 个 PRODUCTION_*.md runbook 头加一行 "KIP reference snapshot: kaspanet/kips@1aba3b8 (see docs/KURRENT_THESIS.tex §Preamble)"。

#### DESIGN-008 [P2] SECURITY_ASSUMPTIONS.md 假设"watchtower" / "response window" 不命名 KIP-21 sequencing substrate,与 thesis 措辞一致但未 cross-link

- **Evidence A (thesis substrate 命名)**: THESIS:209 "The post-Toccata partitioned sequencing surface in KIP-21 [kip21] is valuable for observability, watchtower evidence, and future based-app and compressed-factory paths, but it is not a fund-safety primitive for the bilateral channel." THESIS:622 "KIP-21 observability and proof systems ... not a fund-safety primitive for the bilateral channel"。
- **Evidence B (harness 实证)**: `src/lib.rs:200` `DOMAIN_LANE_ID = "KURRENT_LANE_V1"`; `src/lib.rs:1189` `derive_kurrent_channel_lane_id(channel_id: &str)`; `evidence/kurrent-live-state-channel-evidence.json:19, 29` `expected_lane_id: "ed33cf98..."`; `kurrent-live-state-channel-evidence.json:210` 实际 lane 字段 `domain_separator: "KURRENT_SETTLEMENT_TEMPLATE_V1"`。
- **Evidence C (SECURITY_ASSUMPTIONS)**: `docs/KURRENT_SECURITY_ASSUMPTIONS.md:21-22` 只说"response window long enough for an honest party or watchtower" — 不提 KIP-21、不提 lane proof、不提 accepted-ordering。
- **Description**: thesis 把 KIP-21 显式定位为"observability substrate, not fund-safety primitive",harness 实际用 KIP-21 lane proof 作为 `accepted_order_index` 与 `daa_score` 的 evidence substrate(由 `evaluate_settlement_eligibility` 在 LIB:1487 处消费)。但 SECURITY_ASSUMPTIONS.md 在命名"watchtower"时,**不附带 KIP-21 substrate 锚点**,读者无法从 SECURITY_ASSUMPTIONS.md 单独知道"watchtower evidence 的具体形式是 KIP-21 lane proof"。
- **Suggested direction**: SECURITY_ASSUMPTIONS.md 假设段加 "Watchtower evidence is sourced from KIP-21 lane proofs (see THESIS:209, 622 and src/lib.rs:1487 `evaluate_settlement_eligibility`); the bilateral fund-safety primitive does not require KIP-21, but the harness does."

---

## 7. 探针 5: Model 域的层级性

### Findings

#### DESIGN-009 [P1] `KURRENT_*_V1`(harness)与 `KurrentXxx/v1`(commitment)在 evidence JSON 中并列出现,reader 可能误把 JSON-hash 当 commitment digest

- **Evidence A (harness 域字符串)**: `evidence/kurrent-live-state-channel-evidence.json:6` `domain_separator: "KURRENT_CHANNEL_RECEIPT_V1"`; 同文件 line 52, 119, 148, 210, 240 用 `KURRENT_STATE_V1` / `KURRENT_SETTLEMENT_TEMPLATE_V1`; `evidence/kurrent-state-channel-headers.json:8, 29, 50` 用 `KURRENT_STATE_V1`; `evidence/kurrent-factory-materialisation-model.json:23, 62` 用 `KURRENT_FACTORY_MATERIALISATION_V1`; `evidence/kurrent-ln-to-kaspa-flow-evidence.json:23` 与 `evidence/kurrent-kaspa-to-ln-flow-evidence.json:23` 用 `KURRENT_LN_INTEROP_V1`; `evidence/kurrent-refund-model.json:3` 用 `KURRENT_CHANNEL_RECEIPT_V1`。
- **Evidence B (commitment 域字符串)**: `tests/normative_construction.rs:66, 67, 73, 74, 80, 81, 758` 用 `KurrentScope/v1`, `KurrentState/v1`; 这些字符串**不出现在 evidence/ 目录**(`rg -n 'KurrentScope/v1|KurrentState/v1|KurrentStateCert/v1' evidence/` 零结果)。
- **Evidence C (digest 形式)**: harness 域走 `hash_json(DOMAIN_STATE, self)`(LIB:401),即 canonical JSON 序列化 + SHA256;commitment 域走 `blake2b_256_keyed(DOMAIN_KURRENT_SCOPE, payload)`(LIB:2836),即 BLAKE2b-256 keyed mode with 64-byte-zero-padded key。两种 digest 都输出 32 字节,但算法不同。
- **Evidence D (production target profile 显式列 harness 域)**: `evidence/production/target-profile.json:52-61` `protocol_domains` 数组列出 8 个 `KURRENT_*_V1` 字符串,**没有列出 6 个 `KurrentXxx/v1` commitment 域字符串**。
- **Description**: harness 域与 commitment 域是两个**算法不同**的 digest 体系,但 reader 看到 evidence JSON 中大量 `KURRENT_*_V1` 字符串与 `tests/normative_construction.rs` 中 `KurrentXxx/v1` 字符串并列出现时,可能(1)以为 `KURRENT_STATE_V1` 是 thesis commitment 域的另一种命名形式,实际不是;(2)在 production target profile(evidence/production/target-profile.json:52-61)中看到 `protocol_domains` 列出 8 个 harness 域,以为这是 production commitment 域的完整列表,实际 commitment 域 6 个 tag **没有列在 production target profile 里**。
- **Suggested direction**: (a) `src/lib.rs:192` 上方加 `// HARNESS DOMAIN TAGS — JSON SHA256, NOT thesis commitment tags`; (b) `src/lib.rs:2285` 上方加 `// COMMITMENT DOMAIN TAGS — BLAKE2b-keyed, match THESIS:243-245`; (c) `evidence/production/target-profile.json` 的 `protocol_domains` 字段拆为 `harness_protocol_domains` 与 `commitment_protocol_domains` 两组。

#### DESIGN-010 [P2] `KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1` / `KURRENT_FEE_SPONSORED_CANDIDATE_MARKER_V1` 在 evidence 中使用,但 src/lib.rs 与 src/bin/kurrentctl.rs 均无 `DOMAIN_*` 常量

- **Evidence A (evidence 实证)**: `evidence/kurrent-live-settlement-eligibility-evidence.json:19, 53, 87` `domain: "KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1"`; `evidence/kurrent-live-fee-sponsored-displacement-evidence.json:345, 390` `domain: "KURRENT_FEE_SPONSORED_CANDIDATE_MARKER_V1"`。
- **Evidence B (驱动方)**: `drivers/kaspa-devnet/src/main.rs:2940, 2959, 5121` 直接字符串写入(`rg -n 'KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1' drivers/` 三个匹配点)。
- **Evidence C (无 Rust 常量)**: `src/lib.rs:192-202` 列出 11 个 harness DOMAIN 常量,**不包含** `KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1` 或 `KURRENT_FEE_SPONSORED_CANDIDATE_MARKER_V1`;`src/bin/kurrentctl.rs` 同样无对应常量(`rg -n 'KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1' src/` 零结果)。
- **Description**: evidence JSON 中出现的两个 marker domain 字符串是 kaspa-devnet driver 写出的,但 Rust harness crate 与 kurrentctl 都没有命名常量锚定它们。如果将来重命名或拼写错误,只有手读 JSON 才能发现。
- **Suggested direction**: 在 `src/lib.rs:192-202` 区段加 `pub const DOMAIN_SETTLEMENT_CANDIDATE_MARKER: &str = "KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1";` 与 `pub const DOMAIN_FEE_SPONSORED_CANDIDATE_MARKER: &str = "KURRENT_FEE_SPONSORED_CANDIDATE_MARKER_V1";`,并在 drivers/kaspa-devnet/src/main.rs 引用 `kurrent::DOMAIN_*` 常量(若 driver 允许 crate 引用);或把这 2 个 domain 字符串从 driver 直接写出改为由 kurrent 公共 API 提供。

---

## 8. 探针 6: Boundary 标记 (architecture fit vs production evidence)

### Findings

#### DESIGN-011 [P1] 4 个 `kurrent-state-channel-*.json` 写死合成 state headers,与 `kurrent-live-state-channel-evidence.json` 的真实 `settlement_template/hash` 是两条不同 evidence 流

- **Evidence A (合成)**: AUDIT_AGGREGATE_6134cad.md M14 记录 `write_state_channel_protocol_files()`(kurrentctl.rs:1913-2007)写出 `kurrent-state-channel-headers.json` / `settlement-template.json` / `receipt.json`,使用硬编码 `template_id = "kurrent-state-settle-v1"` 与 `new_state_commitment = sha256_hex(format!("kurrent-state-{N}"))`。
- **Evidence B (实证合成文件)**: `evidence/kurrent-state-channel-headers.json:8, 29, 50` 的 `domain_separator: "KURRENT_STATE_V1"`、`new_state_commitment` 形如 `sha256_hex("kurrent-state-0")` 等。
- **Evidence C (live)**: `evidence/kurrent-live-state-channel-evidence.json:210-211` `settlement_template/hash: "62dc70d5..."`(由 kaspa-devnet driver 实际算出),channel_receipt scope 与 line 5 `channel_id: "channel-a"` 与 line 19 `expected_lane_id: "ed33cf98..."` 来自 live driver 状态。
- **Evidence D (production target profile 误认)**: `evidence/production/target-profile.json:52-61` `protocol_domains` 列出 8 个 `KURRENT_*_V1` 字符串,但 README:228 / `docs/PRODUCTION_SECURITY_REVIEW.md` 等把"evidence 包含 raw transaction / script / witness / receipt"作为 production-readiness 证据,这**同时**涵盖了合成 `kurrent-state-channel-*.json` 与 live `kurrent-live-*.json`。
- **Description**: `kurrent-state-channel-*.json`(`headers`/`settlement-template`/`receipt`)是 `write_state_channel_protocol_files()` 写出的合成 evidence,使用硬编码模板;synthesized 与 live evidence 在 `evidence/` 同目录并列,两者都不是 thesis 规范的 commitment 域 digest(都走 harness 域 JSON-hash)。production-readiness 工具不区分合成 vs live(`kurrentctl verify-evidence` 不验证 `protocol_files` 字段,见 AUDIT_AGGREGATE_6134cad.md M14)。reader 可能把"evidence 文件存在"误读为"thesis commitment 域已被绑定",实际 evidence 域是 harness 域,与 thesis 规范分属两套 digest。
- **Suggested direction**: (a) `write_state_channel_protocol_files()` 加注释 "synthetic harness-domain evidence, not live driver output";(b) `evidence/production/target-profile.json::protocol_domains` 拆为 `harness_synthetic_evidence` 与 `live_driver_evidence` 两组;(c) `kurrentctl verify-evidence` 加 check: 若 file 由 `write_state_channel_protocol_files` 产生,header 必须含 `synthetic: true` 标记。

#### DESIGN-012 [P2] `evidence/kurrent-acceptance.json` / `target-profile.json` / `production-readiness.json` 三个 status 字段在 reader 视角下层级关系不显式

- **Evidence A (三 evidence 状态)**: `evidence/kurrent-acceptance.json` `status: "passed"`(acceptance status);`evidence/production/target-profile.json:75` `status: "passed"`(target profile status);`evidence/kurrent-production-readiness.json:4` `status: "failed/blocked"`(production gate status)。
- **Evidence B (readme 表述)**: README:18-26 用一张"Layer / What it is / Status"表区分 Normative bilateral channel (Research specification) / Prototype evidence harness (Local evidence harness) / Mainnet / production (Not claimed),但 4 个 evidence JSON 的 status 字段没有这层三态区分,只用 "passed" / "failed/blocked"。
- **Description**: `target-profile.json::status = "passed"` 配合 `production-readiness.json::status = "failed/blocked"` 同时存在,reader 看到 "passed" 字段可能误以为 production 接近,实际 production-readiness 的 blocker 是 security review。三个 evidence JSON 的 status 字段在 reader 视角下没有显式层级标签("local-acceptance status" vs "target-profile status" vs "production-gate status")。
- **Suggested direction**: 把三个 JSON 的 status 字段重命名为 `local_acceptance_status` / `target_profile_status` / `production_readiness_status` 并在 schema 中明确其分别属于哪个 gate;或者在每个 evidence 头部加一个 `gate: "local-acceptance" | "production-gate"` 字段。

---

## 9. 探针 7: 内部矛盾显式化

### Findings

#### DESIGN-013 [P1] Response-window 概率下界在 thesis / SECURITY_ASSUMPTIONS / README 中以三种形式陈述,无交叉引用

- **Evidence A (thesis 量化)**: THESIS:571-578 完整给出 `Pr[T_detect + T_construct + T_propagate + T_include < T_Δ] ≥ 1 - ε` 与 T_Δ = 0.1s · Δ 的 deployment-level 量化(THESIS:576 给出 Δ=600 ≈ 60s、Δ=60 ≈ 6s)。
- **Evidence B (SECURITY_ASSUMPTIONS 定性)**: `docs/KURRENT_SECURITY_ASSUMPTIONS.md:21-22` "a response window long enough for an honest party or watchtower to publish a higher-state replacement before stale settlement is accepted" — 无 ε、无 T_detect 等子项。
- **Evidence C (README 简版)**: README:51-59 "Monitoring and timely inclusion remain part of the security model" — 单句简化;README:59 进一步说 "The protocol does **not** give a magical state-number priority after maturity. If stale settlement is accepted first, the higher certificate alone does not reverse it."
- **Description**: 同一个操作假设("响应窗口足够长")在 3 个文档中以 3 种形式陈述:thesis 量化(概率不等式 + wall-clock 数字),SECURITY_ASSUMPTIONS 定性(无量化),README 单句。三者无 cross-link,reader 在不同文档读到不同措辞时,需要自行判断是否同一假设、是否一致。
- **Suggested direction**: 在 SECURITY_ASSUMPTIONS.md 假设段加 (1) 引用 THESIS:571-578 给出概率形式,(2) 引用 README:51-59 给出 plain-English 简版;README "Non-Claims" 列表(line 271-282)加一条 "Response-window probability bound: deployment-parameterised ε; see SECURITY_ASSUMPTIONS.md and THESIS:571-578"。

#### DESIGN-014 [P2] `KURRENT_FACTORY_COMMITMENT_DESIGN.md` 已存在,thesis §"Factories" 末尾 THESIS:626 仍写"future KURRENT_FACTORY_COMMITMENT_DESIGN.md or equivalent slice",reader 可能误以为 note 还未存在

- **Evidence A (note 已存在)**: `docs/KURRENT_FACTORY_COMMITMENT_DESIGN.md:1-72` 文件存在,头 1-4 行"Status: design boundary",明确说明"current implementation is a local-devnet and typed-model materialisation check ... not a production compressed factory commitment"。
- **Evidence B (thesis forward reference)**: THESIS:626 "their normative treatment belongs to a future `KURRENT_FACTORY_COMMITMENT_DESIGN.md` or equivalent slice, and the production kernel remains the fixed-principal, fixed-participant bilateral channel."
- **Evidence C (thesis 后文 forward reference)**: THESIS:630 再次写 "the carrier for the factory root, the choice of proof system, the KIP-16 cost and pricing model, the third-party dependency model, and the security assumptions are all left to a future `KURRENT_FACTORY_COMMITMENT_DESIGN.md` milestone."
- **Description**: 两次 thesis forward reference 写"future KURRENT_FACTORY_COMMITMENT_DESIGN.md",但 doc 已存在。reader 第一次读 thesis §"Future Work" (THESIS:616-630)看到"future",会去 `docs/` 找,找到 note 头"Status: design boundary",但 note 内容是"current evidence path / future compressed commitment requirements"(note:5-19)—— 即"当前 evidence"与"未来 production 设计"两层都被记录,thensis 的"future"指的是 production 工厂,note 已记录 future 工厂的 commitment 要求但未实现。
- **Suggested direction**: 改写 THESIS:626 与 THESIS:630 的 forward reference 为 "see `KURRENT_FACTORY_COMMITMENT_DESIGN.md` for the current boundary between the implemented materialisation model and the future compressed factory commitment";把"future ... slice"改为"current design boundary note; production compressed-factory implementation remains a future slice"。

#### DESIGN-015 [P2] Finality policy 在 thesis / SECURITY_ASSUMPTIONS / README 中分别以 Kaspa-native / "deployment-specific" / "monitoring" 三种 prose 措辞出现,无 cross-link

- **Evidence A (thesis Kaspa-native)**: THESIS:546 "The finality policy is Kaspa-native: a deployment may express it as a DAA-score, blue-score, or selected-parent/finality-depth rule defined by the target network profile, not as a Bitcoin-style 'k confirmations' rule."
- **Evidence B (SECURITY_ASSUMPTIONS 简化)**: `docs/KURRENT_SECURITY_ASSUMPTIONS.md:18-20` "ordinary UTXO uniqueness, deployment-specific finality policy, and a response window long enough"。
- **Evidence C (README 监测)**: README:51-59 "A higher state can replace a lower contest output immediately. Settlement of the current contest output is delayed by a DAA-relative sequence maturity window." 描述响应窗口;无 finality 词汇。
- **Description**: 同一 finality 概念在 3 个文档以 3 种 prose 措辞陈述:thesis 给量化形式(DAA-score / blue-score / selected-parent);SECURITY_ASSUMPTIONS 给"deployment-specific finality policy"标签(无具体形式);README 不直接命名 finality,通过 DAA-relative sequence 描述。3 文档不 cross-link。
- **Suggested direction**: 在 README §"Protocol In Plain English" 末加一句 "Finality is deployment-specific (Kaspa-native DAA-score / blue-score / selected-parent; see THESIS:546)";SECURITY_ASSUMPTIONS.md 假设段把 "deployment-specific finality policy" 改为"deployment-specific Kaspa-native finality (DAA-score / blue-score / selected-parent; see THESIS:546)"。

---

## 10. 探针 8: P0/P1 blocker 表达清晰度

### Findings

#### DESIGN-016 [P1] 4 个 PRODUCTION_*.md runbook 头 "Status: passed" 与 production-readiness 实际状态"failed/blocked"形成双层信号,reader 易误读

- **Evidence A (runbook 头)**: `docs/PRODUCTION_KEY_MANAGEMENT.md:3` "Status: passed"; `docs/PRODUCTION_MONITORING.md:3` "Status: passed"; `docs/PRODUCTION_RECOVERY.md:3` "Status: passed"; `docs/PRODUCTION_ROLLOUT.md:3` "Status: passed"。
- **Evidence B (runbook 内文 disclaimer)**: 4 个 runbook 第 4-7 行内文 disclaim"does not claim that Kurrent is production-ready"等(PRODUCTION_KEY_MANAGEMENT.md:5-7 等)。
- **Evidence C (production-readiness 实际状态)**: `evidence/kurrent-production-readiness.json:4` `status: "failed/blocked"`; 同文件 line 56-58 `blockers: ["external_security_review: missing or non-passing ..."]`。
- **Evidence D (production 综述)**: `docs/KURRENT_PRODUCTION_ACCEPTANCE.md:3` "Status: blocked on independent external security review"。
- **Description**: 4 个 runbook 头 "Status: passed" 与 production-readiness.json 实际 "failed/blocked" 同时存在;runbook 头的 "passed" 是 runbook 自身文档完成度,但 reader 不知道这一点。kurrentctl 验证逻辑(`production_runbook_satisfies` 在 src/bin/kurrentctl.rs:2127-2150)要求 `text.lines().any(|line| line.trim().eq_ignore_ascii_case("Status: passed"))` 才认为 runbook 通过——这是一个**文档自陈**判定,与 production gate 实际状态无关。**4 个 runbook 的 "passed" 与 production gate 的 "blocked" 在 reader 视角下是矛盾信号**。
- **Suggested direction**: (a) 4 个 runbook 头 "Status: passed" 改为 "Status: drafted (runbook-level, not production gate status)"; (b) 在每个 runbook 第 2-3 行加 "Production gate status: see `evidence/kurrent-production-readiness.json` (currently `failed/blocked`)"; (c) `production_runbook_satisfies` 改名/加注释明示这是 "runbook-drafted" 判定,不是 production-gate 判定。

#### DESIGN-017 [P1] `kurrent-production-readiness.json::blockers` 只列 1 条(security review),合并审计 AUDIT_CONSOLIDATED_2026-06-27.md 显式承认 4 条 P0/P1 blocker,production evidence 的 blocker 列表比合并审计窄 3 条

- **Evidence A (合并审计 4 P0/P1)**: `docs/AUDIT_CONSOLIDATED_2026-06-27.md:55-85` 列出 (1) P0 normative contest-output graph still the next real product milestone; (2) P0 external production security review still absent; (3) P1 JSON/devnet harness must stay clearly non-final; (4) P1 dirty worktree acceptance is mitigated, not eliminated。
- **Evidence B (production-readiness blockers 列表)**: `evidence/kurrent-production-readiness.json:56-58` `blockers: ["external_security_review: missing or non-passing required production evidence at evidence/production/security-review.json"]` — **只列 1 条**。
- **Evidence C (production-readiness requirements 列表)**: `evidence/kurrent-production-readiness.json:6-55` 列 8 个 requirements,每个的 `present: true/false` 字段只反映**文件存在**,不反映合并审计的 4 P0/P1 blocker。
- **Description**: 合并审计承认 4 条 P0/P1 blocker,但 production-readiness evidence 的 `blockers` 字段**只列 1 条**(external security review)。其余 3 条(P0 normative contest-output graph、P1 harness domain naming、P1 dirty worktree acceptance)被 production-readiness 工具忽略,reader 看到 production-readiness evidence 不会知道它们存在。AUDIT_CONSOLIDATED_2026-06-27.md 与 production-readiness evidence 是不交叉引用的。
- **Suggested direction**: (a) 在 `evidence/kurrent-production-readiness.json` 增加 `audit_blockers: ["normative_contest_output_graph", "harness_domain_naming", "dirty_worktree_acceptance"]` 字段,与 `blockers` 字段并列;或者 (b) 在 production-readiness schema 中显式引用合并审计 ID;或者 (c) 把 4 个 P0/P1 blocker 写为 `blockers: [...]` 的额外项(包含 security review 之外)。

#### DESIGN-018 [P2] SECURITY_ASSUMPTIONS.md 全文 44 行无 thesis §/line 引用,thesis §"Race and Monitoring Model"(THESIS:571-578)也无 SECURITY_ASSUMPTIONS.md 引用

- **Evidence A (SECURITY_ASSUMPTIONS 自包含)**: `docs/KURRENT_SECURITY_ASSUMPTIONS.md:1-44` 全文 0 处 thesis 引用,0 处 `KURRENT_THESIS.tex` 引用,0 处 line 引用。
- **Evidence B (thesis 无 SECURITY_ASSUMPTIONS 引用)**: THESIS:159 "Reader map" 段,THESIS:571-578 "Race and Monitoring Model" 段,THESIS:640-649 "Limitations and Open Questions" 段,THESIS:650-689 "Production-Readiness Scope" 段 — 全文**无 SECURITY_ASSUMPTIONS.md 引用**。
- **Evidence C (README 头引用)**: README:228 "Repository Map" 列出 SECURITY_ASSUMPTIONS.md 路径,但 README 自身(285 行)只在 line 260 "Reading Order" 第 3 步"Inspect `docs/KURRENT_SECURITY_ASSUMPTIONS.md` for prototype-only evidence assumptions"提及一次,无 line/§引用。
- **Description**: SECURITY_ASSUMPTIONS.md(44 行)与 thesis §"Race and Monitoring Model"(THESIS:571-578)分别陈述响应窗口假设,无 cross-link。reader 不知道这两个文档的对应关系。
- **Suggested direction**: 在 SECURITY_ASSUMPTIONS.md "## Assumptions" 段加 line 引用 "Response window: see THESIS:571-578 (probability form) and THESIS:546 (finality policy)";在 THESIS:571 段加 "Operational liveness assumption is also recorded in `KURRENT_SECURITY_ASSUMPTIONS.md` (44-line research-boundary note)"。

---

## 11. 跨探针综合 (cross-probe synthesis)

按"根因-描述"对 18 条 finding 做去重合并(与本审计 agent memory 记录的 multi-source synthesis 原则一致 — dedup by root cause, not by tag):

### 根因 A: Harness 域与 Commitment 域的命名/算法未被 prose 显式分层

4 条 finding 共享同一根因:**`src/lib.rs` 把两套 digest 体系物理上分成两段(lines 192-202 harness 域、lines 2285-2290 commitment 域),但 `evidence/` JSON、`tests/`、`README` 不在 prose 层面把两域映射写明**。

- DESIGN-001 (P1) `channel_id` vs `scope_id` 角色同源、形式不同
- DESIGN-002 (P2) `KURRENT_*_V1` vs `KurrentXxx/v1` 两 ASCII tag 家族
- DESIGN-009 (P1) 两域 digest 在 evidence 中并列出现,reader 可能误把 JSON-hash 当 commitment
- DESIGN-010 (P2) 2 个 marker domain 字符串无 Rust 常量锚定

**根因 A 严重度判定**:P1(非 P0)—— 代码物理分层是清晰的,模块 docstring(LIB:1-26)显式声明两段是不同 artefacts;问题在于**外部 prose 文档(README, evidence JSON, runbook)未把分层写到 prose**。修一处即可:在 `src/lib.rs:192` 与 `:2285` 上方分别加 `// HARNESS DOMAIN TAGS` / `// COMMITMENT DOMAIN TAGS` 段标题,并在 README Repository Map 加一段把两域 digest 形式与 ASCII tag 列表写明。

### 根因 B: 关键操作假设在多文档中分散陈述,无 cross-link

4 条 finding 共享根因:**"响应窗口 + monitoring + finality" 是 thesis 的核心操作假设,但 prose 把它分散在 thesis、SECURITY_ASSUMPTIONS、README、PRODUCTION_*.md 中,各文档无相互引用**。

- DESIGN-005 (P1) SECURITY_ASSUMPTIONS.md 不引用 thesis 概率下界
- DESIGN-008 (P2) SECURITY_ASSUMPTIONS.md 不命名 KIP-21 watchtower substrate
- DESIGN-013 (P1) Response-window 概率下界 3 种形式(quant / qual / 1-line)
- DESIGN-018 (P2) SECURITY_ASSUMPTIONS.md 全文 0 thesis 引用

**根因 B 严重度判定**:P1(非 P0)—— 假设都在各文档中陈述,reader 拼图需自行做。修一处即可:在 SECURITY_ASSUMPTIONS.md 假设段加 thesis §/line 引用,在 THESIS:571 段加 SECURITY_ASSUMPTIONS.md 引用,形成双向 cross-link。

### 根因 C: "Status: passed" 双层信号 / production-readiness blockers 列表不完整

4 条 finding 共享根因:**"Status: passed" 在 runbook 头(文档完成度信号)与 production-readiness gate(实际生产状态)之间存在语义错配;production-readiness blockers 列表比合并审计的 4 P0/P1 窄 3 条**。

- DESIGN-006 (P2) PRODUCTION_*.md 头 "Status: passed" 与 README disclaimer 双层信号
- DESIGN-012 (P2) 3 evidence JSON 的 status 字段无层级标签
- DESIGN-016 (P1) runbook 头 "passed" 与 production-readiness 实际 "failed/blocked" 双层信号
- DESIGN-017 (P1) production-readiness blockers 比合并审计 4 P0/P1 窄 3 条

**根因 C 严重度判定**:P1(非 P0)—— 4 条都不在"会被误以为是 production-ready"的最严重位(那是 README §"Production Readiness" 显式 disclaimed),但在 runbook 与 production-readiness 工具层是诚实度问题。修一处即可:在 runbook 头加文档级 vs gate 级的语义区分;`kurrent-production-readiness.json` 加 `audit_blockers` 字段列合并审计的 4 P0/P1。

### 根因 D: 边界声明仅在 abstract 与 §13,中间 prose 缺乏重述

4 条 finding 共享根因:**thesis 与 README 物理上把"prototype evidence 不实现 normative 交易图"声明在 abstract 与 §13 production-readiness scope,中间 §3-§7(370 行)以连续 normative spec 形式写出,reader 第一次读会误以为是已部署;同时 README 的 Repository Map 没有把 thesis 规范与 research sketch 在视觉/语义上分层**。

- DESIGN-003 (P1) Thesis §3-§7 写 normative spec 形式但 §1+§13 是唯一"未实现"边界
- DESIGN-004 (P2) Invoice note 自我定位清晰但 README Repository Map 不分层
- DESIGN-014 (P2) `KURRENT_FACTORY_COMMITMENT_DESIGN.md` 已存在但 thesis §"Future Work" 写 "future ... slice"
- DESIGN-015 (P2) Finality policy 3 种 prose 措辞

**根因 D 严重度判定**:P1(非 P0)—— reader 知道 §1 与 §13 就能自行定位;问题是跨段重述。修一处即可:在 §3 起始(THESIS:163 附近)插一段 "Spec style: §3-§7 normative; current prototype is the marker evidence path of §13",并在 README Repository Map 给 thesis 与 research sketch 加视觉分层(`[normative]` vs `[research, non-normative]`)。

### 根因 E: External spec / KIP snapshot 锚点缺失

2 条 finding 共享根因:**thesis pin 到 `kaspanet/kips@1aba3b8`,但 4 个 PRODUCTION_*.md runbook 与 `kurrent-state-channel-*.json` 合成 evidence 流均不引用同一 snapshot;thensis 自己的 §"Future Work" 句亦未把 KIP snapshot 同步 anchor**。

- DESIGN-007 (P2) KIP snapshot 在 thesis 显式,4 个 runbook 不引用
- DESIGN-011 (P1) 4 个 `kurrent-state-channel-*.json` 写死合成 state headers,与 live 实证是两条 evidence 流(同时 `evidence/production/target-profile.json::protocol_domains` 把 harness 域 tag 当 production commitment 域)

**根因 E 严重度判定**:P2 / P1(非 P0)—— 锚点缺失对 spec 一致性有影响,但 thesis 自身已 pin 锚点;reader 主动回查即可。修一处即可:在 4 个 PRODUCTION_*.md 与 `target-profile.json` 头部加一行 KIP snapshot 引用,与 thesis:131-135 同步。

### 根因合并后的总判定

- **P0 设计合理性 blocker:0 条** — 没有任何一条 finding 是"reader 必被严重误导到误把 prototype 当 production"。
- **P1:8 条**(DESIGN-001, 003, 005, 009, 011, 013, 016, 017)— 跨域命名 / 边界声明 / 假设 cross-link / synthetic-vs-live evidence 流 / runbook 与 gate 信号错配。
- **P2:10 条** — 域分层文档、anchor、prose 措辞统一等可读性 polish。
- **P3:0 条** — 无边缘 finding。

**verdict**:Kurrent 的设计合理性在 self-declared "research specification + local evidence harness" 边界内**站得住**;但 8 条 P1 集中在 4 个根因(A 命名域、B 假设 cross-link、C blocker 表达、D 边界重述),建议在下一次 commit 集中处理。

---

## 12. 与 prior audit 的关系

### 12.1 已知 prior audit(已声明 out-of-scope)

- **`docs/AUDIT_AGGREGATE_6134cad.md` (2026-06-21, 51 findings)**:4 个并行 worker 的合并报告。本审计**不复查 51 条 aggregate finding**,但确认以下 aggregate finding 在当前 commit 已被 self-fixed:
  - B3 (kikaspa HRP)— `KURRENT_INVOICE_DESIGN_RESEARCH.md:78-80` self-correction 显式收回,且 note 头 3-12 行 self-declared "Status: research note, not normative"(`rg -n 'Kikaspa|kikaspa' src/` 零结果,确认 4 个 PRODUCTION_*.md 不再泄漏 `kikaspa` 字符串)。
  - B4 (零实现) — note 头 16-19 行 self-declared"this note does not commit"清单。
  - B5 (recipient_xonly) — `KURRENT_INVOICE_DESIGN_RESEARCH.md:96-105` self-correction 显式撤回,改用 MuSig2 贡献 pubkey。
  - I2 (state_number BE/LE) — 改用 LE(`rg -n 'state_number' src/lib.rs` 全部走 `to_le_bytes`,无 BE 路径)。
  - I10 (domain tag `KURRENT_INVOICE_V1` vs `DOMAIN_INVOICE_V1`)— note 不再使用这两个字符串。
- **`docs/AUDIT_CONSOLIDATED_2026-06-27.md` (2026-06-27, 9 resolved + 4 P0/P1 blocker)**:9 个已 resolved finding 在本审计视角下**仍是 resolved**(`settlement_shape_id` 仅 1、`SettlementMask` 包含在 `StateRootInput::canonical_payload`、`toccataSPK` 分离于 `commitSPK` 等)。4 P0/P1 blocker 在本审计的 DESIGN-016/017 视角下被**部分反映**:DESIGN-016 反映 P1 harness domain naming 的双层信号,DESIGN-017 反映 4 P0/P1 在 `kurrent-production-readiness.json::blockers` 中只有 1 条(security review)。

### 12.2 本审计独有的发现(不在 aggregate / consolidated 范围)

下列 finding 是本审计独立产出,未在 `docs/AUDIT_AGGREGATE_6134cad.md` 或 `docs/AUDIT_CONSOLIDATED_2026-06-27.md` 出现:

- **DESIGN-001** `channel_id` vs `scope_id` 命名桥缺失 — aggregate / consolidated 都没显式讨论过 harness JSON `channel_id` 与 thesis commitment `scope_id` 的同一角色、不同形式。
- **DESIGN-002** `KURRENT_*_V1` vs `KurrentXxx/v1` 两 ASCII tag 家族在同一文件并列 — 合并审计 B3/I10 讨论了 invoice note 的 HRP / domain tag,未涉及 src/lib.rs 的 harness/commitment tag 双层结构。
- **DESIGN-005** SECURITY_ASSUMPTIONS.md 不引用 thesis §"Race and Monitoring Model" — 合并审计未涉及 SECURITY_ASSUMPTIONS.md 的 cross-link 完整性。
- **DESIGN-009** 两域 digest 在 evidence JSON 中并列出现 — 合并审计 B3 讨论了 invoice 的 SHA256 vs BLAKE2b-keyed,未涉及 harness vs commitment 域的并列。
- **DESIGN-010** 2 个 marker domain 字符串无 Rust 常量锚定 — 合并审计未涉及 kaspa-devnet driver 写出的 marker domain。
- **DESIGN-012** 3 evidence JSON 的 status 字段无层级标签 — 合并审计未涉及此 evidence schema 问题。
- **DESIGN-014** `KURRENT_FACTORY_COMMITMENT_DESIGN.md` 已存在但 thesis 仍写 "future ... slice" — 合并审计未讨论 factory note 与 thesis 之间的语义错位。
- **DESIGN-018** SECURITY_ASSUMPTIONS.md 全文 0 thesis 引用 — 合并审计未涉及此双向 cross-link 缺失。

### 12.3 与 sibling audit 的分工

- **`docs/audit-security-2026-06-28.md`**(我的 sibling 任务,内部安全审计)— 攻击面 / threat model / fund-safety 论断 / 争议解决边界。**本审计不覆盖攻击面**(任务范围已明确声明),不与其 finding 重叠。
- 本审计与 sibling 共享的边界:`evidence/kurrent-acceptance.json`、evidence JSON 的 status 字段、thesis 的 prose 措辞。但 sibling 关心"威胁是否被命名",本审计关心"reader 能否清楚分辨 prototype vs normative"。

---

## 13. 自我审查 checklist

> 本节用于验证本审计自身不犯"我审的错"。

- [x] **不写 v1/v2/rev N / "earlier draft" / "after audit we corrected Y"** — 本报告全文 0 处版本化叙述,所有 finding 引用 `file:line` 级别。
- [x] **不混说 architecture fit vs production evidence** — 每条 finding 显式标注 in-scope 是 harness 域 / commitment 域 / evidence JSON / runbook / thesis prose;DESIGN-011 显式区分 synthetic vs live evidence 流;DESIGN-012 显式区分 3 个 evidence JSON 的 status 字段。
- [x] **不模糊 research note vs protocol specification 边界** — §4 DESIGN-003/004 显式标注 thesis §3-§7 prose 是 normative spec 形式但未实现,invoice note 自我定位清晰;本审计自身 §1 标 "research boundary, internal review"。
- [x] **内部矛盾显式挑出 file:line,不 hedge** — DESIGN-013 (3 文档 3 措辞)、DESIGN-014 (note 存在 vs thesis 写 "future")、DESIGN-015 (finality 3 措辞) 各给 3 个 `file:line` 证据点。
- [x] **引用必须 file:line 级别** — 18 条 finding 全部给出 ≥2 个 `file:line` 证据点;`rg -n` 验证 0 处空泛"见 thesis"或"见 code"叙述。
- [x] **本报告 prose 不犯我审的错** — 自身命名一致:全部 finding 用 `DESIGN-NNN` ID 编号(P0/P1/P2/P3 严重度自一致);自身不混说"audit-rigor 严密度"或"attack surface"(那是 sibling audit 范围);自身 §1 状态行与 §2.4 探针覆盖矩阵描述一致(P0=0, P1=8, P2=10, P3=0, total=18)。
- [x] **8 探针全部 covered** — §2.4 探针覆盖矩阵 8 行全 filled,无"N/A"。
- [x] **每探针 ≥1 条 finding** — 18/8 探针 = 2.25 条平均,最少的 probe 4 也有 2 条(DESIGN-007/008)。
- [x] **prior audit 关系显式说明** — §12 显式区分 51 aggregate finding(已声明 out-of-scope)、9 resolved finding(本审计确认仍 resolved)、4 P0/P1 blocker(本审计通过 DESIGN-016/017 反映部分)、独有 8 条 finding(本审计独立产出)、sibling audit-security(分工)。
- [x] **跨探针综合按根因合并** — §11 显式按 5 个根因(A 命名域、B 假设 cross-link、C blocker 表达、D 边界声明、E external anchor)把 18 条 finding 去重,避免 probe-tag 重复计数。

---

## 附录 A: 18 条 finding 索引

| ID | 探针 | 严重度 | file:line 锚点 | 标题 |
| --- | --- | --- | --- | --- |
| DESIGN-001 | 1 | P1 | `src/lib.rs:353-831` vs `:2704-2816`; `tests/protocol_model.rs:66-1903` vs `tests/normative_construction.rs:313-547` | `channel_id` 与 `scope_id` 同一角色,无 derivation 桥 |
| DESIGN-002 | 1 | P2 | `src/lib.rs:192-202` vs `:2285-2290` | `KURRENT_*_V1` 与 `KurrentXxx/v1` 两域在同一文件并列存在 |
| DESIGN-003 | 2 | P1 | THESIS:143, 368-533, 650-689 | Thesis §3-§7 写 "normative spec" 形式但 §1+§13 是唯一"未实现"边界 |
| DESIGN-004 | 2 | P2 | `KURRENT_INVOICE_DESIGN_RESEARCH.md:3-12`; README:227-234 | Invoice note 自我定位清晰但 README Repository Map 不分层 |
| DESIGN-005 | 3 | P1 | THESIS:571-578; `KURRENT_SECURITY_ASSUMPTIONS.md:18-22`; README:51-59 | SECURITY_ASSUMPTIONS.md 不引用 thesis 概率下界 |
| DESIGN-006 | 3 | P2 | `PRODUCTION_*.md:3, 5-7`; README:178-180 | PRODUCTION_*.md 头 "Status: passed" 与 README disclaimer 双层信号 |
| DESIGN-007 | 4 | P2 | THESIS:121-135; `PRODUCTION_*.md`(全文 0 snapshot 引用) | KIP reference snapshot 在 thesis 显式,4 runbook 不引用 |
| DESIGN-008 | 4 | P2 | THESIS:209, 622; `src/lib.rs:200, 1189`; `KURRENT_SECURITY_ASSUMPTIONS.md:21-22` | SECURITY_ASSUMPTIONS.md 假设"watchtower" 不命名 KIP-21 substrate |
| DESIGN-009 | 5 | P1 | `src/lib.rs:192-202, 2285-2290`; `evidence/*.json`(0 commitment 域); `tests/normative_construction.rs:66-81, 758`(0 evidence JSON) | 两域 digest 在 evidence JSON 中并列出现 |
| DESIGN-010 | 5 | P2 | `evidence/kurrent-live-*.json:19,53,87,345,390`; `drivers/kaspa-devnet/src/main.rs:2940, 2959, 5121` | 2 个 marker domain 字符串无 Rust 常量锚定 |
| DESIGN-011 | 6 | P1 | `evidence/kurrent-state-channel-headers.json:8,29,50`; `evidence/kurrent-live-state-channel-evidence.json:210-211`; `evidence/production/target-profile.json:52-61` | 4 个合成 evidence JSON 与 live 实证是两条 evidence 流 |
| DESIGN-012 | 6 | P2 | `evidence/kurrent-acceptance.json`; `evidence/production/target-profile.json:75`; `evidence/kurrent-production-readiness.json:4` | 3 evidence JSON 的 status 字段无层级标签 |
| DESIGN-013 | 7 | P1 | THESIS:571-578; `KURRENT_SECURITY_ASSUMPTIONS.md:21-22`; README:51-59 | Response-window 概率下界在 3 文档 3 形式陈述,无 cross-link |
| DESIGN-014 | 7 | P2 | `KURRENT_FACTORY_COMMITMENT_DESIGN.md:1-72`; THESIS:626, 630 | Factory design note 已存在但 thesis §"Future Work" 写 "future ... slice" |
| DESIGN-015 | 7 | P2 | THESIS:546; `KURRENT_SECURITY_ASSUMPTIONS.md:18-20`; README:51-59 | Finality policy 3 种 prose 措辞,无 cross-link |
| DESIGN-016 | 8 | P1 | `PRODUCTION_*.md:3`; `evidence/kurrent-production-readiness.json:4, 56-58` | runbook 头 "passed" 与 production-readiness "failed/blocked" 双层信号 |
| DESIGN-017 | 8 | P1 | `AUDIT_CONSOLIDATED_2026-06-27.md:55-85`; `evidence/kurrent-production-readiness.json:56-58` | production-readiness blockers 比合并审计 4 P0/P1 窄 3 条 |
| DESIGN-018 | 8 | P2 | `KURRENT_SECURITY_ASSUMPTIONS.md:1-44`; THESIS:571-578 | SECURITY_ASSUMPTIONS.md 全文 0 thesis 引用,thesis 也 0 SECURITY_ASSUMPTIONS 引用 |

---

(End of audit-design-2026-06-28.md)
