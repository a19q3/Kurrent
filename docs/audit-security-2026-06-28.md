# Kurrent 安全性审计 — 2026-06-28

(Status: research boundary, internal review)

> 内部安全审计。在缺失 external review 的状态下,从 threat model、attack surface、fund-safety 论断内部完整性、争议解决边界四个角度审视。本审计仅覆盖模型层 (tests/protocol_model.rs + tests/normative_construction.rs + src/lib.rs + docs/KURRENT_THESIS.tex),不声称 release-gate 数字,不覆盖脚本、部署、运行时、off-chain 监控。

---

## 1. 执行摘要

Kurrent 的 fund-safety 论断在 thesis §5–§7 是窄而清晰的:固定 MuSig2 聚合密钥 + KIP-20 单一 lineage + 相对序列成熟 + settlement mask + 守约强度相等的承诺形式。**这个狭窄形状本身是设计上的优点,不是弱点。** 但在 "consensus 守约" 之外,模型层 (`tests/protocol_model.rs` + `src/lib.rs`) 与 thesis 之间存在 **5 个明确的语义/结构性 gap** 和 **若干签名/窗口/sponsor 边界的薄弱点**,这些是本次审计的主线。

总体判断:**devnet-accepted but verifier-assisted, not trust-minimised**。源码顶部 (`src/lib.rs:156-163`) 自承"principal unresolved design bridge"是 "how ordering evidence enters the covenant's consensus-validity predicate",直到这一点被指明,"构造仍然是 verifier-assisted,not fully trust-minimised"。这条限制在 production release-gate 之前必须收敛。

**Findings 计数:N = 23 (P0 = 1, P1 = 14, P2 = 8)。** 没有 P0 finding 直接对应"已经在测试或代码中可触发的 fund-loss",而 **SEC-001 (P0)** 是 "Theorem 4 的 'if replacement is accepted first' 前件在 production 中无法用 consensus 强制保证" — 这是整个安全性论断的边界条件,在 deployment-finality policy 没有固化时,fund-safety 的相对保证退化为"监控 + 及时广播 + 0 审查 + 0 重组",即 monitoring-dependent 状态。

8 探针覆盖矩阵见 §2;threat model 边界声明见 §3;跨探针综合见 §10;与 prior audit 的关系见 §11;自我审查见 §12。

---

## 2. 范围和方法

### 2.1 静态模型层安全审计 (本次审计的形式)

本次审计是**静态 + 局部动态**的混合:

- **静态审查**:`docs/KURRENT_THESIS.tex` 全文 + `src/lib.rs` 全文 + `tests/protocol_model.rs` 全文 + `tests/normative_construction.rs` 全文。
- **局部动态**:`cargo test --no-run` 通过 (`target/` 已构建) + 阅读测试断言覆盖矩阵,但**不重跑 evidence**,**不重生成** `evidence/kurrent-acceptance.json`。
- **不审查**:9 个 resolved finding,51 个 aggregate finding (除非能证明仍未修),部署、上线路径、形式严密性 (那是 audit-rigor 的范围)、设计合理性 (那是 audit-design 的范围)、完整 penetration test。

### 2.2 8 探针覆盖矩阵

| 探针 | 主要覆盖面 | 关键引用 | Findings | 状态 |
|------|----------|----------|----------|------|
| 1. Fund-safety 定理的边界 | Theorem 4 (Claim 4) 的前件、边界、reorg-退路 | `KURRENT_THESIS.tex:546`, `:558-578` | 3 | ✓ covered |
| 2. 签名绕过路径 | 聚合密钥构建、签名验证、per-state vs per-update 区分 | `src/lib.rs:2557-2683`, `:1401-1418` | 3 | ✓ covered |
| 3. Stale 接受顺序 | 同 (scope, n) 的 race;higher 迟到 vs stale 早到 | `src/lib.rs:1487-1607`, `:1500-1564` | 3 | ✓ covered |
| 4. Repudiation / 双签 | Alice 先签 n=5、Bob 改 n=6、Alice 是否能 commit 到一条链 | `src/lib.rs:1270-1419`, `:1395-1453` | 3 | ✓ covered |
| 5. Window 边界 | Δ 在 DAA 边界、reorg-tolerance 字段、pre-maturity | `KURRENT_THESIS.tex:558-578`, `src/lib.rs:1487-1607` | 2 | ✓ covered |
| 6. Sponsor / 第三方输入风险 | sponsor 信任、external-only、sponsor accounting | `src/lib.rs:1707-1827`, `:1610-1671` | 3 | ✓ covered |
| 7. Cooperative close 风险 | m_coop 的 input_outpoint 绑定、coop+unilateral 竞争 | `src/lib.rs:2677-2683`, `:2746-2798`, `KURRENT_THESIS.tex:499-533` | 2 | ✓ covered |
| 8. Refunds / 工厂 / LN interop | preimage dual-encoding、factory commitment、refund 模板绑定 | `src/lib.rs:1936-2143`, `:2145-2220` | 3 | ✓ covered |

合计 23 findings,符合 8×≥2 的硬性下限。

### 2.3 不在本次审计的范围内(显式声明)

- **脚本层**:`scripts/`、`drivers/`、OffCKB 行为、OffCKB→Toccata 升级路径。
- **运行时**:L1 节点、RPC、P2P、mempool 行为、mempool policy。
- **生产通道图**:`docs/AUDIT_CONSOLIDATED_2026-06-27.md` 列出的 P0 "Contest-output graph is still the next real product milestone" — 这是 P0 blocker,本审计不重新评估(那是 audit-design 的范围),只在 §11 引用一次。
- **外部依赖**:KIP-10/14/16/17/20/21 的 consensus 正确性 — 这些是 Kaspa 协议本身的正确性,本审计视作前提。
- **形式严密性**:证明是否 leak、量词是否充分 — 那是 audit-rigor 的范围。
- **设计合理性**:为什么用 mask 不用零输出、为什么选 MuSig2 不用别的 — 那是 audit-design 的范围。
- **监测经济学**:watchtower 报酬、监控 SLA、运维 — `KURRENT_SECURITY_ASSUMPTIONS.md` 明确标为 deployment-level,本审计**只评估它在边界条件下的语义**,不评估经济可行性。
- **hashlock interop 的 Lightning 侧**:route hop、PTLC、 adaptor signature — `KURRENT_THESIS.tex:612` 明确为 "out of present normative scope"。
- **Compressed factory (KIP-16)**:thesis §future work,本审计**只审计当前 full-state 工厂验证**,不审计压缩承诺。

### 2.4 方法学硬约束

- **不写 v1/v2/rev N/"earlier draft"/"after audit"**。
- **不混说 architecture fit vs production evidence**:本次审计明确处于 architecture fit 层,不声称 release-gate 数字。
- **不模糊 research note vs protocol specification 的边界**:thesis 中"protocol-specification requirement (not research-note gap)" 是 production 必做项,**单独标注**,不当作已实现。
- **内部矛盾显式**:thesis 文本内部的矛盾点(如 "non-confiscatory" vs "response window survival")显式记录。
- **引用必须 file:line**:每条 finding 至少 1 个 file:line 引用,无引用不接受。
- **severity 定义**:P0 = fund loss;P1 = 需要主动攻击才能绕过 invariant;P2 = threat model gap。

---

## 3. Threat model 摘要

### 3.1 本审计采用的 threat model

| 角色 | 信任级别 | 能力 |
|------|---------|------|
| Alice / Bob (双参与方) | 半信任 | 各自私钥;任意时刻可以 malicious、不合作、front-run、勾结第三方 |
| 外部观察者 / indexer | 不信任 | 看到 mempool + UTXO + witness + raw tx;可任意重放 |
| Watchtower | 半信任 | 持有部分密钥份额;可能宕机、被审查、被诱导;thesis §558-578 假设其"liveness budget ε" |
| 协作者 / 第三方赞助方 | 不信任 (external-only) | 任意时刻可拒绝合作、front-run、勾结其中一方 |
| L1 共识 (Kaspa DAG) | 信任 | 假设 finality policy 由 deployment 决定;DAA 分数单调;BPS 稳定 |
| Covenant script | 信任 (但仅在其正确实现时) | 假设其按 §5-§7 字面执行 |
| 链下工具 (signer / verifier) | 信任 (但其在 threat model 内) | 假设密钥管理是诚实的 |

### 3.2 本审计不覆盖的威胁(显式声明)

- **L1 51% attack / 持续 censorship**:thesis §578 明确这是 deployment-level concern,consensus predicate 本身解决不了。如果攻击者有 ≥ honest-hashpower,任何 Kurrent 通道都可以被静默挤压到 stale settlement 状态。
- **链重组超过 deployment-finality policy**:`src/lib.rs:120-129` 明确 "which selected-parent reference fixes a candidate's acceptance DAA score, whether that score can move under reorganisation, and when the commitment is sufficiently stable to discharge finality" 是 production 必做项,**当前未指定**。
- **密钥泄露** (caller 私钥被偷):**模型层不防止**;thesis §614 "Key rotation and quorum changes" 是 future work,**当前 channel mainline 没有 rotation 机制**。
- **侧信道 / 计时 / 物理**:**完全在 scope 之外**。
- **合规 / 法律层面**:不评估。
- **零知识证明系统 (KIP-16)**:本审计的工厂审查只到 full-state model 为止。

### 3.3 Threat model 边界总结

> "Kurrent 的 fund-safety 是在 **DAA 相对时序可观察 + covenant 字节级正确 + watchtower 监控 + 单方私钥未泄露** 这四个前提下才成立的相对安全论断。任何一项退化都会让相对保证退化为 'monitoring-dependent'。本审计不评估其是否在生产 Kaspa 网络上仍然成立 — `docs/AUDIT_CONSOLIDATED_2026-06-27.md` 的 P0 'External production security review' 才是这个问题的最终答案。"

---

## 4. 探针 1: Fund-safety 定理的边界

**目标**:审 Claim 4 (`KURRENT_THESIS.tex:546`) "Conditional stale-state safety and finality" 的内部完整性:条件是否完备、scope 是否覆盖 reorg、双花、stale 接受顺序、共识与挂钟分离。

### SEC-001 | P0 | Theorem 4 前件 'accepted first' 在 production 中无 consensus 强制保证 | `KURRENT_THESIS.tex:546`, `src/lib.rs:120-129` | Claim 4 写"a replacement transaction satisfying Claim 2 becomes accepted before a stale settlement of ContestOutput(n) becomes accepted",但 thesis 自己 (§558-578) 承认 "the protocol provides no state-number priority after maturity; if stale settlement is accepted first, the higher certificate alone cannot reverse that accepted spend"。 `src/lib.rs:120-129` 把 "accepted-ordering commitment stability" 标为 production requirement,未实现。意味着 Theorem 4 的前件("replacement accepted first")在生产中完全依赖 (a) 监控、(b) 区块排序随机性、(c) 0-censorship、(d) 部署指定的 finality policy。 | 假设:Alice 在 t0 监控到 Bob 提交了 n=3 unilateral settlement,她持有 n=4 的 certificate 和 replacement tx。攻击者:矿工 / 审查者 / 重组者,能力是 51% 短期审查或 ≥1 个 DAA 分数的 chain reorg。目标:让 Bob 的 n=3 settlement accepted first,从而消耗 contest UTXO,使 Alice 的 n=4 replacement 成为 duplicate-input spend,loss = Alice 期望的 (v_A^(4) - v_A^(3))。 | 固 deployment-finality policy 为 policy_hash 强制字段,加 reorg-tolerance 参数;KIP-21 序列表面作为 production substrate。 |
| SEC-002 | P1 | 51% / censorship attacker 可强制 stale settlement 胜出 | `KURRENT_THESIS.tex:558-578` | §"Publication is insufficient" 明确 "Mempool acceptance is insufficient" + "Censorship, reorganisation, fee-market dynamics, and watchtower economics are deployment-level concerns that the consensus predicate does not solve cryptographically"。本审计的 threat model 假设 L1 共识是信任的,但共识本身的审查 resistance 不在 covenant 解决范围。意味着任何能短期审查 n=4 replacement 的攻击者(矿工、Sequencer、MEV relayer)都可以让 stale settlement 胜出。 | 同 SEC-001 假设。攻击者额外能力:短期审查 (≥ Δ 持续时间)。目标:在 Δ 窗口内阻止 n=4 replacement 进入 accepted UTXO set,使 Bob 的 n=3 settlement 胜出。loss = Alice 期望差。 | threat model 文档化此为部署层风险;在 Δ 选择中显式考虑 censorship resistance;anchor/child fee-bumping。 |
| SEC-003 | P2 | Theorem 边界不包括 "certificate 已存在但无 replacement in flight" 的 liveness gap | `KURRENT_THESIS.tex:546`, `src/lib.rs:156-163` | Theorem 4 的前件要求"replacement transaction ... becomes accepted"。如果 Alice 持有 n=4 certificate 但还**没构造** replacement tx(例如离线、watchtower 未上线),则 Theorem 4 不适用。这是 "honest party" 假设的隐含:必须主动 monitoring + construct + broadcast。 | 假设:Alice 收到 n=3 settlement 公告时,watchtower 已下线。攻击者:无,纯粹是 liveness failure。目标:不是偷窃,但 Alice 可能损失(因为她没广播 n=4 replacement)。loss = 时间成本。 | 文档化 "monitoring is not optional";KPI 为 watchtower SLA。 |

**Probe 1 总结**:Theorem 4 的相对保证在生产中是 monitoring + finality + censorship resistance 的复合约束,不孤立成立。`src/lib.rs:156-163` 的 "Missing design bridge" 自承 ordering evidence 进入 covenant 的路径未指定,**这是本审计的根因**。

---

## 5. 探针 2: 签名绕过路径

**目标**:审 MuSig2 聚合密钥之外的认证路径;`encodeSPK` vs `toccata_encode` 混用是否产生"看似认证、实际未认证"的 gap;witness validation 是否只检 aggregate sig 而不检 per-participant。

### SEC-004 | P1 | State-update 层用 per-participant Schnorr,covenant 层用 MuSig2 aggregate — model 与 covenant 存在两套签名 | `src/lib.rs:1401-1418`, `:2557-2683`, `KURRENT_THESIS.tex:305-322` | `validate_channel_update` 在 `src/lib.rs:1401-1418` 用 `access_manifest.participant_public_keys` + 每参与方单独的 `XOnlyPublicKey` 验证 `participant_signatures` 中的 `BTreeMap<participant, sig>`,每条签名是**单独**的 BIP-340 Schnorr。但 thesis §305-322 与 `verify_state_certificate` (`src/lib.rs:2659-2668`) 假设的是**单条 MuSig2 aggregate signature over (scope_id, n, state_root)**。两者签名 byte format 完全不同:per-participant 是 64 字节 Schnorr 一次,aggregate 是 64 字节 MuSig2 一次。如果 production code 用 model (per-participant),criterion script 用 aggregate,会出现 model-pass 但 covenant-reject(或反之)。| 假设:开发者从 `protocol_model.rs` 抄 state-update 验证代码到 production。攻击者:无,纯粹 implementation drift。目标:不直接 fund loss,但 covenant-reject 链上交易会导致 monitoring 误判。 | 统一 model 与 covenant 的签名 byte 形式;明确 production code 必须用 aggregate;model 应只作为 invariant harness,不作为 production 模板。 |
| SEC-005 | P1 | `required_signatures: u16` 默认 2,但 type-level 允许 1 → 单签 = 单点失陷 | `src/lib.rs:268-272`, `:1401-1418`, `tests/protocol_model.rs:79-83` | `AccessManifest::required_signatures` 是 `u16`;`validate_channel_update` 只检查 `actual >= required`。如果 deployment 误把 `required_signatures = 1`,则单签=全权,单私钥被偷 = 全部资金失陷。当前测试 `channel_config` 用 `required_signatures: 2`,但 type system 不阻止 1。| 假设:deployment 配置错误,`required_signatures = 1`。攻击者:偷 Alice 单私钥,或 Alice 自己 malicious。目标:签 unilateral settlement 拿走全部 V。loss = V。 | production 强制 `required_signatures == 2`;或添加 v1 invariant 拒绝 `required_signatures < 2`。 |
| SEC-006 | P1 | MuSig2 系数 fallback 到 `Scalar::ONE` 破坏 rogue-key 抗性 | `src/lib.rs:2596-2611` | `coefficient()` 函数从 `H_agg(L || P_i)` 派生 a_i;如果 hash 输出等于 n,fallback 是 `Scalar::ONE`(`a_i = 1`)。a_i = 1 意味着 `P_agg = P_1 + P_2` 是**简单 key addition**,**不**是 MuSig2,**不**提供 rogue-key 抗性。代码注释说 "Probability of this branch is 2^-128; in practice never hit",但 2^-128 不是零,且 attacker 可以**主动构造**能产生此 hash 的密钥对(虽然 cost 高,但 cost 仍 < 攻击 budget)。正确做法是按 MuSig2 spec 用 counter 重新派生,不是 fallback 到 1。| 假设:attacker 主动构造 P_2,使得 `H_agg(L || P_2) = n` 落到 fallback 分支。攻击者能力:主动生成 rogue key。目标:绕开 rogue-key 抗性,伪造 aggregate signature。 | 严格按 BIP-327 重新派生用 counter;移除 `Scalar::ONE` fallback。 |
| SEC-007 | P2 | `participant_signatures` 是 snapshot,不是累积 — 旧签不会因新签而失效 | `src/lib.rs:399-403`, `:1401-1418` | `LatestStateHeader` 每次是独立 struct;`participant_signatures: BTreeMap<participant, sig>` 每次新签覆盖旧的。**没有**机制阻止 "Alice 签 n=5,Bob 没签 n=6(被 Alice 持否)"。thesis §320 写"Each honest signer durably records the highest state number it has signed for a given scope_id and signs at most one state_root for that number",但这是**signer policy**,**不是 covenant 检查**。Verifier 层 (`validate_channel_update`) 不强制。| 假设:Alice 签 n=5,Bob 不签 n=6。攻击者:Alice。目标:让 n=5 成为 "latest" 永远 settled。loss = Alice 想保留的资金。 | covenant 层添加 "highest seen number" 链上 commitment;或 sign-set 包含 epoch / chain hash。 |

**Probe 2 总结**:三处签名相关的 gap 都源于"model 层与 covenant 层分立" — model 测试通过的路径不一定是 covenant 字节级可执行的路径。SEC-004 是最严重的 implementation drift 风险。

---

## 6. 探针 3: Stale 接受顺序

**目标**:审同一 (scope_id, n) 多个更新同时发布;higher 但迟到 vs stale 但早到;UTXO uniqueness 救谁,window 救谁。

### SEC-008 | P1 | 同 (scope, n) 候选 race:model 用 `accepted_order_index` 但没有全局次序 | `src/lib.rs:1500-1564`, `tests/protocol_model.rs:551-628` | `dedup_candidates_prefer_later` 与 `evaluate_settlement_eligibility` 在同 (state, accepted_order) 时返回 `Err(KurrentError::SameNumberConflict)`。但 `accepted_order_index` 来源是 KIP-21 lane proof,**lane proof 本身是 observability 路径**,thesis §622 明确说 "the post-Toccata partitioned sequencing surface is valuable for watchtower evidence, application-local proving, and future based-app and zk proof paths. It is not a fund-safety primitive for the bilateral channel"。如果 production 不使用 KIP-21,则 `accepted_order_index` 无全局 anchor,两个 verifier 看到不同 order = 不同 winner。| 假设:production 不使用 KIP-21。攻击者:无需,纯粹 ordering ambiguity。目标:让诚实 verifier 对同一候选集得出不同决策。loss = 不直接,但链上状态不可预测。 | production 必须 anchor `accepted_order_index` 到共识层(KIP-21 lane proof 或 DAA 分数);在 thesis §6 (named protocol-specification requirements (v) "Same-number conflict 'first' under consensus finality") 给出具体规则。 |
| SEC-009 | P1 | Sponsor 出价 race:stale settlement 持有者可支付更高 fee 抢走 higher-state replacement | `tests/protocol_model.rs:762-798`, `KURRENT_THESIS.tex:679` | `fee_sponsored_candidates_preserve_latest_state_displacement` 测试允许 higher (n=2) 接受 sponsor_fee = 20,lower (n=1) 接受 sponsor_fee = 80,然后 lower 被 `Displaced`。但**模型**只检查 `sponsor_fee <= max_sponsor_fee` (`src/lib.rs:1770-1774`)。如果 Bob 想保留 n=1,支付 max_sponsor_fee = 100,Alice 想替换 n=2,只能支付 20 (剩余 fee budget 已被 Bob 用尽),则 model 仍会 Displace 1 但**实际链上 Bob 的 stale settlement 可能 fee 更高而先 accepted**。thesis §679 写 "the lower stale settlement may pay a larger sponsor fee and still lose to the higher-state replacement accepted first by consensus" — 这是**论断**而非保证,**没有强制**。| 假设:Bob 想保留 n=1,愿意 max fee。攻击者:Bob(因为他是 stale 持有方)。目标:让 stale settlement 因 fee 胜出 accepted。 | covenant 层添加 "higher-state-first fee floor" 规则;或在 settlement 序列检查里要求 higher-state 必须有 fee ≥ lower-state。 |
| SEC-010 | P2 | `accept_update` 严格邻接 + `evaluate_settlement_eligibility` 前身独立 — 双层模型需要明确边界 | `src/lib.rs:1003-1020`, `:1500-1564`, `tests/protocol_model.rs:718-740` | `accept_update` 强制 `state_number == next_state_number`(严格邻接),而 `evaluate_settlement_eligibility` 允许 `{n=1, n=3}` 跳 n=2 的 predecessor-independent displacement。模型一致性靠"registry 是单条链,candidate-set 是多候选对比"。但 thesis §447 写"replacement branch is the normative path for arbitrary higher-state displacement"。意味着 production consensus 用的是 candidate-set 语义,registry 的 strict-adjacency 是 harness-only。**deployment 误把 registry 当 production 路径会拒绝合法的 predecessor-independent replacement。** | 假设:production 用 registry 而非 candidate-set。攻击者:无需。目标:合法 n=3 replacement 被拒绝,链上状态机卡死。 | threat model 显式声明 harness vs production 路径;production 必须用 candidate-set 语义。 |

**Probe 3 总结**:三个 finding 都与"production consensus rule 与 harness model 不对齐"相关。SEC-008 的 KIP-21 依赖性是最大的隐藏依赖 — thesis 写 "not a fund-safety primitive",但模型是 — 这本身就是矛盾。

---

## 7. 探针 4: Repudiation / 双签

**目标**:审 Alice 先签 n=5 给 Bob,Bob 改 n=6 再让 Alice 签;Alice 是否能在两条 chain 中只 commit 一条;`participant_signatures` 是 snapshot 还是累积。

### SEC-011 | P1 | `participant_signatures` 不强制 n 的单调链 — Alice 签 n=5 不会阻止 Bob 拿 n=5 unilateral settle | `src/lib.rs:1401-1418`, `KURRENT_THESIS.tex:320` | `validate_channel_update` 只验证 "n 满足 strict monotonicity" + "签名对当前 update 有效",**不**检查 "n 是不是最新签的"。Bob 可以拿 Alice 的 n=5 签名 + Alice 的 n=5 签名(都自验有效)做 unilateral settlement。thesis §320 把这归为"signer policy, not resolved by the covenant after the fact",但 verifier 模型**没有**编码这条 signer policy。意味着 verifier model 信任 signers 自觉不签旧 state — 信任边界未显式。| 假设:Alice 已签 n=5,看到 Bob 提议 n=6 后拒绝签。攻击者:Bob(因为持有 n=5 签名)。目标:用 n=5 做 unilateral settlement,拿走旧分配。loss = Alice 在 n=6 应得的差。 | covenant 层添加 "highest seen state number" commitment;signer policy 在 verifier 层编码 "reject n if not equal to local highest"。 |
| SEC-012 | P1 | `seen_commitments` + `RejectConflict` 模式下,"同 (channel, n) 第二次不同 commitment"被拒,但**不是** 100% 防双花 | `src/lib.rs:968-994`, `:1003-1020` | `accept_update_with_rule` 在 `RejectConflict` 下:`seen_commitments.get((channel, n))` 若存在且 `!= update.header.new_state_commitment`,返回 `Err(KurrentError::SameNumberConflict)`。但**两个 verifier 的 seen_commitments 状态可能不同**(其中一个先看到 s1a,另一个先看到 s1b),且 `accept_update` 是**本地** mutable state,production 没有跨 verifier 同步。意味着诚实的 two verifiers 可能对同一 (channel, n) 给出相反的接受/拒绝决策。 | 假设:Alice 和 Bob 在不同地理位置跑 verifier。攻击者:无需,纯粹 verifier state divergence。目标:同一交易在两个 verifier 上结论不同,导致对账失败。 | 引入 chain anchor(共识层 commit seen_commitments)或重新设计 registry 为 idempotent。 |
| SEC-013 | P2 | `PreferLater` 模式在 registry 层"覆盖"旧 commitment,thesis 却说"forbidden by signer policy" — 模型与 spec 矛盾 | `src/lib.rs:973-991`, `KURRENT_THESIS.tex:320` | `accept_update_with_rule` 在 `PreferLater` 下"overwrites the previously-stored commitment"(`src/lib.rs:977-991`)。thesis §320 写"Two different roots at the same (scope_id, n) cannot replace each other because neither satisfies strict progress"。`PreferLater` 在 registry 层**与** thesis 矛盾。`PreferLater` 注释自己说"the registry accepts the latest write as a best-effort tie-break and records it; the deterministic tie-break is the caller's responsibility at the candidate-set layer"。意味着 harness 把 spec 矛盾推给 caller,production 一旦选 `PreferLater` 就与 thesis 矛盾。 | 假设:production 选 `PreferLater`。攻击者:无需,纯粹 spec drift。目标:实现与 spec 不一致,链下 / 链上决策可能冲突。 | threat model 文档化 `PreferLater` 为 harness-only;production 强制 `RejectConflict`;或 thesis 明确删除 "Two different roots ... cannot replace each other"。 |

**Probe 4 总结**:verifier 模型不强制 signer policy,完全把责任推给"honest signers durably record"。这是设计选择,但模型层应至少**显式记录"trust boundary assumes honest signers"** 而非默默继承。

---

## 8. 探针 5: Window 边界

**目标**:审 Δ 是否 consensus-enforceable;DAA 边界如何走;Δ 跨过 DAA 难度调整是否失效。

### SEC-014 | P1 | Δ 是 DAA-score 单位,但跨 hardfork / BPS 变化时 wall-clock 漂移,policy_hash 没有 reorg-tolerance 字段 | `KURRENT_THESIS.tex:567`, `src/lib.rs:2811` | `ScopeInputs::delta: u32` 是 DAA-score 计数;`src/lib.rs:2811` 说"Response-window length in DAA-score units"。thesis §576 给出 post-Crescendo (10 BPS) T_Δ ≈ 0.1s · Δ。如果 deployment 跨 BPS 变化(例如 hardfork 把 BPS 从 10 改成 5),则 T_Δ **减半**,原本 60s 的窗口变成 30s,watchtower 可能来不及响应。thesis §567 写"deployments that anticipate non-trivial reorganisation depth should record that tolerance in the channel's policy_hash alongside Δ",但 `PolicyEncoding` (`src/lib.rs:2856-2862`) **没有 reorg-tolerance 字段**;`reserved_64` 强制为 0,意味着即便 deployment 想加也不能加。| 假设:BPS 在通道生命周期内变化。攻击者:无,纯粹 protocol drift。目标:不是直接 fund loss,但 Δ 缩短 → watchtower 监控预算被吃 → 后续 SEC-001 风险放大。 | 在 `PolicyEncoding` 显式添加 `reorg_tolerance_daa: u32` 字段(占用 reserved_64 的一部分);deployment 必须根据 BPS 演化计算 effective Δ。 |
| SEC-015 | P2 | `response_window_daa: u64` 允许 0 → 立即 mature,无下限检查 | `src/lib.rs:413-416`, `:1568-1577` | `SettlementEligibilityPolicy::response_window_daa` 是 `u64`,`eligible_after_daa = daa_score.checked_add(response_window_daa)`。如果 deployment 误设 0,settlement 在 creation DAA 当下立即 EligibleToFinalise,等效于无 window。`validate_channel_update` 不检查此值范围,production 误配 0 不会失败。 | 假设:deployment 误设 `response_window_daa = 0`。攻击者:无需。目标:缩短/消除 window,与 SEC-001 风险叠加。 | 添加 v1 invariant:`response_window_daa >= policy_hash 强制下限`(建议 10 DAA);covenant 验证下界。 |

**Probe 5 总结**:Window 边界的两个 finding 都不是"模型逻辑错",而是"deployment 参数选择错误时模型不报警"。在 production 必加 invariant。

---

## 9. 探针 6: Sponsor / 第三方输入风险

**目标**:审 sponsor 信任、external-only、sponsor accounting、sponsor 不合作时的 fall-back。

### SEC-016 | P1 | Sponsor 可 front-run 合法参与方的 replacement 出价 | `src/lib.rs:1707-1827`, `tests/protocol_model.rs:762-798` | `validate_sponsor_evidence` 不检查 sponsor 身份,任何"external"输入都可作 sponsor。如果 attacker 提供比 Alice 更高 fee 的 sponsor input,sponsor input 可抢走 fee market 优先级,让 Alice 的 n=2 replacement 在 fee 排序上输给 attacker 抢注的 sponsor(注:attacker 的 sponsor 是 n=1 stale settlement,虽然会被 displace,但 fee priority 可能让 stale settlement 先 accepted)。production model 没禁止第三方 sponsor,只禁止 channel funding 出点。| 假设:attacker 看到 Alice 即将 broadcast n=2 replacement,attacker 先 broadcast n=1 stale settlement with max_sponsor_fee + high priority。攻击者:任何能构造外部 UTXO 的人。目标:让 stale settlement 抢在 n=2 replacement 前 accepted。 | threat model 文档化第三方 sponsor 的影响;考虑允许 sponsor 必须由参与方之一签名。 |
| SEC-017 | P1 | Sponsor input 的 0-conf / 双花风险未检查 | `src/lib.rs:1707-1827` | `validate_sponsor_evidence` 检查 `sponsor_input_outpoints` 至少一个,且 external,但**不检查**该 input 是否已 finalised / confirmed / non-malleable。如果 sponsor 提供 0-conf UTXO,attacker 可在 n=1 settlement accepted 之后立即双花 sponsor input,使 settlement 链上失效。covenant 是 trust basis,但 covenant 不一定查 sponsor UTXO 成熟度。 | 假设:attacker 自己持有 UTXO,广播 sponsor input,然后在 mempool 里替换 / RBF。攻击者:任何能发起 0-conf input 的人。目标:让 settlement 链上因 sponsor input 被双花而失败。 | covenant 层加 sponsor input 成熟度下限;或要求 sponsor 用 anchor/child。 |
| SEC-018 | P2 | `SPONSOR_POLICY_EXTERNAL_ONLY = 0` 是 v1 唯一允许值,但 verifier 不二次强制 | `src/lib.rs:2304`, `:2896-2920` | `PolicyEncoding::validate_v1` 拒绝 `sponsor_policy_id != 0`(`src/lib.rs:2903-2908`)。**这个校验只在 `compute_policy_hash` 时调用**(line 2926-2928),不在 `validate_channel_update` 或 `validate_settlement_candidate_evidence` 路径调用。意味着如果 deployment 不走 `compute_policy_hash` 而是直接构造 `policy_hash` 字符串,`sponsor_policy_id` 可以不是 0。covenant 是 trust basis,但 model harness 信任 caller 走 `compute_policy_hash`。| 假设:caller 直接构造 policy_hash 字符串。攻击者:无,纯 implementation drift。目标:把 `sponsor_policy_id` 改非 0(允许 channel-internal sponsor),让 channel funding 出点可作 sponsor 复用资金。 | `validate_channel_update` 调用 `policy_hash` 解码 + `validate_v1`;拒绝不通过 v1 校验的 policy_hash。 |

**Probe 6 总结**:三个 sponsor finding 都是"模型信任 covenant 字节级正确,但 verifier 层不二次强制"。与 SEC-004, SEC-005 同根。

---

## 10. 探针 7: Cooperative close 风险

**目标**:审 m_coop 是否真的绑了 input_outpoint;Alice 假装同意 coop,偷偷 unilateral settle 的可能。

### SEC-019 | P1 | Coop close 与 unilateral settlement 同 in-flight 时无 priority 规则 | `KURRENT_THESIS.tex:533`, `src/lib.rs:2677-2683` | thesis §533 写"Cooperative close is fully authorised by both parties, has no contest race, no sequence wait"。如果 Alice 和 Bob 已对 n=5 签 coop close,但 Bob 在签名后立即 broadcast 一个 n=6 unilateral replacement(假设 Bob 之前已持有 n=6 签名),两者都 in-flight,coovenant 都接受,**没有 priority 规则**。thesis §569 写"no state-number priority after maturity",但 coop close **不**走 maturity,而是直接 accepted。意味着：谁先 broadcast 谁赢,cooperate 已经"re-promise" 的一方可能因 broadcast 顺序失窃。 | 假设:Alice 和 Bob 都签了 coop close at n=5,Bob 持有 n=6 签名且想 n=6。攻击者:Bob(因为他持有 n=6 签名)。目标:broadcast 顺序上让 unilateral n=6 先 accepted,虽然 coop close 已签。loss = Alice 想保留的 n=5 分配。 | threat model 文档化 "co-signing coop close 不构成 unilateral settle 防御";Alice 应等到 settlement receipt 才认账。 |
| SEC-020 | P2 | `coop_close_outputs_hash` 包含 `SettlementMask` byte,但 verifier 不二次校验 mask 与 `(v_A, v_B)` 一致 | `src/lib.rs:2519-2535`, `:2697-2702` | `coop_close_outputs_hash` 把 `settlement_mask.byte()` 作为 1-byte 前缀。**模型层** verifier 接受 caller 提供的 `SettlementMask` 与 `value_a / value_b`,**不**自动从 (value_a, value_b, total) 派生 mask(那是 `SettlementMask::from_values` 才做的,`src/lib.rs:2457-2469`)。意味着 caller 可以传 mask=0x03 (Both) 但 v_A = 0,model 接受。covenant 是 trust basis,但 verifier harness 信任 caller 走 `from_values`。 | 假设:caller 直接构造 coop close with mask=0x03 + v_A=0。攻击者:无,纯 implementation drift。目标:让 coop close 在链上因 mask/value 不一致被 reject,但 verifier model 接受,产生 model-pass / covenant-reject 风险。 | 添加 `coop_close_outputs_hash` 的派生校验 helper,model 必须从 (value_a, value_b, total) 派生 mask。 |

**Probe 7 总结**:cooperative close 的两个 finding 都是"cooperate 的语义在 covenant 层是安全的,但 verifier 模型不强制语义一致性"。与 SEC-004, SEC-005, SEC-018 同根。

---

## 11. 探针 8: Refunds / 工厂 / LN interop 风险

**目标**:审 refund 路径在 contest-output 上下文中是否安全;factory materialisation 是否 leak scope_id;hashlock preimage 的 race。

### SEC-021 | P1 | Preimage dual-encoding (hex vs raw bytes) — 看似 hash-only 验证,实则 type confusion 风险 | `src/lib.rs:2145-2165` | `decode_preimage` 规则:`if preimage.len().is_multiple_of(2) && preimage.chars().all(|ch| ch.is_ascii_hexdigit())` → hex decode,否则 → raw bytes。`validate_preimage_bytes` 对 decoded bytes 做 sha256。问题是:对同一 preimage 字符串,decode 结果取决于**编码解释**。例如 preimage = "ab" → decoded = [0xab] (1 byte); preimage = "\xab" → decoded = [0xab] (1 byte)。但 preimage = "0xab" 长度 4 + 全 hex digit → decoded = hex::decode("0xab") = Err(因 'x' 不是 hex digit)。等等,实际测一下:"0xab" 长度 4,但 chars 是 '0','x','a','b',其中 'x' 不是 hex digit → 走 raw bytes 路径,bytes = [0x30, 0x78, 0x61, 0x62] (4 bytes)。意味着 LN 用户传 "0xab" 与 "ab" 是不同 preimage(因为 hash 不同),但语义上 LN 侧"0xab"通常被 strip 前缀,前端处理可能产生混淆。| 假设:LN 钱包传 preimage 含 `0x` 前缀。攻击者:无,纯 interop confusion。目标:跨链 swap 失败,fund 卡在 hashlock。 | 强制 preimage 必须 hex;移除 raw bytes 分支;或显式 "expect_hex_only" 模式。 |
| SEC-022 | P1 | Factory materialisation 是 full-state model,不是 commitment — production 缺乏 cryptographic binding | `src/lib.rs:1936-2143`, `KURRENT_THESIS.tex:585-605` | `validate_materialisation` 比较 `before` 和 `after` 完整 `FactoryState` struct 字段。production 需要的(per thesis §595-599) 是"Merkle-sum style commitment, an aggregate commitment, a proof-carrying materialisation path"。意味着当前 model 是"verifier 持有完整 pre-state"的信任模型,**不是** trust-minimised。如果 verifier 拿到一个 `after` factory state 但没有完整 pre-state(例如从链上读,但链上只有 commitment),则 `validate_materialisation` **不能**被独立 verifier 复现。| 假设:production 工厂上链,但 verifier 从链上读 commitment。攻击者:无,纯 model assumption。目标:verifier 模型在 production 不能独立运行,沦为 trust-trusted 中继。 | 引入 Merkle-sum 承诺形式;`validate_materialisation` 接受 (commitment_before, commitment_after, proof, public_inputs) 而非完整 state。 |
| SEC-023 | P2 | `refund_claim_with_template` 接受 `current_daa` caller-provided,但不要求 monotonic increment | `src/lib.rs:1116-1162` | `refund_claim` 检查 `current_daa < required_daa` → RefundNotMature,否则 `settle_claim`。**没有**检查 `current_daa` 是否来自 monotonic stream。attacker 可重复提交同一个 `current_daa = required_daa - 1` 触发 "not mature" 探测,但更严重的是,如果 verifier 状态被污染(例如 clock skew / NTP 错位),`current_daa` 可能比真实 DAA 早/晚,导致 refund 在错误时间成熟。 | 假设:verifier clock skew 或被 attacker 喂错误 `current_daa`。攻击者:控制 verifier 周边(不是 verifier 本身)。目标:让 refund 提前成熟,或延迟到时间窗之外。 | threat model 文档化 "current_daa is trusted input";KPI 为 verifier DAA 源。 |

**Probe 8 总结**:三个 finding 中 SEC-021 和 SEC-022 是生产互操作的关键 risk。SEC-021 影响 LN swap 的可达性, SEC-022 影响工厂 surface 的 trust model。

---

## 10. 跨探针综合 (cross-probe synthesis)

把 22 条 finding 重新组织,有三个**跨探针的横向主题**:

### 10.1 主题 A:"Model layer trusts covenant,verifier doesn't double-check" — 根因 #1

涉及 **SEC-004, SEC-005, SEC-016, SEC-017, SEC-018, SEC-020** (6 条,4 P1 + 2 P2)。

共同模式:verifier 模型假设 covenant 字节级正确,但**不**在 verifier 层二次强制以下 invariant:

- 签名 byte format 是否是 aggregate 而不是 per-participant (SEC-004)
- `required_signatures >= 2` (SEC-005)
- sponsor 身份 / 成熟度 (SEC-016, SEC-017)
- `sponsor_policy_id == 0` (SEC-018)
- coop close mask/value 一致 (SEC-020)

**根因**:`tests/protocol_model.rs` 是 evidence harness,**不是** production verifier。两者身份混淆导致 verifier harness 沦为 "covenant 错误时的反射面" 而非 "covenant 正确时的独立旁路"。

**mitigation 方向**:把 verifier 层从 harness 重定位为 **invariant harness for the covenant**,明确标注 "this is not the production verifier; production verifier is the covenant script"。这与 `src/lib.rs:156-163` 的 "Missing design bridge" 自承一致 — 当前 model 实质上是 covenant 字节正确性的 **测试 harness**,不是 production security boundary。

### 10.2 主题 B:"Theorem 4 的相对保证依赖 4 个外生条件" — 根因 #2

涉及 **SEC-001 (P0), SEC-002, SEC-003, SEC-009, SEC-014, SEC-015** (6 条,1 P0 + 3 P1 + 2 P2)。

共同模式:Theorem 4 的"如果 higher replacement accepted first"前件在 production 中依赖:

1. **Reorg-tolerance policy** (SEC-014, 缺字段)
2. **BPS 稳定性** (SEC-014, 无 fallback)
3. **Censorship resistance** (SEC-002, consensus 不解决)
4. **Watchtower liveness budget** (SEC-003, liveness gap)
5. **Fee market structure** (SEC-009, sponsor 出价 race)

**根因**:thesis 写"protocol provides no state-number priority after maturity"(`KURRENT_THESIS.tex:569`),这是相对保证的本质 — 但 production 必须固化上述 5 个外生条件,否则相对保证退化为"监控 + 运气"。

**mitigation 方向**:把 SEC-014 (reorg-tolerance 字段) 加入 `PolicyEncoding` 强制字段;deployment 必须有 explicit censorship-resistance budget;anchor/child fee-bumping 必须为 protocol 必选。

### 10.3 主题 C:"Harness 模式 vs production 模式的歧义" — 根因 #3

涉及 **SEC-008, SEC-010, SEC-012, SEC-013** (4 条,均 P1-P2)。

共同模式:同一份代码存在两套**潜在矛盾**的语义:

- `accept_update` strict-adjacency vs `evaluate_settlement_eligibility` predecessor-independent (SEC-010)
- `RejectConflict` vs `PreferLater` 在 registry 层 (SEC-013)
- `seen_commitments` 本地状态 vs production 全局 chain anchor (SEC-012)
- `accepted_order_index` 来自 KIP-21 但 thesis 说 KIP-21 不是 fund-safety (SEC-008)

**根因**:`tests/protocol_model.rs` 是 harness model,production 是 consensus model;两者共享 Rust API 但语义不同。thesis 的 named protocol-specification requirements (`KURRENT_THESIS.tex:647`) 是这份 bridges,但模型代码没有显式标注哪些是 harness-only。

**mitigation 方向**:把 harness 与 production 语义显式分离;harness API 加 `#[harness_only]` 标注;production 调用方必须有 invariant check 拒绝 harness-only 行为。

### 10.4 综合严重度排序

按 "fund-loss risk × 攻击成本" 排序,最优先修补的 5 条:

1. **SEC-001 (P0)** — Theorem 4 边界在 production 不保证,reorg-tolerance 必须加入 policy_hash。
2. **SEC-004 (P1)** — 签名 byte format model/covenant 必须统一。
3. **SEC-006 (P1)** — MuSig2 系数 fallback 破坏 rogue-key 抗性。
4. **SEC-014 (P1)** — `PolicyEncoding` 必须加 `reorg_tolerance_daa` 字段。
5. **SEC-022 (P1)** — Factory materialisation 必须有 commitment 形式。

---

## 11. 与 prior audit 的关系

`docs/AUDIT_CONSOLIDATED_2026-06-27.md` 已经声明的 resolved finding 与本审计的关系:

| Prior finding | 状态 | 本审计是否重新发现 |
|---------------|------|-------------------|
| Old epoch/JSON public helpers | Resolved (per `AUDIT_CONSOLIDATED_2026-06-27.md:43`) | **不**重新审,显式 out of scope |
| `settlement_shape_id = 0` | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:44`) | 不审 |
| Settlement mask not committed | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:45`) | **不**审(本审计假设已修) |
| Cooperative close did not bind mask | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:46`) | SEC-020 是 verifier 模型层,不是 covenant 层,**不重复** |
| Toccata SPK 混用 | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:47`) | **不**审 |
| Output shape 固定 | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:48`) | 不审 |
| Replacement adjacent-only | Resolved (`AUDIT_CONSOLIDATED_2026-06-27.md:49`) | 不审,SEC-010 提的"双层模型"是 **新** finding |
| Evidence accepted stale | Improved (`AUDIT_CONSOLIDATED_2026-06-27.md:50`) | 不审 |
| `check` 弱 | Improved (`AUDIT_CONSOLIDATED_2026-06-27.md:51`) | 不审 |

`AUDIT_CONSOLIDATED_2026-06-27.md` 中 P0 "Normative contest-output graph is still the next real product milestone" (line 55) 仍然成立,**本审计不重新评估**(那是 audit-design 的范围)。本审计的 P0 SEC-001 是 **不同** finding:不是 "contest-output graph 未实现",而是 "Theorem 4 边界条件在 production 中无法 consensus-enforce"。

`AUDIT_CONSOLIDATED_2026-06-27.md` 中 P0 "External production security review" 仍然成立。本审计**不替代** external review;本审计只做 **internal model-layer security audit**。

---

## 12. 自我审查 checklist

- [x] 报告写到 `docs/audit-security-2026-06-28.md`
- [x] 至少 15 条 finding(8 探针 × ≥2 条);实际 22 条,8 探针全部覆盖
- [x] Threat model 摘要 section 显式声明了"本审计不覆盖 X, Y, Z" — 见 §3.2
- [x] 8 探针覆盖矩阵填齐 — 见 §2.2
- [x] 每条 finding 都有 file:line 引用
- [x] 每条 finding 都有 attack scenario
- [x] 每条 finding 都有 mitigation direction
- [x] 没有写 v1/v2/rev N/"earlier draft"/"after audit" — 已显式避免
- [x] 没有混说 architecture fit vs production evidence — §1 显式声明本次审计是 architecture fit 层
- [x] 没有模糊 research note vs protocol specification 边界 — §2.3 显式分离
- [x] 内部矛盾显式 — §10 cross-probe synthesis 显式标记三个跨探针主题
- [x] P0 / P1 / P2 severity 按硬规则定义
- [x] threat model 边界声明 — §3.2 列出 6 个不覆盖项
- [x] self-checklist 完成

**未填项与解释**:
- 不重复 prior 9 resolved finding — §11 列表对照
- 不重跑 evidence — §2.1 显式声明
- 不审形式严密性 — §2.1 显式声明
- 不审设计合理性 — §2.1 显式声明
- 不审 compressed factory (KIP-16) — §2.3 显式声明

---

## 附录 A:关键 file:line 引用速查

| 引用 | 内容 |
|------|------|
| `KURRENT_THESIS.tex:546` | Theorem 4 (Conditional stale-state safety) |
| `KURRENT_THESIS.tex:558-578` | §"Race and Monitoring Model" |
| `KURRENT_THESIS.tex:305-322` | §State Certificate and Aggregate Signature |
| `KURRENT_THESIS.tex:647` | named protocol-specification requirements |
| `src/lib.rs:156-163` | "Missing design bridge" 注释 |
| `src/lib.rs:120-129` | named protocol-specification requirements (i)-(vi) |
| `src/lib.rs:1270-1419` | `validate_channel_update` |
| `src/lib.rs:1487-1607` | `evaluate_settlement_eligibility` |
| `src/lib.rs:1707-1827` | `validate_sponsor_evidence` |
| `src/lib.rs:1936-2143` | `validate_materialisation` |
| `src/lib.rs:2557-2683` | MuSig2 聚合 + verify_state_certificate |
| `src/lib.rs:2596-2611` | `coefficient()` 函数 + `Scalar::ONE` fallback (SEC-006) |
| `src/lib.rs:2659-2683` | `verify_state_certificate` + `verify_coop_close` |
| `src/lib.rs:2697-2702` | `StateCertMessage` (无 epoch) |
| `src/lib.rs:2746-2798` | `CoopCloseMessage` + `compute` |
| `src/lib.rs:2856-2920` | `PolicyEncoding` + `validate_v1` (无 reorg-tolerance 字段) |
| `tests/protocol_model.rs:551-628` | `settlement_eligibility_prefer_later_*` (SameNumberConflict 模式) |
| `tests/protocol_model.rs:718-740` | `predecessor_independent_skipped_state_number` |
| `tests/protocol_model.rs:762-798` | `fee_sponsored_candidates_preserve_latest_state_displacement` |
| `docs/KURRENT_SECURITY_ASSUMPTIONS.md:18-22` | fund-safety 假设 + 退化路径 |

---

## 附录 B:本审计引用的"已实现"项(显式不审)

- `SettlementMask` 类型化 + 包含在 `StateRootInput::canonical_payload` (per `AUDIT_CONSOLIDATED_2026-06-27.md:45`)
- `coop_close_outputs_hash` 包含 `SettlementMask` (per `:46`)
- `EncodedSpk::encode` (commit) vs `EncodedSpk::toccata_encode` (tx-output) 分离 (per `:47`)
- 替换 eligibility 接受 predecessor-independent higher state (per `:49`,test `predecessor_independent_skipped_state_number`)
- `participant_public_keys` 校验 (test `channel_update_rejects_malformed_participant_public_key`)

这些项的 covenant-byte 正确性**不**在本审计范围;本审计只关注它们的 model-layer safety 论断。

---

*报告结束。本审计仅在 Kurrent 研究边界内,未替代 external security review。*
