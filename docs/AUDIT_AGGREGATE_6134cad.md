# Kurrent Audit — Aggregate Report

**Repo:** `/Users/arthur/RustroverProjects/Kurrent`
**Branch / HEAD:** `main` @ `6134cad` ("Add lightweight Kurrent invoice design note")
**Date:** 2026-06-21
**Scope:** Four parallel audits on the post-invoice-design-note state of the repo.
**Audit-only.** No files modified by this aggregate.

---

## Audit composition

| Worker | Scope | Report location |
| --- | --- | --- |
| 1 | Thesis ↔ prototype ↔ test (the bilateral-fund-safety spec, code, tests) | `scratchpad.md` lines 1–700 (22 findings) |
| 2 | Scripts / runners / devnet flows / evidence package | `scratchpad.md` lines 702–1351 (14 findings) |
| 3 | Invoice design note — internal consistency + cross-doc vs thesis + impl reality | `audit-KURRENT_INVOICE_DESIGN_RESEARCH.md` (21 findings, post-demotion filename) |
| 4 | Invoice design note — integration with the surrounding protocol surface | `/tmp/kurrent-invoice-audit-report.md` (20 findings) |

Workers 1, 2, 3 sent back via `mavis communication send`. Worker 4's synthesis turn
hit the Mavis token-plan rate limit (`minimax Token Plan quota exceeded` — error 42212)
**after** writing a complete 34 KB / 212-line report to `/tmp/kurrent-invoice-audit-report.md`.
The report content is intact on disk; this aggregate incorporates it as if it had
been received normally.

The two invoice audits (3 and 4) overlap on a core set of contradictions between the
invoice note and the thesis/code. They reach the same conclusions through different
lenses — Worker 3 from cross-doc consistency, Worker 4 from integration. Where the two
agree, the finding is upgraded; where they disagree, both readings are kept.

---

## Aggregate verdict

**A clean reproducer on `main @ 6134cad` cannot pass `verify-production-readiness.sh`
from a fresh checkout** — the gate references at least six documents that have never
existed in this repository (`PRODUCTION_KEY_MANAGEMENT.md`, `PRODUCTION_MONITORING.md`,
`PRODUCTION_RECOVERY.md`, `PRODUCTION_ROLLOUT.md`, `KURRENT_SECURITY_ASSUMPTIONS.md`,
`KURRENT_PRODUCTION_ACCEPTANCE.md`, `PRODUCTION_SECURITY_REVIEW.md`). The local-devnet
acceptance path (`scripts/check.sh`) is more reproducible but still passes against
stale evidence because `verify_evidence()` does not enforce a `git_commit` binding.
The thesis↔prototype gap is wide but mostly MAJOR; the invoice note is a research
artefact layered onto a release-pinned spec and is not shippable as-is on this commit;
the verifier gate is the structural failure.

**Counts (deduplicated across workers):**

| Severity | Count | Notes |
| --- | --- | --- |
| BLOCKER | 7 | Cross-doc / gate-reachability / invoice format |
| MAJOR | 21 | Includes duplication between workers 3 and 4 on invoice items |
| MINOR | 14 | |
| NIT | 9 | |
| Total | **51 findings** | |

---

## Cross-audit contradiction table

Both invoice audits (3, 4) flag the same protocol-surface items from different angles.
This is the consolidated picture.

| # | Invoice note claim | Thesis / code reality | Verdict |
| --- | --- | --- | --- |
| I1 | `channel_id` is a 32-byte commitment with an open derivation question (INV:55-57, 102, 263-269) | Thesis uses `scope_id = H_KurrentScope/v1(chain_context ‖ covenant_id ‖ agg_key ‖ le32(Δ) ‖ programme_version ‖ policy_hash)` (THESIS:222-235); `LatestStateHeader.channel_id` is a hex string | **Contradiction.** Naming clash. Use `scope_id`. |
| I2 | `state_number` 8 BE u64 (INV:103, 236) | Thesis and code use `le64(n)` everywhere (THESIS:267, 310-311; LIB:2843, 2956-2961) | **Contradiction.** Change to LE. |
| I3 | `amount_sompi` 8 BE u64 (INV:105, 237) | State root uses `le64(v_A)` / `le64(v_B)` (THESIS:268-269; LIB:2622, 2625) | **Contradiction.** Change to LE. |
| I4 | `recipient_xonly` = per-state-update x-only pubkey distinct from MuSig2 aggregate (INV:67-68, 104-106, 149-154, 270-274) | Authorisation is fixed MuSig2 aggregate `P_agg`; per-state rotation requires `EpochTransitionCertificate` (future work, THESIS §10 line 614) | **Contradiction.** Note invents a key role the covenant cannot bind. Replace with the recipient's MuSig2 contribution pubkey. |
| I5 | Signing message `SHA256("KURRENT_INVOICE_V1" ‖ ...)` (INV:134-140) | Thesis uses **BLAKE2b-256 keyed mode** with `KurrentXxx/v1` ASCII domain tags via `OpBlake2bWithKey` (THESIS:236-246; LIB:2519-2537) | **Contradiction.** Use BLAKE2b-keyed with `KurrentInvoice/v1`. SHA256 stays only for `payment_hash` (LN interop). |
| I6 | `state_number' ≥ state_number` (INV:58-62) | Registry enforces `state_number' == current + 1` (LIB:1024, 1742; TEST:858-877); `state-channel-flow` asserts "state numbers must advance exactly one step" (kurrentctl.rs:2122-2130) | **Contradiction.** Either rename to "registry-layer invariant" and tighten to `+1`, or carve out a parallel consensus-layer rule that the registry also enforces. |
| I7 | `expiry_daa` = DAA blocks after `timestamp`; verification `current_daa < timestamp + expiry_daa` (INV:107, 180-181) | Channel response window is **DAA-relative sequence maturity** against the contest output's creation DAA score (THESIS:139, 318, 471-486, 562-567; LIB:3173-3189) | **Contradiction.** Note mixes absolute- and relative-DAA timing substrates. |
| I8 | `state_root binds payment_hash as a hashlock witness` (INV:196-212) | Thesis reserves hashlock interop as future work (THESIS:610-612, §8.6 item vi); no `payment_hash` field in `LatestStateHeader` (LIB:399-422) | **Speculative claim.** Note presents future-work surface as current capability. |
| I9 | `kikaspa` / `kikaspat` / `kikaspar` / `kikasprt` / `kikaspaidn` HRPs (INV:77-81, 230, 247) | Kaspa's address bech32m uses `kaspa` / `kaspatest` / `kaspasim` / `kaspadev` / `kaspareg` (external Kaspa tooling) | **Contradiction.** `kikaspa*` is not a real HRP. |
| I10 | Domain tag `KURRENT_INVOICE_V1` and `DOMAIN_INVOICE_V1` (INV:67, 134 — internally inconsistent) | Active tags are `KurrentScope/v1`, `KurrentState/v1`, etc. (THESIS:243-244; LIB:2477-2482); `KURRENT_INVOICE_V1` is 18 ASCII bytes, not 16 as the note claims | **Internal contradiction + missing tag.** |
| I11 | `expiry_daa = 0` means "no expiry" (INV:107, 275) | Verification rule `current_daa < timestamp + 0` makes zero mean "expire immediately" (INV:180) | **Internal contradiction.** |
| I12 | `network_profile = "simnet-0.15"` format (INV:68-71, 111, 183) | Deployed harness uses `kaspa-simnet-toccata` (kurrentctl.rs:1956, 1984, 2184, 2205, 2397; every evidence file) | **Value mismatch.** Note's worked example is unverifiable against deployed harness. |
| I13 | `payer_secret` is optional; tracking rule open (INV:106, 184-185, 282-286) | No payer-nonce concept anywhere in the repo; thesis has no equivalent (LIB:790-805 LnSwapEvidence has no payer-side nonce) | **Replay risk.** Without `payer_secret` mandatory and tracked, recipient can re-issue same `(channel_id, payment_hash, state_number)` → payer double-spend. |
| I14 | Single KI can be replayed across multiple state updates because the signing message does not bind a per-invoice `state_root` (INV:196-212) | No KI exists in code today | **Replay risk.** A malicious payer who sees a paid KI can ride it across state n+1, n+2, ... and drain `amount_sompi × (states)` from the recipient. |
| I15 | `LnSwapEvidence` interop (INV:214-225) | Thesis never names `swap_id` or `LnSwapEvidence`; hashlock interop explicitly deferred (THESIS:610-612) | **Speculative claim.** Interop is future work. |
| I16 | `channel_id` derivation committed to `protocol_version, network_profile, funding_outpoint, participant_set_commitment` (INV:264-269) | Thesis commits to `chain_context, covenant_id, agg_key, le32(Δ), programme_version, policy_hash` — covenant-id-anchored, not participant-set-anchored (THESIS:226-235) | **Different commitment.** |
| I17 | `0x0F description` length 1..639 (INV:108) | 639 is the BOLT 11 5-bit-group limit; this is a TLV with 8-bit length prefix | **Terminology collision** with BOLT 11. |
| I18 | "bech32m chosen to avoid BIP-173 length-extension malleability" (INV:92-95) | BIP-173 defect is padding/insertion, not cryptographic length-extension | **Technical description wrong** (conclusion still correct). |

---

## BLOCKER findings (7)

### B1. Production-readiness gate references 7 docs that do not exist on disk or in git history
**(Worker 2, Finding #23)**

- `production_readiness_requirements()` in `src/bin/kurrentctl.rs:944-987` references
  `PRODUCTION_KEY_MANAGEMENT.md`, `PRODUCTION_MONITORING.md`, `PRODUCTION_RECOVERY.md`,
  `PRODUCTION_ROLLOUT.md`, plus `security_review_required_artifact_paths()`
  (`kurrentctl.rs:1038-1073`) which requires `KURRENT_SECURITY_ASSUMPTIONS.md`,
  `KURRENT_PRODUCTION_ACCEPTANCE.md`, `PRODUCTION_SECURITY_REVIEW.md`, `Cargo.lock`,
  `src/lib.rs`, `src/bin/kurrentctl.rs`, `tests/protocol_model.rs`,
  `drivers/kaspa-devnet/Cargo.lock`.
- `docs/` contains only `KURRENT_INVOICE_DESIGN_RESEARCH.md`, `KURRENT_THESIS.pdf`,
  `KURRENT_THESIS.tex`. None of the PRODUCTION_*.md / KURRENT_*_*.md docs exist.
- `git log --all --name-only` confirms none have ever existed.
- **Effect:** a clean reproducer on `main @ 6134cad` fails
  `scripts/verify-production-readiness.sh` on at least six production gates before
  it ever reaches the external security review check.
- **Fix:** either author the seven required docs in this commit, or re-tier the
  production-readiness table so that only artifacts that exist in the repo gate the
  local-evidence claim and the external security review is the only external blocker.

### B2. `verify-evidence.sh` does not enforce `git_commit` binding
**(Worker 2, Finding #24)**

- `verify_evidence()` (`kurrentctl.rs:819-942`) checks `report.status == "passed"`,
  `report.blockers.is_empty()`, required flow fields, and `EvidenceFile.sha256`
  re-hashes. It does **not** check `kurrent-acceptance.json::git_commit ==
  git rev-parse HEAD`.
- On-disk `kurrent-acceptance.json` records `git_commit: 93e3f25` but HEAD is
  `6134cad`. So `verify-evidence.sh` happily passes on stale evidence from a prior
  commit.
- `verify_production_readiness()` (`kurrentctl.rs:1194-1267`) has the same gap.
  Only `external_security_review` checks `reviewed_git_commit == HEAD`
  (`kurrentctl.rs:1131-1134`).
- **Effect:** the verifier is self-referential. A reproducer passes against any
  previously-passed `kurrent-acceptance.json`, even if the current commit diverged.
- **Fix:** add `git_commit` enforcement to both verifiers; ensure
  `kurrent-production-readiness.json` records its own `git_commit` field.

### B3. Invoice note uses invented `kikaspa*` HRPs
**(Worker 3, Finding #1)**

- Note defines HRPs `kikaspa`/`kikaspat`/`kikaspar`/`kikasprt`/`kikaspaidn`
  (INV:77-81, 230, 247).
- Kaspa's actual bech32m HRPs are `kaspa`/`kaspatest`/`kaspasim`/`kaspadev`/`kaspareg`.
- `kikaspa*` is not in any Kaspa tooling and would fail any bech32 separator check
  (the `1` separator rule).
- **Effect:** the worked example at line 230 cannot be parsed by any standard bech32m
  decoder.
- **Fix:** replace with canonical Kaspa HRPs, or document an explicit derivation from
  `network_profile`.

### B4. Zero implementation backing for the invoice format
**(Worker 3, Finding #2; cross-referenced by Worker 4 Finding #1, #10, #11, #14)**

- `src/`, `tests/`, `evidence/`, `Cargo.toml` have zero matches for `kikaspa`,
  `kurrentinvoice`, `hrp`, `bech32`, `bech32m`, `KI ::=`, `payer_secret`,
  `amount_sompi`, `recipient_xonly`. The only `invoice` references in code are LN
  BOLT 11 `addinvoice` flows (`kurrentctl.rs:1645, 1651, 1659, 1660, 1691, 1716,
  2339-2365`) and `evidence/ln-bob-invoice.json`.
- `Cargo.toml` has no `bech32` dependency.
- **Effect:** the note specifies a wire format and signing model that nothing in
  the repo can produce, parse, sign, or verify. No `kurrentctl pay-invoice`,
  no `kurrentctl decode-ki`, no `KurrentInvoice` typed model, no worked-example
  test.
- **Fix:** either (a) add a `KurrentInvoice` typed model in `src/lib.rs` parallel
  to existing normative types, a `validate_invoice(...)` function, and at least one
  `tests/` case exercising the worked example; or (b) demote the note to a clearly
  labelled design sketch.

### B5. `recipient_xonly` claims a key role that does not exist
**(Worker 3, Finding #6; Worker 4, Finding #2)**

- Note defines `recipient_xonly` (TLV 0x09) as "recipient's per-state-update x-only
  pubkey, distinct from the MuSig2 aggregate" (INV:67-68, 104-106, 149-154, 270-274).
- Thesis fixes authorisation as fixed MuSig2 aggregate `P_agg` over lex-sorted
  participant keys (THESIS:151-152, 213-215, 264-265, §5.3). Per-state key rotation
  requires `EpochTransitionCertificate` (future work, THESIS:614).
- Code: `musig2_aggregate_xonly` (`LIB:2674-2701`) is the only aggregate key.
  Individual participant pubkeys in `AccessManifest.participant_public_keys`
  (`LIB:1596`) feed the aggregate, but there is no separate "per-state-update" key.
- **Effect:** if the invoice is consumed on-chain, the covenant cannot bind the
  recipient signature to a state because the covenant only checks Schnorr over
  `P_agg`. If consumed off-chain only, the verification rule "matches the
  channel's recorded recipient per-state-update pubkey" is unenforceable.
- **Fix:** either drop `recipient_xonly` and use the recipient's MuSig2 contribution
  pubkey (verify it's a participant of `agg_key`), or specify the key derivation
  rule for the new per-state-update key.

### B6. `state_number` semantics contradict the registry's +1 rule
**(Worker 4, Finding #1; cross-referenced by I6 above)**

- Note allows `state_number' ≥ state_number` (INV:58-62).
- Registry enforces strict one-step: `LIB:1024` (`NonMonotonicState { current,
  attempted }`), `LIB:1742` (`next_state != previous_state + 1`),
  `tests/protocol_model.rs:858-877` (`settlement_eligibility_rejects_skipped_state_number`),
  `kurrentctl.rs:2122-2130` (`"state numbers must advance exactly one step"`).
- Thesis §3.4 line 177: a consensus-predicate replacement "is predecessor-independent:
  it need not be the immediate successor of the spent state" — this is at the
  *covenant layer*, not the *registry layer*. The registry on top still enforces +1.
- **Effect:** a KI presenting `state_number = 5` and the next state update at
  `state_number' = 7` would fail at the registry layer. The note's `≥` rule would
  silently fail at the boundary the state-channel-flow actually exercises.
- **Fix:** name the layer explicitly. If the note's invoice binds at the registry
  layer (what `run-state-channel-flow` exercises), then `state_number' == current + 1`.
  If it binds at the consensus predicate layer only, the note must also specify how
  the registry learns to relax the +1 rule for invoice-driven updates.

### B7. `state_root` does not bind `payment_hash` as a hashlock witness today
**(Worker 4, Finding #3; cross-referenced by I8 above)**

- Note claims: "the payer constructs a new Kurrent state `state_number'` ...
  whose **state root binds `payment_hash` as a hashlock witness**" (INV:196-212).
- No such binding in code: `LatestStateHeader` (`LIB:399-422`) has no `payment_hash`
  field. `StateUpdate.balances: BTreeMap<String, u64>` carries balances only. The
  thesis's `state_root_n = H_KurrentState/v1(...)` commitment shape (THESIS §3.3) has
  no payment-hash slot.
- Thesis explicitly defers: THESIS:612 ("Hashlock interop" under Future Work);
  THESIS:647 item (vi): "the hashlock interop must define the shared-secret scoping
  rule, the per-leg claim commitment, and the witness-binding discipline".
- **Effect:** the note presents a future-work surface as a current capability. A
  reader who trusts the note will write code that calls a binding that does not
  exist.
- **Fix:** mark step 2 ("Update") as future work matching thesis §8.6 item (vi).
  Until the surface is specified, the invoice is an offer with a hash that the
  channel state cannot witness on-chain.

---

## MAJOR findings (21, deduplicated)

### M1. `channel_id` vs thesis's `scope_id` (I1)
### M2. Byte-order mismatch for `state_number` and `amount_sompi` (I2, I3)
### M3. Hash primitive mismatch: SHA256 vs BLAKE2b-keyed (I5)
### M4. Domain tag inconsistency (`DOMAIN_INVOICE_V1` vs `KURRENT_INVOICE_V1`) (I10)
### M5. `expiry_daa` substrate mismatch (I7)
### M6. `network_profile` worked-example values don't match deployed harness (I12)
### M7. Replay protection relies on optional `payer_secret` whose tracking is open (I13)
### M8. Single KI replays across multiple state updates (I14)
### M9. `LnSwapEvidence` interop is future work, not current capability (I15)
### M10. `channel_id` derivation inputs disagree with thesis scope inputs (I16)
### M11. `expiry_daa = 0` ambiguity (I11)
### M12. `description` length bound "1..639" is BOLT 11 5-bit-group terminology in a TLV context (I17)
### M13. Verification rule 10 (`recipient_xonly matches channel's recorded recipient pubkey`) is unenforceable on-chain
**(Worker 3, Finding #17)**

- Note's rule 10 (INV:188-189): "`recipient_xonly` matches the channel's recorded
  recipient per-state-update pubkey for `channel_id`."
- The thesis does not record a "recipient per-state-update pubkey" on the covenant
  layer. The covenant only checks `P_agg` against `m_n` (THESIS:310-318, 428-432).
- **Fix:** rename to "off-chain pre-signing check by the recipient's local channel
  config" and remove the implicit promise that anything on-chain enforces it.

### M14. `kurrent-state-channel-{headers,settlement-template,receipt}.json` are dead artifacts
**(Worker 2, Finding #25)**

- `write_state_channel_protocol_files()` (`kurrentctl.rs:1913-2007`) writes three
  synthetic evidence files on every `run-state-channel-flow` invocation. They use
  hardcoded constants: `template_id = "kurrent-state-settle-v1"`, `outputs =
  {alice: 600_000, bob: 400_000}`, `script_covenant_hash = sha256_hex(b"kurrent-toccata-counter-covenant-v1")`,
  synthetic `state_number` 0/1/2 headers with `new_state_commitment =
  sha256_hex(format!("kurrent-state-{N}"))`.
- These are not pinned to the live driver's actual settlement template
  (`kurrent-live-state-channel-evidence.json::settlement_template/hash = 62dc70d5...`).
- `verify_evidence()` does not validate the `protocol_files` field.
- **Effect:** any tampering with `kurrent-state-channel-headers.json` is invisible
  to the verifier.
- **Fix:** either delete `write_state_channel_protocol_files()` or make
  `verify_evidence()` re-hash and structurally validate `protocol_files`.

### M15. `run-ln-devnet` cleanup races on shared port + `bitcoind -daemonwait`
**(Worker 2, Finding #26)**

- `run_ln_devnet()` (`kurrentctl.rs:1439-1742`) spawns bitcoind with `-daemonwait`
  (detaches, no PID capture). Cleanup calls `bitcoin-cli stop`; if bitcoind failed
  to come up the cleanup still calls `bitcoin-cli stop` and times out silently.
- Removes `.kurrent-devnet/lnd-regtest/` at start, **but** does not gracefully
  stop prior lnd processes. An interrupted run leaves orphan lnd processes holding
  TCP ports 12009/12010.
- `.kurrent-devnet/` is gitignored but undocumented.
- **Effect:** `run-ln-devnet.sh` is not safe to interrupt. A re-run after a failed
  run may collide on ports.

### M16. Adversarial soak is deterministic in-process model, not on-chain test
**(Worker 2, Finding #27)**

- `run_adversarial_soak()` (`kurrentctl.rs:2630-2668`) runs 64 iterations across
  6 scenarios. All checks call the same Rust types as the unit tests. None interact
  with live kaspad, live LND, or real mempool.
- Fixtures use hardcoded keys `[11; 32]` for alice, `[22; 32]` for bob.
  Seed = `"kurrent-adversarial-soak-v1"` (hardcoded).
- **Effect:** name is misleading. A clean reproducer produces identical output to
  the on-disk artifact because the seed is hardcoded.
- **Fix:** rename to `deterministic-adversarial-model-soak`.

### M17. `production_evidence_satisfies` markdown check is one-line tautology
**(Worker 2, Finding #28)**

- `.md` files: `text.lines().any(|line| line.trim().eq_ignore_ascii_case("Status: passed"))`.
  A `runbook.md` containing only `Status: passed` (and 99 blank lines) satisfies
  the gate. `.json` files: `value.get("status") == Some("passed")` — pure self-declaration.
- **Effect:** the production-readiness check for runbooks is not checking meaningful
  content. Combined with B1, the gate is doubly unreachable.
- **Fix:** drop the `.md` path; require runbooks to be `.json` evidence files with
  explicit fields, or move the runbook gate out of `verify-production-readiness`
  into a separate documentation gate.

### M18. `evidence/acceptance-logs/` is gitignored but used as authoritative log
**(Worker 2, Finding #29)**

- `scripts/check.sh` writes `local-devnet-acceptance-<timestamp>.log` into
  `evidence/acceptance-logs/` (lines 7-42). The directory is in `.gitignore`.
- `kurrent-acceptance.json` does not embed a log digest or log path.
- **Effect:** reviewers cannot reconstruct the `kurrentctl check` output that
  produced a given `kurrent-acceptance.json`.

### M19. Setup script is `arthur`-specific on darwin
**(Worker 2, Findings #30, #31, #32)**

- `known_bin_dirs()` (`kurrentctl.rs:198-209`) hardcodes `/Users/arthur/go/bin`,
  `/Users/arthur/RustroverProjects/rusty-kaspa/target/{release,debug}`.
- `parent_dir()` fallback is `/Users/arthur/Documents` (kurrentctl.rs:199).
- `--depth 1` for lnd clone + `--filter=blob:none` for rusty-kaspa + build from
  `HEAD` → not deterministic across revisions.
- **Effect:** clean reproducer only works on original author's macOS box.

### M20. `prepare-devnet-tools.sh` clones upstream `kaspanet/rusty-kaspa` (not toccata) by default
**(Worker 2, Findings #31, #32)**

- `prepare-devnet-tools.sh` → `prepare-devnet-tools` clones upstream `rusty-kaspa`
  by default. The kaspa-devnet driver override_params path expects
  `compute_budget_relay_test_params.json` from the toccata fork.
- **Effect:** the override_params path is brittle on a clean checkout.

### M21. Three-layer commitment is described as production target but is not active surface
**(Worker 1, Finding #21)**

- Code describes three-layer commitment (factory materialisation, settlement eligibility,
  state-channel flow) as the production target, but only the state-channel layer is
  actively exercised in the harness. The factory and settlement-eligibility layers
  are model-only today.

---

## MINOR findings (14)

| # | Source | Finding |
| --- | --- | --- |
| m1 | W3 F11 | `description` length "1..639" is BOLT 11 5-bit-group terminology in a TLV context |
| m2 | W3 F12 | `payer_secret` semantics not specified ("matches verifier's local payer-nonce" is the only rule) |
| m3 | W3 F13 | `network_profile` "simnet-0.15" format not anchored anywhere in the repo |
| m4 | W3 F14 | `metadata` TLV is recursive-opaque — undefined inner encoding |
| m5 | W3 F15 | `KURRENT_INVOICE_V1` is 18 ASCII bytes, not 16 as the note claims |
| m6 | W3 F16 | `0xBC830A3` BIP-350 constant written with mixed case; conflates polymod XOR with data-part separator |
| m7 | W3 F18 | "BIP-173 length-extension malleability" mis-describes the actual BIP-173 defect |
| m8 | W4 F10 | Payer-side protocol consumer is unspecified — no CLI / library surface named |
| m9 | W4 F11 | Note's domain separator `KURRENT_INVOICE_V1` is undeclared in `src/lib.rs` |
| m10 | W4 F13 | Note claims `LnSwapEvidence` interop; thesis never names `LnSwapEvidence` |
| m11 | W4 F14 | `state-channel-flow` does not produce any invoice evidence; no `kurrent-invoice-flow-evidence.json` |
| m12 | W4 F15 | `state-channel-flow` `interaction_safety_assertions` contradict the invoice's `state_number` semantics |
| m13 | W2 #30 | kaspad/lnd built from source on first run, output not hashed (non-deterministic) |
| m14 | W2 #31 | Root resolution walks exe parent chain; brittle for `cargo install` |

---

## NIT findings (9)

| # | Source | Finding |
| --- | --- | --- |
| n1 | W3 F19 | Worked example state_number 42 inconsistent with the byte field (depends on Finding 10 / M2) |
| n2 | W3 F20 | `DOMAIN_INVOICE_V1` and `KURRENT_INVOICE_V1` collision (restated from F7 / M4) |
| n3 | W3 F21 | Worked example uses `simnet` but `protocol_version: 0x0001` is unanchored to channel's `programme_version` |
| n4 | W4 F16 | Note says BOLT 11 vocabulary references in prose (acceptable, but worth pruning for normative spec) |
| n5 | W4 F17 | Note's "open questions" list contains items that are actually blocking for verifier implementation |
| n6 | W4 F18 | "channel-state identity required to redeem the payment off-chain" — claim without protocol path |
| n7 | W4 F19 | `payment_secret` semantic vs BOLT 11 — minor inaccuracy in explanatory prose |
| n8 | W4 F20 | README does not mention `KURRENT_INVOICE_DESIGN_RESEARCH.md` in Repository Map; lists three docs that don't exist |
| n9 | W2 #36 | All `scripts/run-*.sh` are pure wrappers; documenting this would help reviewers |

---

## Subject-by-subject highlights (preserved from individual audits)

### Thesis ↔ prototype ↔ test (Worker 1 — selected highlights)

- **F1 BLOCKER** — `settlement_mask` is not in any normative commitment. The thesis
  references a settlement-mask boundary condition for output reduction but the
  prototype's `BoundedShape::Settlement.output_slot_count() = 3` ignores the mask-driven
  reduction (LIB: shape enum + state-root commit; `tests/protocol_model.rs` covers
  boundaries only for canonical allocations).
- **F2 BLOCKER** — Contest-output transaction graph is entirely absent. The thesis
  describes the on-chain settlement transaction (covenant-bound contest output,
  alternative-history replacement, settlement distribution), but the Rust crate
  has no transaction-building helpers and `scripts/run-state-channel-flow.sh`
  only writes a synthetic `kurrent-state-channel-headers.json` with
  `new_state_commitment = sha256_hex(format!("kurrent-state-{N}"))`.
- **F3 BLOCKER** — Same-number conflict rule is contradicted by prototype, by design.
  Thesis §3.4 line 177: "predecessor-independent". Prototype's
  `validate_state_number` + `NonMonotonicState` error enforces strict `state_number
  == current + 1`. The thesis says one thing and the code does another; this is
  intentional in the code but is a structural divergence from the spec.
- **F5 MAJOR** — `epoch` field in `compute_state_cert_message` is not in the spec.
  `StateCertMessage::compute` takes an `epoch` argument (`LIB:2837-2847`) that is
  not in the thesis's `m_n = H_KurrentStateCert/v1(scope_id ‖ le64(n) ‖ state_root_n)`
  formula. Either the thesis absorbs the epoch or the code drops it.
- **F8 MAJOR** — `OP_CHECKSIGFROMSTACK` thesis profile vs `OpCheckSigFromStack`
  proxy. The thesis describes CSFS as a covenant opcode; the prototype uses a Rust
  proxy that simulates CSFS in-process (`src/bin/kurrentctl.rs` proxy path). This
  means the harness never exercises a real CSFS check.
- **F15 MINOR** — `Tx.version = TX_VERSION_TOCCATA = 1` is not asserted anywhere
  in the on-chain path. A toccata-profile transaction with `version = 0` would
  pass the prototype's covenant check because the prototype doesn't check.

### Scripts / runners / devnet flows / evidence package (Worker 2 — selected highlights)

- **F26 MAJOR** — `run-ln-devnet` cleanup races on shared port + `bitcoind -daemonwait`
  (see M15).
- **F27 MAJOR** — Adversarial soak is deterministic in-process model, not on-chain
  test (see M16).
- **F33 MINOR** — Verification of the "external security review" file is genuinely
  strong: schema version + reviewer attestation ≥40 chars + `git_commit` binding +
  scope coverage + finding counts + methodology non-empty + file hash binding.
  This is the strongest cryptographic binding in the entire verifier.
- **F34 MINOR** — `tmp/p0-precondition-assert.patch` is committed as a `.patch`
  file plus README, but the README references a commit not in `main` (commit
  `4730b26` is unreachable from `main @ 6134cad`). The patch is a stale snapshot
  of itself.
- **F35 NIT** — `evidence/ln-bob-invoice.json` vs `evidence/ln-bob-lookupinvoice.json`
  keep `r_preimage` of the same preimage. Minor leakage.

### Invoice design — internal consistency / cross-doc (Worker 3 — selected highlights beyond MAJOR list)

- **F2 BLOCKER** — Zero implementation backing (see B4).
- **F8 MAJOR** — Hash function mismatch: SHA256 vs thesis's BLAKE2b-256 keyed
  (see I5 / M3).
- **F11 MINOR** — `description` length bound inconsistency with BOLT 11 (see m1).
- **F12 MINOR** — `payer_secret` semantics not specified (see m2).
- **F17 MINOR** — Verification rule 10 is unenforceable on-chain (see M13).
- **Cross-doc table** — 16 cross-doc contradiction entries; most overlap with I1-I18.

### Invoice design — integration (Worker 4 — selected highlights beyond MAJOR list)

- **F1 BLOCKER** — `state_number` semantics in the invoice contradict the
  implementation's "advance exactly one step" rule (see B6).
- **F4 MAJOR** — `network_profile` HRP/profile strings do not match the deployed
  profile values (see I12 / M6).
- **F6 MAJOR** — `expiry_daa` semantics are unspecified past the recipient
  commitment (no voiding rule) (see I7 / M5).
- **F7 MAJOR** — Replay protection across invoices relies on a `payer_secret` that
  is optional (see I13 / M7).
- **F8 MAJOR** — Recipient re-use of the same KI across multiple state updates is
  unaddressed (see I14 / M8).
- **F10 MINOR** — Payer-side protocol consumer is unspecified (see m8).
- **F18 NIT** — "channel-state identity required to redeem the payment off-chain"
  — claim without protocol path (see n6).
- **Recommended placement** — Do not move the note into the thesis. Rename to
  `KURRENT_INVOICE_DESIGN_RESEARCH.md` and add a one-paragraph preamble that
  states it is a research claim the thesis does not yet endorse. Move the
  resolved rules to a follow-up `KURRENT_INVOICE_PROTOCOL_SPEC.md` once the
  four blockers (B3-B7) and the major gaps are resolved.

---

## What this commit adds (positive)

- Adds a *research* note that genuinely tries to position the protocol against
  BOLT 11 and identify what would need to change to add an offer layer. The
  note is short (308 lines), structurally sound as a design sketch, and uses
  the correct domain-tag-framing language ("research-architecture claim",
  "production protocol-specification work must additionally satisfy the following
  named requirements") that mirrors the thesis's "Named protocol-specification
  requirements (not research-note gaps)" framing (THESIS:647).
- The version-narrative check passes — the note contains no "v1"/"v2"/"rev N"/
  "earlier draft"/"frozen outline" language. Single-delivery.
- No regression in the thesis or the implementation: the thesis hash, the Rust
  crate hash, and the test surface are unchanged on this commit.

## What this commit does not change (necessary cleanup not done)

- README's "Repository Map" still lists 5 documents; only 2 exist on disk. The
  new invoice note is not listed. The README pointer to a non-existent audit
  doc is a pre-existing inconsistency this commit did not introduce but did
  not fix either.
- The factory design note referenced in README and thesis does not exist on
  disk (`KURRENT_FACTORY_COMMITMENT_DESIGN.md`).
- The seven PRODUCTION_*.md / KURRENT_*_*.md runbooks still do not exist
  (Finding B1).

---

## Reproducibility verdict (consolidated)

**Local-devnet acceptance (`scripts/check.sh`) on `main @ 6134cad`:**

- **Pass-able on a clean reproducer machine that is `arthur`'s macOS box** with
  `/Users/arthur/Documents/rusty-kaspa-toccata` and `/Users/arthur/go/bin` on
  PATH: yes, but only against stale evidence (B2: `git_commit` not bound).
- **Pass-able on a clean reproducer machine that is not `arthur`'s**: no —
  `prepare-devnet-tools.sh` will misbehave (M19, M20) and the override_params
  path will not find the toccata fork's `compute_budget_relay_test_params.json`.
- **Pass-able on a Linux CI runner**: no — same hardcoded paths.

**Production-readiness gate (`scripts/verify-production-readiness.sh`):**

- **Pass-able on a clean reproducer**: no — at least six required production
  artifacts point at docs that have never existed (B1). The gate is structurally
  unreachable from a fresh checkout.

**Reproducibility of `evidence/kurrent-acceptance.json`:**

- The on-disk report records `git_commit: 93e3f25`. HEAD is `6134cad`. The
  evidence is from a prior commit and the verifier does not detect the gap (B2).

**External security-review verifier:**

- Genuinely strong. Schema version + reviewer attestation length + `git_commit`
  binding + scope coverage + finding counts + methodology non-empty + file hash
  binding. This is the single piece of the verifier that survives every audit
  dimension.

---

## Recommended fix sequence

1. **Gate-reachability** (B1, B2): write the missing runbook docs, or re-tier the
   production-readiness table so it only requires artifacts that exist. Add
   `git_commit` enforcement to both verifiers.
2. **Invoice format** (B3-B7, M1-M13): either (a) demote the invoice note to
   `KURRENT_INVOICE_DESIGN_RESEARCH.md` with explicit "not normative" framing
   and remove the verifier-implementation obligation, or (b) re-derive the note
   against the thesis and add a `KurrentInvoice` typed model + one worked-example
   test in the same commit.
3. **Spec/code alignment** (Worker 1 F1-F8): pick a position on `settlement_mask`,
   contest-output tx graph, same-number rule, `epoch` field, CSFS proxy vs real
   opcode, and document the divergence explicitly.
4. **Reproducer portability** (M19, M20): replace `/Users/arthur/Documents` and
   `/Users/arthur/go/bin` with PATH-relative resolution; pin lnd and rusty-kaspa
   to specific tags.
5. **Verifier strengthening** (M14, M17, M18): re-validate `protocol_files`;
   drop the markdown one-liner check; bind the acceptance log to the acceptance
   report.

---

## Audit sources

- Worker 1 (thesis ↔ prototype ↔ test): `scratchpad.md` lines 1-700
- Worker 2 (scripts / runners / devnet / evidence): `scratchpad.md` lines 702-1351
- Worker 3 (invoice design — internal): `audit-KURRENT_INVOICE_DESIGN_RESEARCH.md` (237 lines, 21 findings, post-demotion filename)
- Worker 4 (invoice design — integration): `/tmp/kurrent-invoice-audit-report.md` (212 lines, 20 findings)

The full source findings and code citations are preserved in the source files.
This aggregate deduplicates and merges them. Where workers 3 and 4 reach the
same conclusion from different angles (12 of the 18 invoice cross-doc items),
the findings are merged and credited to both.