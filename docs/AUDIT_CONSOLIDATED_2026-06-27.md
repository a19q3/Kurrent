# Kurrent Consolidated Audit Summary

**Date:** 2026-06-27  
**Repository:** `/Users/arthur/RustroverProjects/Kurrent`  
**Recorded HEAD:** `dfc1b49ac7945a907b05bb7901c85eeaf8afc5ef`  
**Source material:** two full audit reports supplied on 2026-06-27, plus direct verification against the current working tree and regenerated evidence.  
**Release position:** Kurrent has not been released. There is no backwards-compatibility obligation for prototype APIs, evidence formats, or commitment bytes.

## Executive Decision

Kurrent should have one product protocol surface: the normative bilateral latest-state construction in `docs/KURRENT_THESIS.tex`.

The audit decision is therefore strict:

1. Do not preserve old prototype APIs as compatibility shims.
2. Do not support both historical and thesis commitment bytes.
3. Do not keep an `epoch` field in any public state-certificate path.
4. Do not preserve adjacent-only replacement semantics where the thesis says `m > n`.
5. Do not treat the marker/KIP-21 harness as the bilateral fund-safety construction.

This working tree now follows that decision for the normative Rust API. The old epoch-bearing helper surface has been removed, settlement shape `1` is the only accepted thesis value, the state root authenticates the settlement mask, cooperative-close output hashing includes the mask, `toccataSPK` is separate from `commitSPK`, and replacement eligibility accepts predecessor-independent higher state numbers.

The remaining distinction is not backwards support. It is a current implementation boundary: the repository still contains a JSON/devnet evidence harness with `KURRENT_*_V1` model domains. That harness may remain useful for local evidence and regression tests, but it must not be described as the final on-chain bilateral contest-output protocol.

## Current Verdict

The pre-release compatibility burden has been cut from the public normative path. The implementation is now materially closer to the thesis than the two supplied audit reports described.

Kurrent is **devnet-accepted in this working tree** after regeneration:

- `cargo test --all-targets`: passed.
- `cargo clippy --all-targets -- -D warnings`: passed.
- `cargo run --quiet --bin kurrentctl -- check`: passed.
- `cargo run --quiet --bin kurrentctl -- verify-evidence`: passed.
- `cargo run --quiet --bin kurrentctl -- verify-presentation-reality`: passed, 80/80 checks.

Kurrent is **not production-ready**. `cargo run --quiet --bin kurrentctl -- verify-production-readiness` exits `17` because `evidence/production/security-review.json` is missing or not passing. That is the correct blocker: external security review remains outside this implementation pass.

## Resolved Audit Findings

| Finding from supplied audits | Current decision and status |
| --- | --- |
| Old epoch/JSON public helpers conflicted with the thesis. | Resolved for the public normative surface. The old `KurrentScope`, `KurrentStateRoot`, free `compute_*` helper path, and unvalidated state-certificate shim are gone. |
| `settlement_shape_id` used the wrong value. | Resolved. `SETTLEMENT_SHAPE_TWO_PARTY_FIXED = 1`; tests now reject the old fixed-shape assumption. |
| Settlement mask was specified but not committed. | Resolved. `SettlementMask` is typed and included in `StateRootInput::canonical_payload`. |
| Cooperative close did not bind the mask. | Resolved. `coop_close_outputs_hash` takes and commits `SettlementMask`. |
| Toccata output SPK bytes were conflated with commitment SPK bytes. | Resolved. `EncodedSpk::encode()` remains `commitSPK`; `EncodedSpk::toccata_encode()` is the transaction-output byte form. |
| Output shape was fixed rather than mask-driven. | Resolved in the bounded-shape model. Participant output count is derived from the settlement mask, with sponsor change handled separately. |
| Replacement was adjacent-only. | Resolved in the eligibility model. Higher non-adjacent state numbers are accepted when the candidate is otherwise valid. |
| Evidence accepted stale or structurally weak artefacts. | Improved. Acceptance now includes 22 source-artifact hashes and verifies them; state-channel evidence cross-links settlement-template hashes and state numbers; superficial `not_executed`/`blocked_before_execution` statuses are rejected. |
| `check` was weaker than the real acceptance story. | Improved. `kurrentctl check` now also runs semantic transaction verification, adversarial soak evidence generation, evidence verification, and presentation-reality verification. |

## Remaining Blocking Findings

### P0. Normative contest-output graph is still the next real product milestone

The thesis says the production mainline is the contest-output transaction graph. The repository now has stronger normative bytes and stronger local evidence, but it still does not complete the on-chain bilateral contest-output implementation end to end.

Required next work:

1. Implement the actual contest-output transaction graph.
2. Bind script bytecode, output shape, response-window maturity, same-number conflict handling, sponsor placement, SPK comparison, and conservation into executable success and failure tests.
3. Keep KIP-21 and marker evidence as observability or harness evidence, not as the bilateral safety predicate.

### P0. External production security review is still absent

Production readiness correctly remains blocked on independent review evidence:

```text
external_security_review: missing or non-passing required production evidence at evidence/production/security-review.json
```

This should remain a hard production gate. Do not downgrade it to a warning.

### P1. The JSON/devnet harness must stay clearly non-final

The current evidence harness still uses `KURRENT_*_V1` model domains for local JSON state, receipt, settlement-template, factory, and LN interop evidence. Those strings are no longer a backwards-compatibility promise, but they are still visible in the model and generated evidence.

Required policy:

1. Document them as harness/model domains, not as the thesis commitment domains.
2. Do not expose them as a stable public protocol API after the contest-output path exists.
3. Either retire or namespace them before first release.

### P1. Dirty worktree acceptance is mitigated, not eliminated

Acceptance now records and verifies 22 source-artifact hashes, which is a significant improvement over `git_commit` alone. The worktree is still dirty because code, docs, and evidence changed during this pass. For production release evidence, require either a clean source/doc/test tree or a signed manifest whose source hashes are explicitly the release object.

## Acceptance Evidence Snapshot

The regenerated `evidence/kurrent-acceptance.json` reports:

- `status`: `passed`
- `blockers`: `[]`
- `source_artifact_hashes`: 22 entries
- `flow_evidence_paths_and_hashes`: 8 entries
- `raw_transaction_paths_and_hashes`: 17 entries
- `witness_paths_and_hashes`: 8 entries
- `script_paths_and_hashes`: 6 entries
- `command_transcript_paths`: 9 entries
- `git_commit`: `dfc1b49ac7945a907b05bb7901c85eeaf8afc5ef`

The regenerated `evidence/production/presentation-reality.json` reports:

- `status`: `passed`
- `summary.total`: 80
- `summary.passed`: 80
- `summary.failed`: 0

The regenerated `evidence/kurrent-production-readiness.json` reports:

- `status`: `failed/blocked`
- blocker: missing or non-passing external security review evidence

## Release Posture

Kurrent is not ready for a production release. It is ready to claim a narrower, truthful status:

> The current working tree has removed the public pre-release compatibility surface from the normative Rust path, aligns the core commitment bytes more closely with the thesis, and passes local devnet acceptance. The production channel remains incomplete until the contest-output graph and external security review are done.

## Final Call

Delete backwards support. That decision has been applied to the old public normative helper path and should continue to guide the remaining work.

Do not add shims for pre-release formats. Do not carry old `settlement_shape_id = 0` behaviour. Do not restore epoch-bearing state certificates. Do not keep unvalidated signing helpers. Do not let the evidence harness be mistaken for the final bilateral contest-output protocol.
