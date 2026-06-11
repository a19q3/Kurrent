# Production Rollout And Rollback

Status: passed

This runbook defines the release, rollout, rollback, and compatibility procedure for Kurrent production changes.

## Scope

- Covers protocol model changes, script/covenant changes, evidence verifier changes, semantic verifier changes, operational runbook changes, and dependency/profile changes.
- Does not replace external security review for protocol or script changes.

## Release Classes

- Documentation-only: run Markdown review and production-readiness gate.
- Model-only: run Rust tests, Clippy, local acceptance where relevant, and production-readiness gate.
- Script or transaction semantics: run full local acceptance, semantic transaction verifier, adversarial soak suite, and security review.
- Dependency or target-profile change: regenerate target profile, rerun all gates, and verify compatibility with pinned Kaspa/Toccata profile.

## Pre-Rollout Gates

1. `cargo fmt --all --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test`
4. driver crate `cargo fmt`, `cargo clippy`, and `cargo test`
5. `./scripts/check.sh`
6. `./scripts/write-production-target-profile.sh`
7. `./scripts/run-semantic-transaction-verifier.sh`
8. `./scripts/run-adversarial-soak.sh`
9. `./scripts/prepare-security-review-package.sh`
10. `./scripts/verify-production-readiness.sh`

Production rollout cannot proceed unless every gate required for the release class passes.

## Rollout Procedure

1. Create a release record with git commit, target profile hash, acceptance report hash, semantic verifier hash, and operator approvals.
2. Deploy to a non-funding production-profile environment.
3. Run dry state-update signing and semantic verification against non-spendable fixtures.
4. Enable monitoring and alert ownership.
5. Deploy to limited funding scope.
6. Observe at least one full settlement/refund lifecycle appropriate to the release class.
7. Expand only after the release owner signs off.

## Rollback Procedure

- Documentation-only: revert documentation and regenerate production-readiness report.
- Model or verifier change: revert binary and schema changes, rerun evidence verification, and preserve incompatible evidence under a new release id.
- Script or protocol change: stop new funding, settle or migrate active channels according to latest valid state, and do not downgrade active script commitments.
- Dependency/profile change: restore the previous pinned target profile and verify node compatibility before resuming submissions.

## Compatibility Rules

- Domain separator changes require explicit migration notes.
- Settlement template hash changes require new channel/factory configuration.
- Participant public-key changes require key-management rotation procedure.
- Evidence schema changes require backwards-compatible reader support or an explicit archive migration.

## Failure Conditions

- Any rollout proceeds with a failing production-readiness report.
- Any script or protocol change proceeds without semantic verifier evidence.
- Any rollback attempts to reinterpret active commitments under a different domain separator or settlement template hash.
