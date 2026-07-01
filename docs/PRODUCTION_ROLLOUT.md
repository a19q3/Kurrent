# Production Rollout And Rollback

Status: drafted (runbook-level, not production gate status)

This runbook defines release procedure for production-readiness gating. It does
not make a production deployment claim.

## Scope

Rollout covers source revision selection, evidence regeneration, verifier
execution, release approval, and rollback for Kurrent. A release is not
production-ready unless local acceptance, production target profile, semantic
transaction verification, adversarial model soak, operational runbooks, and
independent external security review all pass for the same intended revision.

## Rollout Procedure

1. Select the Kurrent source commit and record the branch, commit hash, and
   remote.
2. Select and record the sibling `rusty-kaspa` commit. It must be current
   Toccata-mainnet `origin/master` or a reviewed descendant that satisfies
   `kurrentctl detect-tools`.
3. Run `cargo test` and `./scripts/check.sh`.
4. Run `./scripts/write-production-target-profile.sh`.
5. Run `./scripts/run-semantic-transaction-verifier.sh`.
6. Run `./scripts/run-adversarial-soak.sh`.
7. Run `./scripts/prepare-security-review-package.sh`.
8. Obtain independent external security-review evidence for the requested
   artefact set.
9. Run `./scripts/verify-production-readiness.sh`.
10. Publish only if the production-readiness report passes and every reviewed
   artefact hash matches the release candidate.

Any Kurrent source, Kaspa source, evidence, or runbook change after external
review invalidates the review package and requires regeneration.

## Rollback Procedure

Rollback chooses the last release candidate with passing production evidence
for the affected deployment profile. Operators stop new channel opens, preserve
current evidence, restore the previous binary and configuration, replay local
acceptance, and verify that signer state records are compatible with the
rollback target. If compatibility is not proven, channels must close rather
than continue on ambiguous signer state.

## Evidence

Rollout evidence includes the release commit, acceptance report, production
target profile, semantic verifier output, adversarial soak report, security
review package, external review evidence, operator approval, and rollback
decision if rollback is exercised.
