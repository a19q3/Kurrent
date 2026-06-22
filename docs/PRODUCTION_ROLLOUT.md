# Production Rollout And Rollback

Status: passed

This runbook defines release procedure for production-readiness gating. It does
not make a production deployment claim.

## Scope

Rollout covers source revision selection, evidence regeneration, verifier
execution, release approval, and rollback for Kurrent. A release is not
production-ready unless local acceptance, production target profile, semantic
transaction verification, adversarial model soak, operational runbooks, and
independent external security review all pass for the same intended revision.

## Rollout Procedure

1. Select the source commit and record the branch, commit hash, and remote.
2. Run `cargo test` and `./scripts/check.sh`.
3. Run `./scripts/write-production-target-profile.sh`.
4. Run `./scripts/run-semantic-transaction-verifier.sh`.
5. Run `./scripts/run-adversarial-soak.sh`.
6. Run `./scripts/prepare-security-review-package.sh`.
7. Obtain independent external security-review evidence for the requested
   artefact set.
8. Run `./scripts/verify-production-readiness.sh`.
9. Publish only if the production-readiness report passes and every reviewed
   artefact hash matches the release candidate.

Any source, evidence, or runbook change after external review invalidates the
review package and requires regeneration.

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
