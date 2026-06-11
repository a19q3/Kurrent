# Production Monitoring

Status: passed

This runbook defines the monitoring and alerting controls required for Kurrent production operation.

## Scope

- Covers Kurrent protocol services, Kaspa node connectivity, Lightning node connectivity, signer service health, evidence retention, and settlement/refund liveness.
- Does not replace adversarial soak evidence or external security review.

## Required Signals

- Kaspa node RPC availability, peer count, sync status, virtual DAA score progression, mempool admission failures, block-template failures, and transaction rejection reasons.
- Kurrent channel state number, latest accepted commitment hash, previous commitment hash, settlement template hash, funding outpoint, and signer threshold status.
- Factory active virtual-channel set, materialisation ids, touched leaves, fee reserve, and conservation totals.
- LN invoice payment hash, preimage-observed status, payment status, channel state, route/payment failures, and timeout horizon.
- Refund maturity height/DAA, early-refund rejection status, mature-refund submission status, and double-claim rejection status.
- Evidence verifier result, semantic transaction verifier result, production-readiness result, and hash mismatch count.

## Alerts

- Critical: signer unavailable, threshold signature failure, forged signature attempt, stale settlement accepted, refund maturity missed, production evidence verifier failure, or unexpected raw transaction hash mismatch.
- High: Kaspa RPC unavailable for more than 60 seconds, LN payment stuck beyond configured timeout budget, mempool rejection for a transaction expected to be accepted, or channel state not advancing when required.
- Medium: delayed evidence upload, non-critical command transcript missing, peer count below threshold, or monitoring scrape gaps.

## SLOs

- Evidence verifier: must pass for every release candidate.
- Semantic transaction verifier: must pass for every production evidence bundle.
- Critical alert acknowledgement: within 15 minutes.
- Refund maturity action: before 25 percent of the configured safety margin has elapsed.
- Evidence retention: raw transaction, witness, script, receipt, and command transcript artefacts retained for the full dispute period plus 90 days.

## Dashboards

- Production gate status: local acceptance, semantic verifier, soak evidence, runbooks, external review.
- Channel state: latest state, funding outpoint, settlement eligibility, signer quorum.
- Swap state: LN invoice, preimage hash, Kaspa hashlock funding, settlement/refund status.
- Node health: Kaspa, Bitcoin regtest/mainnet profile where applicable, LN node health, signer health.

## Release Checks

1. Run `./scripts/check.sh`.
2. Run `./scripts/run-semantic-transaction-verifier.sh`.
3. Run `./scripts/run-adversarial-soak.sh`.
4. Run `./scripts/prepare-security-review-package.sh`.
5. Run `./scripts/verify-production-readiness.sh`.
6. Confirm all production dashboards are green before funding or migration.
7. Store the evidence report paths in the release record.

## Failure Conditions

- Any production deployment lacks alerting for signer threshold failure, stale-state attempt, refund maturity, or evidence hash mismatch.
- Any release proceeds without retained evidence for raw transactions, scripts, witnesses, flow JSON, and verifier output.
- Any critical alert is unowned.
