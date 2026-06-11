# Production Recovery

Status: passed

This runbook defines incident response and recovery actions for Kurrent production operation.

## Scope

- Covers stalled channels, stale-state attempts, signer failures, Kaspa node divergence, LN payment failures, hashlock settlement failures, and refund paths.
- Does not authorise mainnet launch without the other production evidence gates.

## Incident Roles

- Incident commander: owns decision-making and timeline.
- Protocol operator: validates channel/factory/swap state.
- Signer operator: freezes or restores signing service.
- Node operator: manages Kaspa and LN node health.
- Evidence custodian: preserves logs, raw transactions, scripts, witnesses, and verifier reports.

## First Response

1. Freeze non-essential signing for the affected channel, factory, or swap.
2. Snapshot latest accepted state, funding outpoint, settlement template hash, participant set hash, and receipt hash.
3. Preserve node logs, command transcripts, raw transaction hex, witness hex, script hex, and JSON flow evidence.
4. Run `./scripts/verify-evidence.sh` and record the result.
5. Run `./scripts/run-semantic-transaction-verifier.sh` and record the result.
6. Classify the incident as stale-state, liveness, signer, node, LN, refund, or evidence-integrity.

## Recovery Paths

- Stale-state attempt: reject the stale spend, preserve attempted transaction evidence, verify latest accepted state, and settle only from the latest valid commitment.
- Signer unavailable: keep channel state frozen, restore signer from approved backup, verify public key identity, and run a dry signature validation before resuming.
- Signer compromise: shut down signer, revoke credentials, preserve logs, rotate keys through a new configuration, and settle or migrate funds from the latest safe state.
- Kaspa node divergence: stop submissions, compare node status with independent peers, preserve mempool and rejection logs, and resume only after the target profile is restored.
- LN payment failure: verify invoice status, payment hash, preimage availability, timeout budget, and route failure reason; choose settlement or refund according to observed preimage state.
- Refund path: verify current DAA/height, required maturity, funding outpoint, and double-claim registry before submitting refund.

## Evidence Requirements

- Incident timeline.
- Latest accepted state and receipt.
- All relevant raw transactions, witnesses, scripts, and node rejection messages.
- Output of local evidence verifier and semantic transaction verifier.
- Operator approvals for freeze, recovery, settlement, refund, or rotation.

## Post-Incident Checks

1. Re-run local devnet acceptance if code or scripts changed.
2. Re-run semantic transaction verification if evidence changed.
3. Update monitoring thresholds if alerting was late or noisy.
4. Update key-management records if any credential was rotated.
5. Record whether external security review is required before resuming production.

## Failure Conditions

- Any recovery action proceeds without preserving latest state and transaction evidence.
- Any operator submits settlement or refund without verifying claim exclusivity.
- Any compromised signer resumes without key rotation or explicit incident commander approval.
