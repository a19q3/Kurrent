# Production Monitoring

Status: drafted (runbook-level, not production gate status)

This runbook describes the monitoring procedure required by the production gate.
It is not a production deployment claim.

## Scope

Kurrent safety is conditional on timely detection and inclusion of higher-state
replacement transactions. Monitoring therefore covers local node health, channel
state freshness, DAA-relative response-window tracking, evidence retention, and
operator escalation. The runbook assumes the fixed bilateral channel described
in the thesis and does not cover public Lightning route-hop operation.

## Signals

Operators monitor the following signals for each deployment profile:

- local Kaspa node reachability and network identity;
- local `rusty-kaspa` source revision and whether it satisfies
  `kurrentctl detect-tools`;
- current DAA score and response-window distance for each contested state;
- latest accepted channel state number and state-root hash;
- replacement, settlement, refund, and cooperative-close transaction status;
- signer availability and highest signed state number;
- fee sponsor availability and fee-reserve status;
- evidence writer success for raw transactions, scripts, witnesses, and flow
  reports.

Each signal must have a timestamped record. Alerts must include the channel
scope, state number, relevant transaction id or outpoint, and the local node
view used to make the decision.

## Alert Response

Response-window alerts are handled first. If a stale settlement candidate is
seen before maturity, the operator publishes the latest higher-state
replacement and records the publication evidence. If maturity is close and the
replacement has not propagated, the operator escalates fee sponsorship and
records the inclusion attempt.

Signer alerts freeze new signing until the highest signed state can be
confirmed. Node-divergence alerts require comparison against a second trusted
node before publication decisions are made. Evidence-writer alerts are blocking
for release claims, because an unrecorded safety action cannot be independently
replayed.

## Evidence

Monitoring evidence consists of alert logs, DAA-score samples, publication
transcripts, transaction ids, fee-sponsor records, node version records, and the
acceptance evidence hash for the deployed revision. Logs must be retained long
enough for independent review and incident reconstruction.
