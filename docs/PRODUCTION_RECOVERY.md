# Production Recovery

Status: passed

This runbook records incident and recovery procedure for the production gate.
It does not assert unattended or mainnet production readiness.

## Scope

Recovery covers operational incidents around Kurrent channel liveness, signer
availability, evidence corruption, local node divergence, Lightning/Kaspa swap
failure, and refund handling. It is written for the present research
specification plus local evidence harness. It must be re-reviewed before any
deployment profile changes.

## Incident Classes

The operator classifies incidents into one of these classes:

- stale-state publication or suspected stale-state publication;
- replacement publication failure before the response window closes;
- signer unavailable, compromised, or state-number record inconsistent;
- Kaspa node divergence or wrong network profile;
- Lightning leg failed, unpaid, or settled without matching Kaspa evidence;
- refund or timeout flow blocked;
- evidence files missing, tampered, or not reproducible.

Classification decides the first recovery action. Fund-safety incidents take
priority over evidence hygiene. Evidence hygiene remains blocking for any later
production claim.

## Recovery Procedure

For a stale-state or replacement incident, identify the latest authorised state,
verify the state certificate, publish the replacement candidate, and preserve
the raw transaction, witness, and node response. If the stale settlement is
already accepted, record the accepted spend and stop claiming recovery through a
higher certificate alone.

For signer incidents, freeze signing, restore or isolate the signer, compare
the highest signed state record, and require operator approval before any new
signature. For swap incidents, validate the preimage against the payment hash
and reconcile both legs before releasing further funds. For evidence incidents,
regenerate local evidence from source and compare all file hashes.

## Evidence

Recovery evidence includes incident timeline, operator decisions, node view,
transaction ids, raw transaction files, witness files, signer state record,
preimage validation results when relevant, and the post-incident acceptance
report.
