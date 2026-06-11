# Production Key Management

Status: passed

This runbook defines the minimum key-management controls required before Kurrent can be operated outside local devnet.

## Scope

- Applies to Kurrent participant signing keys, Kaspa funding keys, Lightning node credentials, RPC credentials, and operator break-glass credentials.
- Does not approve mainnet launch by itself; it satisfies only the key-management production-readiness evidence item.

## Required Controls

- Participant state-update signatures must use isolated Schnorr keys whose public keys are pinned in channel configuration.
- Private keys must never be stored in repository files, shell history, evidence artefacts, logs, or CI variables with broad read access.
- Production signing must run through a signer process or hardware-backed key store with explicit request logging and policy checks.
- Every signing request must bind protocol version, network profile, channel id, funding outpoint, settlement template hash, state number, previous commitment, new commitment, participant balances, and signing timestamp.
- Operator access must be split by role: deployer, signer operator, incident commander, observer, and auditor.
- Key rotation must require a new signed channel or factory configuration; in-place silent key substitution is forbidden.
- Backup material must be encrypted, access-controlled, tested quarterly, and restorable without giving one operator unilateral spending power.

## Operating Procedure

1. Generate production keys on the approved signing host or hardware device.
2. Record public keys, key ids, creation time, operator ids, and intended channel/factory scope in the deployment record.
3. Verify the participant public-key map before accepting any state update.
4. Run a dry signing request against a non-spendable production-profile fixture and verify the signature with `validate_channel_update`.
5. Seal private-key backup material and record dual-control approval.
6. Enable signer request logs before funding any channel or factory.

## Rotation

- Planned rotation: create a replacement configuration, collect all required participant approvals, migrate funds only after both old and new configurations verify.
- Emergency rotation: freeze new state updates, preserve latest accepted state, rotate affected credentials, and settle or migrate only after incident commander approval.
- Revoked keys must remain listed in the audit record with revocation reason and final usable state number.

## Recovery

- A lost non-threshold key requires immediate rotation planning but does not by itself force settlement.
- A lost threshold key set requires channel freeze and recovery from the latest mutually signed state.
- A suspected key compromise requires immediate signer shutdown, evidence preservation, and incident response under `docs/PRODUCTION_RECOVERY.md`.

## Audit Evidence

- Public-key inventory.
- Signed channel/factory configurations.
- Signer request logs.
- Backup test result.
- Rotation or no-rotation attestation for the release.

## Failure Conditions

- Any private key appears in repository, logs, evidence, or CI output.
- Any state update can validate with a forged, empty, stale, or non-threshold signature set.
- Production signer policy omits channel id, funding outpoint, state number, or settlement template binding.
