# Production Key Management

Status: drafted (runbook-level, not production gate status)

This runbook is a production-readiness artefact for key-management procedure only.
It does not claim that Kurrent is production-ready, mainnet-ready, or externally
reviewed.

## Scope

This document covers operator handling of participant signing keys, backup
material, signer isolation, and recovery drills for the Kurrent local
production-readiness gate. It applies to the fixed-participant bilateral channel
model described in `KURRENT_THESIS.tex`; key rotation and quorum changes remain
separate protocol work and require an explicit transition certificate before
deployment.

The key-management objective is simple: signing material must be available
enough for liveness, isolated enough to avoid unauthorised state signatures, and
recoverable enough that a channel can be closed or defended during an incident.

## Controls

Participant keys are generated on an isolated host or hardware signer. Raw seed
material is never written to application logs, evidence JSON, command
transcripts, or repository files. Public keys may be committed as participant
configuration, but private keys and mnemonic material must remain outside the
repository.

Each signer records the highest signed state number for a scope before releasing
any signature. The record must be durable across process restart. A signer must
refuse to sign two different state roots for the same `(scope_id, state_number)`
pair unless a future protocol explicitly defines a same-number conflict
resolution policy.

Access to signer hosts is limited to named operators. Operator access changes
are reviewed before releases. Backup material is encrypted, labelled with the
channel or deployment scope, and stored separately from the online signer.

## Recovery Procedure

1. Declare an incident owner and freeze non-essential signing activity.
2. Identify the affected scope, participant key, last signed state number, and
   available acceptance evidence.
3. Restore the encrypted backup into an isolated recovery host.
4. Verify that the restored public key matches the participant configuration.
5. Replay `cargo test` and the local acceptance gate before resuming signing.
6. If signing cannot safely resume, prepare cooperative close or unilateral
   settlement evidence using the latest valid state certificate.

Any recovery that changes participant keys must be treated as a protocol change,
not an operational hotfix.

## Evidence

Release evidence for this runbook consists of the runbook revision, signer host
inventory, public-key manifest, backup identifier, recovery-drill transcript,
operator approval, and the local acceptance report hash produced for the same
source revision.
