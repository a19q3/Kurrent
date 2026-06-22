# Kurrent Security Assumptions

Status: research boundary

This document states assumptions for interpreting the thesis and local evidence
harness. It is an input to security review, not a production pass certificate.

## Scope

Kurrent is currently a research specification plus a local evidence harness.
The normative fund-safety argument is the bilateral contest-output channel in
`KURRENT_THESIS.tex`. The harness demonstrates local flows and typed invariants;
it is not a public mainnet deployment and not the final contest-output
transaction graph.

## Assumptions

The fund-safety argument assumes a valid Kaspa network profile with the required
Toccata-era covenant and introspection surface, ordinary UTXO uniqueness,
deployment-specific finality policy, and a response window long enough for an
honest party or watchtower to publish a higher-state replacement before stale
settlement is accepted.

Signer policy assumes participants sign at most one state root for a given
`(scope_id, state_number)` pair and durably record the highest signed state.
Operational safety assumes monitoring, fee inclusion, and key recovery are
available during the response window.

Lightning/Kaspa swap evidence assumes the preimage hashes to the observed
payment hash and that each leg binds the preimage to its own amount, direction,
expiry, and participant keys.

## Non-Claims

This repository does not claim mainnet readiness, unattended operation, public
Lightning routing, production compressed-factory commitments, or that a higher
state can reverse a stale settlement after that stale settlement has already
been accepted.

## Evidence

Relevant evidence includes `evidence/kurrent-acceptance.json`, production
target profile output, semantic transaction verifier output, adversarial model
soak output, and independent external security review once obtained.
