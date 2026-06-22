# Kurrent Invoice Design Research

Status: research note, not normative.

This document sketches a possible Kurrent invoice (KI) offer format. It is not
part of the Kurrent protocol specification, not an implementation contract, and
not a wire format that tooling should parse today. The normative protocol
surface on this branch remains `KURRENT_THESIS.tex` and the typed Rust model.

An eventual invoice protocol must live in a separate
`KURRENT_INVOICE_PROTOCOL_SPEC.md` document with a typed model, canonical byte
tests, and a worked-example test in the same change.

## Current Boundary

The present repository has no `KurrentInvoice` type, no KI encoder or decoder,
no bech32/bech32m dependency, no CLI command for KI payment, and no state update
field that binds a KI payment hash. Existing invoice evidence is Lightning
regtest evidence only.

Specifically, this note does not commit:

- a registered invoice human-readable part;
- a `recipient_xonly` role distinct from the current participant keys;
- a payment-hash witness binding inside `LatestStateHeader`;
- a state-number rule different from the prototype registry's exact `+1`
  progression;
- production replay, expiry, revocation, or watchtower semantics.

## Purpose

A KI would be a peer-side offer. The recipient would state the conditions under
which it is willing to co-sign a future Kurrent state update that pays a named
amount and reveals a payment preimage. The invoice is not itself a state update,
state certificate, settlement witness, or on-chain covenant object.

The design goal is similar to BOLT 11 at the user-flow level: carry payment
hash, amount, description, expiry, and recipient authentication in a compact
copy-paste or QR-friendly string. The protocol model is different: Kurrent is a
bilateral latest-state channel, so there is no route, no onion packet, no MPP,
and no `min_final_cltv` equivalent.

## Candidate Commitments

A future KI should bind to the same identity surface as the channel. The current
thesis uses `scope_id`, not an independently derived `channel_id`, for the
normative static channel commitment:

```text
scope_id = H_KurrentScope/v1(
    chain_context || covenant_id || agg_key ||
    le32(delta) || le16(programme_version) || policy_hash
)
```

The invoice design should therefore either use `scope_id` directly or define a
clear mapping from `scope_id` to any user-facing invoice channel identifier.
Adding a second opaque `channel_id` without that mapping creates a naming clash.

Candidate fields for future work:

| Field | Candidate encoding | Status |
| --- | --- | --- |
| `payment_hash` | 32 bytes, SHA256 preimage hash | useful for LN interop, but channel witness binding is future work |
| `scope_id` | 32 bytes | should replace the earlier draft's free `channel_id` |
| `state_number` | `le64` | must name a registry-compatible next state unless a future consensus-only flow is specified |
| `amount_sompi` | `le64` | base-unit amount; no floating-point representation |
| `recipient_participant_xonly` | 32 bytes | if used, it must be a participant key already committed into the aggregate key policy |
| `payer_secret` | 32 bytes | unresolved; make mandatory or require fresh payment hashes per invoice |
| `expiry_daa` | `le32`, non-zero finite expiry | unresolved; absent should mean no invoice expiry |
| `description` | UTF-8 bytes | length limit must be a byte limit, not a BOLT 11 5-bit-group limit |
| `description_hash` | 32 bytes | mutually exclusive with `description` |
| `network_profile` | UTF-8 bytes | must match deployed profile values such as `kaspa-simnet-toccata` |

## Encoding Open Point

Bech32m remains a plausible envelope, but this note deliberately does not assign
an HRP. Kaspa address HRPs in the local Kaspa address crate are `kaspa`,
`kaspatest`, `kaspasim`, and `kaspadev`; a KI string should not invent
`kikaspa*` as if those values were registered.

Before any implementation lands, the protocol specification must fix:

- the exact HRP registry rule;
- canonical TLV ordering;
- duplicate-tag handling;
- unknown-tag handling;
- byte-to-5-bit regrouping;
- checksum input;
- maximum encoded length.

## Signing Model

The earlier draft used a single-party Schnorr signature under a per-state-update
recipient key. That key role does not exist in the current Kurrent channel
state machine. The current protocol authenticates state certificates through the
fixed MuSig2 aggregate key, and individual participant public keys are only the
inputs to that aggregate and the off-chain participant-signature checks.

A future invoice can still be a recipient-only offer, but the verifier must be
able to prove that the signing key is a committed participant key for the
channel scope. The signing domain should follow the current Kurrent convention:
BLAKE2b-256 keyed mode with an ASCII tag such as `KurrentInvoice/v1`, not a
standalone `SHA256("KURRENT_INVOICE_V1" || ...)` message. SHA256 remains
appropriate for LN-compatible payment hashes.

The exact signing payload is unresolved. It should include at least:

- programme version;
- invoice envelope domain;
- `scope_id` or derived invoice channel id;
- payment hash;
- amount;
- expiry if present;
- payer binding if present;
- canonical metadata hash.

## State Update Interaction

The prototype registry currently requires accepted state updates to advance
exactly one state number at a time. A KI consumed by that registry layer should
therefore bind the next expected state, not an arbitrary `state_number >= n`
floor.

The thesis also describes a consensus-level direct displacement path where a
higher valid state can replace a lower contest output without proving every
intermediate state. That is not the same layer as the prototype registry. A
future invoice specification must explicitly choose which layer it targets and
explain how tooling reconciles the two.

Most importantly, the current `LatestStateHeader` has no `payment_hash` field.
The thesis records hashlock interop as future protocol work: the shared-secret
scoping rule, per-leg claim commitment, and witness-binding discipline still
need to be specified. Until then, a KI is only a research offer concept; it is
not an enforceable on-chain payment condition.

## Replay And Expiry Requirements

Replay prevention is unresolved and must be resolved before implementation. One
safe direction is to require a fresh payment hash for every invoice. Another is
to make `payer_secret` mandatory and require the recipient to persist issued
`(payment_hash, payer_secret)` pairs. Leaving `payer_secret` optional while
allowing payment-hash reuse is not acceptable.

Expiry must also be a protocol rule, not prose. A future spec must state whether
expiry voids only the recipient's offer, whether a recipient must provide a
revocation or voiding witness, and how invoice expiry relates to the channel's
DAA-relative response window.

## LN Preimage Swap Interop

The same payment preimage can conceptually link a Kurrent-side claim and a
Lightning-side invoice. The current repository has `LnSwapEvidence` for local
preimage evidence, but the thesis does not yet specify a KI-to-state witness
binding. Interop should therefore be treated as future work until the hashlock
claim commitment exists in the Kurrent state-update surface.

## Promotion Requirements

To promote this research note into a protocol spec, the project needs:

1. `KURRENT_INVOICE_PROTOCOL_SPEC.md` with normative field definitions.
2. A `KurrentInvoice` Rust type with validated constructors.
3. Canonical encoding and decoding tests.
4. A signing and verification test vector.
5. A state-update witness-binding rule for `payment_hash`.
6. Replay and expiry tests.
7. CLI commands or library entry points that consume the type.
8. README wording that advertises the feature only after the above exists.
