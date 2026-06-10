# Kurrent State Channel Spec

Kurrent channel state is represented by `LatestStateHeader` and `StateUpdate`.

`LatestStateHeader` binds:

- network/profile;
- genesis or local devnet id when available;
- funding outpoint;
- channel id;
- optional factory id;
- optional virtual channel id;
- state number;
- previous and new state commitments;
- settlement template hash;
- challenge policy hash;
- participant set hash;
- script/covenant hash;
- protocol version;
- domain separator.

The current model enforces strict monotonic state progression. A state must start at `0` and each accepted update must increase by exactly one. A same-number conflicting commitment is rejected. Settlement is only allowed for the latest accepted commitment and matching settlement template hash.

This spec is implemented locally in `src/lib.rs`.

Current runtime evidence:

- `evidence/kaspa-txscript-covenants.stdout.log` exercises a Toccata covenant script that accepts monotonic state increments and rejects non-incrementing or stale-counter spends.
- `evidence/kaspa-daemon-compute-budget-relay.stdout.log` exercises live Kaspa daemon transaction relay/mining behaviour on the Toccata checkout.
- `evidence/kurrent-state-channel-flow-evidence.json` binds those transcripts to Kurrent state headers, a settlement template, a channel receipt, and live Kurrent funding / update / stale-rejection / settlement evidence.
- `evidence/kurrent-live-state-channel-evidence.json` records the live Kurrent funding outpoint, state-update txid, rejected stale-spend txid, settlement txid, raw transaction hashes, witness hashes, settlement-template hash, and channel-receipt hash.

The Kaspa state-channel flow now passes locally. The aggregate local devnet acceptance gate also passes.
