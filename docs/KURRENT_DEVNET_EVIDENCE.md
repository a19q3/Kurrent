# Kurrent Devnet Evidence

Current status: `passed`.

The repository contains successful local capability evidence and passed live Kurrent Kaspa business-flow evidence.

## Evidence Present

- `evidence/tool-detection.json`: local Kaspa, Lightning Network, and Rust tooling detection.
- `evidence/kaspa-simnet-probe.log`: real `kaspad` simnet startup probe.
- `evidence/kaspa-txscript-covenants.stdout.log`: real Toccata txscript covenant VM run. It accepts monotonic counter transitions and rejects invalid non-incrementing transitions.
- `evidence/kaspa-daemon-compute-budget-relay.stdout.log`: real Kaspa daemon integration run for live transaction relay, block-template submission, and mining.
- `evidence/ln-devnet-evidence.json`: real two-node Lightning Network regtest channel, invoice payment, and observed preimage.
- `evidence/kurrent-state-channel-flow-evidence.json`: Kurrent state-channel protocol files plus Kaspa capability command evidence.
- `evidence/kurrent-live-state-channel-evidence.json`: live Kurrent Kaspa simnet funding, state update, stale-state rejection, and state-2 settlement evidence, including txids, raw transaction hashes, witness hashes, settlement-template hash, and channel-receipt hash.
- `evidence/kurrent-live-funding-tx.hex`: serialised live Kurrent funding transaction.
- `evidence/kurrent-live-state-update-tx.hex`: serialised live Kurrent state-1 to state-2 update transaction.
- `evidence/kurrent-live-stale-rejected-tx.hex`: serialised live stale/non-continuing spend attempt rejected by the node.
- `evidence/kurrent-live-settlement-tx.hex`: serialised live Kurrent state-2 settlement transaction.
- `evidence/kurrent-live-state-update-witness.hex`: live state-update witness bytes.
- `evidence/kurrent-live-stale-rejected-witness.hex`: live rejected stale-spend witness bytes.
- `evidence/kurrent-live-settlement-witness.hex`: live settlement witness bytes.
- `evidence/kurrent-factory-flow-evidence.json`: Kurrent factory materialisation model evidence.
- `evidence/kurrent-live-factory-evidence.json`: live factory funding and materialisation evidence.
- `evidence/kurrent-ln-to-kaspa-flow-evidence.json`: Lightning Network preimage evidence bound into a Kurrent swap receipt scope.
- `evidence/kurrent-live-ln-to-kaspa-evidence.json`: live Kaspa hashlock settlement using the observed Lightning preimage.
- `evidence/kurrent-kaspa-to-ln-flow-evidence.json`: Lightning Network payment/preimage evidence bound into the reverse Kurrent swap receipt scope.
- `evidence/kurrent-live-kaspa-to-ln-evidence.json`: live reverse-direction Kaspa hashlock funding and settlement evidence.
- `evidence/kurrent-refund-flow-evidence.json`: Kurrent refund maturity and double-claim model evidence.
- `evidence/kurrent-live-refund-evidence.json`: live early-refund rejection and matured refund evidence.
- `evidence/kurrent-acceptance.json`: aggregate verdict.
- `docs/KURRENT_INTERACTION_SAFETY_AUDIT.md`: model-level interaction-safety coverage for every accepted business flow.

## Evidence Still Missing

None for the local devnet acceptance gate.
