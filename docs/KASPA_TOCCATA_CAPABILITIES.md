# Kaspa Toccata Capabilities

Local source inspected:

- Repository: `/Users/arthur/Documents/rusty-kaspa-toccata`
- Current checked-out branch: `toccata`
- Toccata commit inspected: `0ae28f93`

## Evidence Found

1. Target branch/profile: local `toccata` checkout points at commit `0ae28f93`.
2. `OP_CAT`: `crypto/txscript/src/opcodes/mod.rs` defines `OpCat`; covenant examples use `OpCat`.
3. Transaction introspection: `crypto/txscript/src/opcodes/mod.rs` defines input, output, payload, outpoint, locktime, amount, script-public-key, and covenant introspection opcodes.
4. `CHECKSIGFROMSTACK`: `crypto/txscript/src/opcodes/mod.rs` defines `OpCheckSigFromStack` and `OpCheckSigFromStackECDSA`.
5. Hashlock enforcement: `OpSHA256`, `OpBlake2b`, `OpBlake3`, and equality verification are present in the script engine source.
6. Timelock/refund enforcement: `OpCheckLockTimeVerify` and `OpCheckSequenceVerify` are present in the script engine source.
7. Covenant-style output constraints: `CovenantsContext`, covenant IDs, authorised output indices, covenant input/output counts, and output covenant IDs are present.

## Runtime Evidence Exercised Here

- `evidence/kaspa-simnet-probe.log`: `kaspad` starts on simnet with unsynced mining enabled.
- `evidence/kaspa-txscript-covenants.stdout.log`: the Toccata covenant VM example accepts monotonic covenant spends and rejects non-incrementing spends.
- `evidence/kaspa-daemon-compute-budget-relay.stdout.log`: the local Toccata daemon integration accepts a live transaction into relay/mining flow.
- `evidence/kurrent-live-state-channel-evidence.json`: Kurrent creates and mines live simnet funding, state-update, and state-2 settlement transactions, and records a rejected stale/non-continuing spend.
- `evidence/kurrent-live-factory-evidence.json`: Kurrent creates and mines live factory funding and materialisation transactions.
- `evidence/kurrent-live-ln-to-kaspa-evidence.json`: Kurrent consumes the observed Lightning Network invoice preimage in a live Kaspa hashlock settlement transaction.
- `evidence/kurrent-live-kaspa-to-ln-evidence.json`: Kurrent exercises the reverse-direction hashlock funding and settlement path on live Kaspa simnet.
- `evidence/kurrent-live-refund-evidence.json`: Kurrent records live early-refund rejection and matured refund acceptance.

## Evidence Boundary

The local devnet acceptance gate is exercised. This repository still does not claim mainnet readiness, public Lightning routing, unattended operations, or native LN route-hop integration.

## Acceptance Impact

The capability audit supports the current local `passed` verdict: all required local business-flow scripts exercise the relevant capabilities through real devnet evidence.
