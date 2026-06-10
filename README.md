# Kurrent Protocol

Kurrent Protocol is a Kaspa-native latest-state state-channel and local channel-factory protocol for local development and devnet acceptance work. Its settlement model is non-punitive and latest-state oriented, with Eltoo as intellectual lineage. Lightning Network interoperability is limited to atomic hash/preimage settlement.

This repository does not claim mainnet readiness. The current local devnet verdict is `passed`: real Kaspa and Lightning Network tooling is available and exercised, and every required local business flow now emits raw transaction, witness, txid, preimage, log, and verifier evidence.

## Target Profile

- Protocol version: `KURRENT_STATE_V1` family of domain separators.
- Target Kaspa source profile inspected locally: `/Users/arthur/Documents/rusty-kaspa-toccata`, branch `toccata`, commit `0ae28f93`.
- Capabilities found in local source: `OpCat`, transaction introspection opcodes, covenant IDs, authorised-output covenant context, `OpCheckSigFromStack`, hash opcodes, and locktime/sequence verification.
- Capabilities exercised locally: Kaspa simnet node startup, Toccata txscript covenant VM execution, live Toccata daemon transaction relay/mining integration, real Lightning Network invoice payment with observed preimage, and Kurrent-originated live Kaspa covenant state-channel, factory, hash/preimage, and refund transactions with raw txids and witness artefacts.
- Capabilities not claimed by this repository: mainnet readiness, native Lightning route-hop integration, public routing, or unattended production operations.

## Quickstart

```sh
./scripts/check.sh
```

The command checks Rust formatting, runs strict Clippy and tests, detects the required external tooling, runs the real Kaspa and Lightning Network probes, verifies evidence files by path and hash, and writes `evidence/kurrent-acceptance.json`. In the present environment it exits zero and records status `passed`.

## Replay

```sh
cargo test
./scripts/detect-tools.sh
./scripts/check.sh
```

## Evidence

- Acceptance report: `evidence/kurrent-acceptance.json`
- Tool detection: `evidence/tool-detection.json`
- Kaspa simnet probe: `evidence/kaspa-simnet-probe.log`
- Toccata covenant VM transcript: `evidence/kaspa-txscript-covenants.stdout.log`
- Toccata live daemon relay/mining transcript: `evidence/kaspa-daemon-compute-budget-relay.stdout.log`
- Lightning Network invoice and preimage evidence: `evidence/ln-devnet-evidence.json`
- Kurrent live Kaspa funding/settlement evidence: `evidence/kurrent-live-state-channel-evidence.json`
- Interaction-safety audit: `docs/KURRENT_INTERACTION_SAFETY_AUDIT.md`
- Blocker notes: `docs/KURRENT_BLOCKERS.md`
- Delivery summary: `docs/DELIVERY_SUMMARY.txt`

## Claims

This repository currently proves the Rust protocol model plus selected real Kaspa and Lightning Network devnet capabilities. It does not claim native Lightning Network route-hop integration, mainnet readiness, or a completed public routing network. A `passed` verdict is only valid after every required Kurrent business flow produces real raw transaction, witness, txid, preimage, log, and verifier evidence and `./scripts/check.sh` exits zero.
