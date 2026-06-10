# Kurrent Interaction Safety Audit

Current verdict: `passed` for the local devnet gate after the interaction-safety model expansion.

This audit covers the model-level interaction safety of every business flow currently accepted by `./scripts/check.sh`. It is intentionally narrower than mainnet production security: it proves local protocol invariants, live devnet evidence, and evidence verification, but it does not claim public routing, unattended operations, or mainnet readiness.

## State Channel

Implemented safety checks:

- state headers must use `KURRENT_STATE_V1`;
- protocol version, network profile, devnet id, channel id, funding outpoint, script hash, participant set hash, and settlement template hash must match the configured channel and funding state;
- participant balances must cover exactly the configured participant set and conserve funding principal;
- participant signatures must come from authorised participants and meet the required threshold;
- state numbers must advance exactly one step;
- `previous_state_commitment` must match the latest accepted commitment;
- same-number conflicting commitments are rejected;
- stale settlement is rejected after a newer state is accepted.

Live evidence:

- `evidence/kurrent-live-state-channel-evidence.json`;
- `evidence/kurrent-live-state-update-tx.hex`;
- `evidence/kurrent-live-stale-rejected-tx.hex`;
- `evidence/kurrent-live-settlement-tx.hex`;
- corresponding witness and redeem-script files.

## Factory Materialisation

Implemented safety checks:

- factory id and virtual channel id must match;
- duplicate materialisation is rejected;
- principal inputs and fee inputs must be disjoint;
- the touched virtual channel must leave the active factory set after materialisation;
- materialised principal must equal the touched virtual channel principal;
- consumed fee must equal the factory fee reserve consumed by the plan;
- output sum must equal materialised principal plus fee;
- untouched virtual channels must remain byte-for-byte unchanged;
- aggregate principal and fee conservation must hold.

Live evidence:

- `evidence/kurrent-live-factory-evidence.json`;
- `evidence/kurrent-live-factory-funding-tx.hex`;
- `evidence/kurrent-live-factory-materialisation-tx.hex`;
- factory witness and redeem-script files.

## LN To Kaspa And Kaspa To LN

Implemented safety checks:

- LN preimage must hash to the invoice payment hash;
- hex-encoded LND preimages are hashed as decoded bytes;
- swap direction must be one of `ln-to-kaspa` or `kaspa-to-ln`;
- amount, recipient, and script hash must be present;
- receipt hash must be fresh after adding swap id and direction;
- receipt protocol version, network profile, funding outpoint, settlement outpoint, script hash, swap id, and direction must match the swap evidence;
- receipt replay across direction, network, swap id, outpoint, or script scope is rejected.

Live evidence:

- `evidence/ln-devnet-evidence.json`;
- `evidence/kurrent-live-ln-to-kaspa-evidence.json`;
- `evidence/kurrent-live-kaspa-to-ln-evidence.json`;
- both hashlock settlement transaction, witness, and redeem-script files.

## Refund

Implemented safety checks:

- refund before required DAA maturity is rejected;
- refund at maturity is accepted;
- settlement and refund are mutually exclusive for the same claim;
- scoped claim keys bind network profile, funding outpoint, output id, and claim subject;
- claim scopes do not collide across different funding outputs.

Live evidence:

- `evidence/kurrent-live-refund-evidence.json`;
- `evidence/kurrent-live-early-refund-rejected-tx.hex`;
- `evidence/kurrent-live-refund-tx.hex`;
- refund witness and redeem-script files.

## Evidence Verifier

Implemented safety checks:

- the aggregate status must be `passed` and blockers must be empty;
- all six business-flow statuses must be `passed`;
- required state/factory/refund outpoints and virtual channel identifiers must be present;
- raw transaction, script, witness, flow JSON, and LN evidence records are checked by path and SHA-256 hash;
- hex artefacts are decoded before hashing, so the recorded hashes refer to transaction/script/witness bytes rather than display text;
- command transcripts must exist.

## Remaining Boundary

The audit does not claim:

- mainnet readiness;
- public Lightning Network routing;
- native LN route-hop integration;
- adversarial long-running mempool coverage;
- production key-management, monitoring, or unattended recovery.

Those are outside the current local devnet acceptance gate and must remain separate production-readiness work.
