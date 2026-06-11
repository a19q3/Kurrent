# Kurrent Security Assumptions

The local model assumes:

- participant sets are committed by hash;
- settlement templates are committed by hash;
- script/covenant logic is committed by hash;
- state updates bind protocol version, network profile, devnet id, channel id, funding outpoint, script hash, participant set, settlement template, balances, and authorised Schnorr signatures over the canonical state-update signing payload;
- channel receipts bind enough scope to prevent replay across protocol version, network/profile, funding outpoint, settlement output, script hash, swap id, and direction;
- receipt hashes are refreshed after scope mutation and rejected when stale;
- a refund and a settlement are mutually exclusive claims for the same scoped network/funding/output/claim subject;
- factory materialisation must remove the touched virtual channel from the active set and preserve untouched virtual channels.

The following assumptions are discharged by the local devnet acceptance evidence:

- Kaspa node policy accepts the required scripts;
- Toccata-era opcodes are active in the target local profile;
- transaction witnesses execute exactly as expected;
- Lightning Network tooling reveals the preimage through a real payment flow.
