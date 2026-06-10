# Kurrent Security Assumptions

The local model assumes:

- participant sets are committed by hash;
- settlement templates are committed by hash;
- script/covenant logic is committed by hash;
- channel receipts bind enough scope to prevent replay across network/profile, channel, output, state, swap id, and direction;
- a refund and a settlement are mutually exclusive claims for the same swap or channel state;
- factory materialisation must preserve untouched virtual channels.

The following assumptions are discharged by the local devnet acceptance evidence:

- Kaspa node policy accepts the required scripts;
- Toccata-era opcodes are active in the target local profile;
- transaction witnesses execute exactly as expected;
- Lightning Network tooling reveals the preimage through a real payment flow.
