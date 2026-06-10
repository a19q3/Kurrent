# Kurrent Lightning Network Interoperability

Kurrent interoperability with the Lightning Network is scoped only to atomic hash/preimage settlement.

The local model supports:

- binding a swap id, direction, network/profile, amount, recipient, script hash, funding outpoint, settlement outpoint, payment hash, and preimage hash in `LnSwapEvidence`;
- validating that the preimage hashes to the expected payment hash;
- rejecting wrong preimages;
- rejecting receipt replay across direction, network/profile, or swap id.

Real local evidence now exists in `evidence/ln-devnet-evidence.json`: two local Lightning Network nodes open a channel, pay an invoice, and record the settled preimage. The Kurrent flow files bind that payment hash and preimage into swap receipt scopes, and the live Kaspa hashlock flows consume the observed preimage in settlement transactions.

No native Lightning Network route-hop integration is claimed. The local atomic hash/preimage interoperability gate passes.
