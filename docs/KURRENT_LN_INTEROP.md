# Kurrent Lightning Network Interoperability

Kurrent interoperability with the Lightning Network is scoped only to atomic hash/preimage settlement.

The local model supports:

- binding a swap id, direction, network/profile, amount, recipient, script hash, funding outpoint, settlement outpoint, payment hash, and preimage hash in `LnSwapEvidence`;
- validating that the preimage hashes to the expected payment hash;
- rejecting wrong preimages;
- rejecting stale receipt hashes after scope mutation;
- rejecting receipt replay or mismatch across protocol version, direction, network/profile, swap id, funding outpoint, settlement outpoint, or script hash;
- rejecting zero-amount or empty-recipient swap evidence.

Real local evidence now exists in `evidence/ln-devnet-evidence.json`: two local Lightning Network nodes open a channel, pay an invoice, and record the settled preimage. The Kurrent flow files bind that payment hash and preimage into swap receipt scopes, and the live Kaspa hashlock flows consume the observed preimage in settlement transactions.

No native Lightning Network route-hop integration is claimed. The local atomic hash/preimage interoperability gate passes.
