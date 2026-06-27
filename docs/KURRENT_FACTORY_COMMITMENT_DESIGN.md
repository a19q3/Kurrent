# Kurrent Factory Commitment Design Boundary

Status: design boundary

## Scope

This note records the boundary between the implemented Kurrent factory evidence
path and the future compressed factory commitment design referenced by the
thesis.

The current implementation is a local-devnet and typed-model materialisation
check. It verifies a complete `FactoryState` before and after a materialisation
plan, recomputes principal conservation over the full virtual-channel set, checks
that the touched virtual channel is removed, rejects double materialisation, and
rejects mutation or injection of untouched virtual channels.

That is useful evidence for the invariants a production factory must satisfy,
but it is not a production compressed factory commitment.

## Current Evidence Path

The implemented path uses full-state recomputation:

- the verifier sees every active virtual channel in the pre-state;
- the verifier sees the complete post-state;
- the materialisation plan names the touched virtual channel and amount;
- principal conservation is checked with overflow-safe arithmetic;
- untouched leaves must remain byte-for-byte stable;
- the materialised channel id is recorded so the same materialisation cannot be
  replayed.

This path is intentionally conservative for model testing. It makes invariant
violations visible without pretending that a compact on-chain proof object has
already been specified.

## Future Compressed Commitment Requirements

A production compressed factory design must replace full-state recomputation
with a commitment and proof system. At minimum it must specify:

- a canonical leaf encoding for every virtual channel;
- range-constrained balances and explicit fixed-width arithmetic;
- unique virtual-channel identifiers and canonical ordering;
- a Merkle-sum, aggregate, or equivalent principal-bearing commitment;
- membership proofs for touched leaves;
- non-membership or update-authentication rules for absent and newly inserted
  leaves;
- preservation proofs for untouched leaves;
- update authorisation rules for factory state transitions;
- unilateral exit behaviour when participants are unavailable;
- proof-size, verification-cost, and denial-of-service bounds;
- binding between proof public inputs, the spent factory output, successor
  factory output, settlement output, factory id, and covenant lineage.

Until those items exist, production-readiness evidence may claim only local
model-level materialisation safety, not a production compressed factory.

## Relationship To Current Gates

The current production-readiness gate treats the factory surface as evidence for
local materialisation invariants. It does not discharge:

- compressed commitment soundness;
- consensus-level proof verification;
- unavailable-data recovery;
- factory update protocol safety;
- production fee-market or bounded-inclusion assumptions.

An external security review may review this boundary and the implemented
materialisation model, but it cannot convert the future compressed factory into
implemented production functionality without a corresponding protocol and code
slice.
