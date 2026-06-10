# Kurrent Scope

Kurrent Protocol is scoped to Kaspa-native latest-state state channels, local channel-factory materialisation, and Lightning Network atomic settlement interoperability.

The current repository contains:

- serialisable protocol objects for channel, factory, receipt, swap, evidence, and acceptance reporting;
- local model checks for state monotonicity, stale settlement rejection, materialisation uniqueness, fee/principal separation, conservation, preimage validation, refund maturity, and evidence hash verification;
- scripts that detect the real external tooling needed for production acceptance;
- real Kaspa simnet startup probing;
- real Toccata txscript covenant VM evidence;
- real Kaspa daemon relay/mining integration evidence;
- real Lightning Network invoice payment and preimage evidence;
- live Kurrent Kaspa simnet funding, state-update, stale-rejection, and state-2 settlement transaction evidence;
- live factory materialisation evidence;
- live Kaspa hash/preimage settlement evidence in both directions;
- live early-refund rejection and matured refund evidence;
- a blocker-first acceptance report path with per-flow evidence files.

The current repository contains a successful full local Kurrent devnet run. Mainnet readiness, public routing, and unattended production operation remain outside this local acceptance scope.
