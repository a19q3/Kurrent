# Prompt Audit And Optimised Execution Brief

## Audit

The source prompt is appropriately strict about evidence: it forbids simulated success and requires real Kaspa devnet artefacts, real transaction/script/witness data, and real Lightning Network hash/preimage evidence. The critical risk is that it asks for production acceptance even when the local environment may not contain the required node and payment tooling.

The prompt therefore needs one operational refinement: execution must be blocker-gated. The repository may implement local protocol objects, local validation rules, and acceptance scaffolding, but the final verdict may only be `passed` when the real external flows run. The current local suite satisfies that gate.

## Optimised Execution Brief

1. Configure the Kurrent Git remote.
2. Update the available local Kaspa source checkout, or clone the Toccata checkout into the parent folder when missing.
3. Inspect the local Kaspa Toccata source for script and covenant capability evidence.
4. Implement serialisable Kurrent protocol objects and local rejection checks.
5. Add acceptance scripts that fail non-zero when real external tooling or Kurrent-originated transaction evidence is absent.
6. Generate a truthful acceptance report with exact blockers.
7. Never report `passed` unless the full real devnet suite succeeds.

This is the execution path used in this repository.
