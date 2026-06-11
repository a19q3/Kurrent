# Kurrent Blockers

Current local-devnet verdict: `passed`.

Current production-readiness verdict: `failed/blocked`.

## Blocking Items

None for the local devnet acceptance gate.

Production-readiness blockers are tracked by:

```sh
./scripts/verify-production-readiness.sh
```

The production target profile is now present at `evidence/production/target-profile.json`.

The semantic transaction verifier evidence is now present at `evidence/production/semantic-transaction-verifier.json`.

The deterministic adversarial soak evidence is now present at `evidence/production/adversarial-mempool-soak.json`.

The external-review request package can be generated at `evidence/production/security-review-request.json`.

The production runbooks for key management, monitoring, incident recovery, and rollout/rollback are now present under `docs/PRODUCTION_*.md`.

The required production evidence still missing is: independent security review evidence.

## Next Smallest Step

For further hardening, complete the production-readiness evidence pack while preserving the local-devnet replay command:

```sh
./scripts/check.sh
```
