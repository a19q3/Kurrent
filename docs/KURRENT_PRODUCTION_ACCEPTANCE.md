# Kurrent Acceptance Gates

There are two separate gates.

## Local Devnet Acceptance

```sh
./scripts/check.sh
```

The only successful local-devnet verdict is `passed`. It may be reported only if every required business flow runs against real local devnet tooling and the check script exits zero.

The command writes a complete combined stdout/stderr transcript for the acceptance run:

```sh
evidence/acceptance-logs/latest.log
```

For a fixed log file name, run:

```sh
KURRENT_ACCEPTANCE_LOG_PATH="$PWD/evidence/acceptance-logs/manual-local-devnet.log" ./scripts/check.sh
```

Current expected local-devnet verdict: `passed` in the present local environment. The suite executes real Kaspa and Lightning Network capability probes and every required Kurrent business flow passes against local devnet tooling.

## Production Readiness

```sh
./scripts/verify-production-readiness.sh
```

The production-readiness gate is separate and stricter. It requires the local-devnet gate to pass and also requires explicit production evidence for target profile, semantic transaction verification, adversarial soak testing, key management, monitoring, incident recovery, rollout/rollback, and independent security review.

Current expected production verdict: `failed/blocked`. The target profile, semantic transaction verifier, deterministic adversarial soak, and production runbooks are present, but independent security-review evidence is not complete yet. The command writes `evidence/kurrent-production-readiness.json`.

The target profile, semantic verifier, adversarial soak, and security-review request package can be refreshed with:

```sh
./scripts/write-production-target-profile.sh
./scripts/run-semantic-transaction-verifier.sh
./scripts/run-adversarial-soak.sh
./scripts/prepare-security-review-package.sh
```

The security-review request package does not satisfy the final gate. The final gate requires `evidence/production/security-review.json` with a passing independent-review schema, matching report and attestation file hashes, all required scope ids, zero open findings, and exact reviewed artefact hashes.

## Required Flows

- Kaspa state-channel flow.
- Kaspa local factory flow.
- Lightning Network to Kaspa atomic settlement.
- Kaspa to Lightning Network atomic settlement.
- Refund / timeout flow.
- Evidence-verifier flow.

## Blocker Codes

- `10`: external tooling unavailable.
- `11`: real state-channel flow failed.
- `12`: real factory flow failed.
- `13`: real Lightning Network to Kaspa flow failed.
- `14`: real Kaspa to Lightning Network flow failed.
- `15`: real refund flow failed.
- `16`: evidence verification failed.
- `17`: production-readiness evidence missing or failed.

Any non-zero code means the verdict is `failed/blocked`.
