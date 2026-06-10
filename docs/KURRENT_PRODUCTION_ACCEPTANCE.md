# Kurrent Production Acceptance

There is one acceptance gate:

```sh
./scripts/check.sh
```

The only successful verdict is `passed`. It may be reported only if every required business flow runs against real local devnet tooling and the check script exits zero.

Current expected verdict: `passed` in the present local environment. The suite executes real Kaspa and Lightning Network capability probes and every required Kurrent business flow passes against local devnet tooling.

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

Any non-zero code means the verdict is `failed/blocked`.
