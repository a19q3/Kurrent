# Production Security Review Brief

Status: pending external review

This brief defines the final independent review evidence required before Kurrent can claim production readiness.

## Required Reviewer

- The reviewer must be external to the implementation work and must state any conflicts.
- The reviewer must provide name, organisation, contact, completion date, report file, and signed attestation file.
- The review evidence must be written to `evidence/production/security-review.json`.

## Required Scope

- `protocol_design`
- `state_channel_latest_state_safety`
- `kaspa_script_and_covenant_constraints`
- `participant_signer_model`
- `ln_kaspa_atomic_swap_interop`
- `refund_timeout_and_double_claim_safety`
- `evidence_verification_and_production_gates`
- `operational_controls_and_runbooks`

## Required Methodology

The review must include at least three concrete methods, including manual protocol review, script/covenant review, and replay of the production evidence gates.

## Required Artefacts

Generate the current artefact list with:

```sh
./scripts/prepare-security-review-package.sh
```

The command writes `evidence/production/security-review-request.json`, including exact paths and SHA-256 hashes that the final review evidence must cover.

## Passing Criteria

- `schema_version` is `kurrent-security-review-v1`.
- `status` is `passed`.
- `review_type` is `independent_external_security_review`.
- All required scope ids are present.
- Critical, high, medium, and low open finding counts are zero.
- `unresolved_blocking_findings` is empty.
- The report and signed attestation files exist and match their recorded SHA-256 hashes.
- The reviewed artefact hashes match the current generated request package.

This file is a brief, not the review itself. It must not be treated as production-passing evidence.
