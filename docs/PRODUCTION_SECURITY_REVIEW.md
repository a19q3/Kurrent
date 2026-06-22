# Production Security Review

Status: review brief

This brief defines the external review request. It is not a completed external
security review and cannot satisfy the final production gate.

## Scope

The external reviewer must cover the protocol design, latest-state safety
argument, Kaspa script and covenant constraints, participant signer model,
Lightning/Kaspa atomic-swap interop, refund and timeout safety, evidence
verification, and operational controls.

## Required Artefacts

The review package is generated with
`./scripts/prepare-security-review-package.sh`. The reviewer must use the
artefact list and hashes in `evidence/production/security-review-request.json`.
Any source, evidence, or runbook change after package generation requires a new
package and review update.

## Passing Evidence

The final evidence file must be written to
`evidence/production/security-review.json` with schema
`kurrent-security-review-v1`. It must identify the reviewer, attest
independence, cover all required scopes, contain at least three review methods,
report zero open critical/high/medium/low findings, and bind report plus signed
attestation file hashes.

## Non-Claims

This brief alone is only a request for review. A repository containing this
file but no completed `security-review.json` remains blocked for production.
