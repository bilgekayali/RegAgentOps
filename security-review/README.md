# Security Review Evidence

The `v1.0.0` tagged-release workflow requires a completed independent review artifact at:

`security-review/v1.0-review.json`

The file must conform to `schemas/independent-security-review-checklist.schema.json` and the requirements documented in `docs/SECURITY_REVIEW.md`.

A completed file is deliberately **not** pre-populated in the repository. Do not copy a synthetic example and present it as an independent review.

If one or more checklist items are not technically closed, they may only use `risk_accepted` when an accountable human has explicitly accepted that specific residual risk and the artifact binds the corresponding risk-acceptance evidence digest.
