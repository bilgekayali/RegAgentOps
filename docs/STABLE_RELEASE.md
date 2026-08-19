# Stable Release Baseline

RegAgentOps v1 separates **code/contract readiness** from **tagged stable-release eligibility**.

A source branch can contain the complete 1.0.0 implementation and pass all ordinary regression/security gates without implying that an independent human security review has occurred. The `v1.0.0` tag path is intentionally stricter.

## StableReleaseBaseline

`StableReleaseBaseline` is an offline evidence artifact that binds:

- the exact v1 compatibility-policy digest;
- the exact public-surface manifest digest;
- the exact current `DeploymentReleaseManifest` for 1.0.0;
- the exact supported-upgrade-path digest from a final 0.9.x release;
- the exact independent-security-review checklist digest;
- the exact legal/accessibility responsibility-scope digest;
- the exact reproducible checksum-manifest digest;
- the exact provenance-attestation digest; and
- one evidence reference for every governance boundary delivered from v0.1 through v0.9.

The required boundary order is:

1. authorization;
2. authenticated identity;
3. human approval;
4. MCP governance;
5. signed execution receipts;
6. data and purpose governance;
7. assurance evidence;
8. tenant/cryptographic hardening; and
9. production reference deployment.

The production-reference boundary evidence must bind the exact 1.0 `DeploymentReleaseManifest`.

## Currentness

`StableReleaseRegistry` consumes the existing v0.9 `ProductionDeploymentRegistry`. It refuses to register a new stable baseline when either the exact 0.9.x source release or the exact 1.0 target release is no longer current under the production registry's worker/egress/tool/tenant-isolation checks.

The stable registry does not deploy a workload, create a Git tag, publish a package or contact GitHub. It is an evidence/readiness boundary only.

## Reproducible wheel gate

The release-provenance workflow performs two wheel builds from the same Git tree with `SOURCE_DATE_EPOCH` set to the commit timestamp. The two wheel SHA-256 values must be identical before a final wheel is copied into the release-artifact directory and `SHA256SUMS` is generated.

This is a reproducibility check for the repository's wheel build under the workflow environment. It is not a proof that arbitrary third-party toolchains, future operating systems or unpinned external package indexes will reproduce bytes forever.

## Provenance

On a version-matching `v*` tag, the release workflow produces GitHub artifact attestations for the wheel and `SHA256SUMS`. The attestation represents build provenance; it is not a statement that the code is vulnerability-free, regulator-approved or fit for a particular deployment.

## v1.0.0 review blocker

The `v1.0.0` tag job requires `security-review/v1.0-review.json`.

That file must satisfy the v1 independent-security-review contract:

- `reviewer_independence_confirmed` is true;
- all twelve required items are present in canonical order;
- every item is `closed` or `risk_accepted`;
- a `risk_accepted` item carries an accountable human identity and exact risk-acceptance evidence digest; and
- a `closed` item does not masquerade as a risk acceptance.

The repository intentionally does not ship a fabricated completed review file. A real independent reviewer or an accountable human risk-acceptance decision must supply the evidence before the stable tag is eligible.

## Stable does not mean production certification

The word **stable** refers to the defined public compatibility and release-evidence boundary. It does not claim production fitness, regulatory compliance, legal sufficiency, accessibility conformance, PostgreSQL RLS non-bypassability, KMS/HSM hardware custody, external-anchor immutability or autonomous executor safety.
