# Threat Model — v1.0

## Protected assets

RegAgentOps v1 protects the earlier authorization, identity, approval, MCP, execution, data-purpose, assurance, tenant/crypto and production-reference assets plus these stable-release assets:

- stable `regagentops.api` symbol baseline;
- stable CLI command contract;
- v1 JSON schema/discriminator baseline;
- exact 0.9.x source and 1.0 target release linkage;
- independent-security-review identity/status/evidence integrity;
- item-level accountable-human risk-acceptance integrity;
- legal/accessibility responsibility-scope and non-claim integrity;
- reproducible checksum and provenance evidence;
- exact v0.1-v0.9 boundary-evidence composition;
- stable-baseline chronology; and
- distinction between historical baseline evidence and current stable eligibility.

## Trust boundaries

1. caller → identity/policy plane;
2. institution governance → policy/MCP/data/approval state;
3. authenticated authorization → external executor;
4. database/KMS/HSM/external anchor → tenant/crypto evidence;
5. tenant-isolation registry → production registry;
6. network/dispatch/container platform → production-reference policies;
7. build/security pipeline → release/checksum/provenance evidence;
8. exact production releases → supported upgrade path;
9. independent reviewer → security-review checklist;
10. accountable risk owner → item-level risk-acceptance evidence;
11. institution legal/privacy/accessibility/IAM functions → responsibility review; and
12. all v0.1-v0.9 evidence planes → stable release baseline.

## Primary v1 threats and controls

### Stable API erosion

Threat: a 1.x release silently removes or renames a documented Python integration point while retaining the same major version.

Controls: only `regagentops.api` is the stable façade; `compatibility/v1-public-api.json` pins exact baseline symbols; CI compares runtime `api.__all__` to the committed baseline. `StableCompatibilityPolicy` requires public-symbol removal to use a new major and requires at least two minor releases of deprecation before planned removal.

Residual boundary: direct imports from internal modules are intentionally not part of this guarantee unless re-exported by `regagentops.api`.

### CLI contract erosion

Threat: a stable CLI command disappears or changes purpose incompatibly inside 1.x.

Controls: the v1 baseline pins `contract-snapshot` and `demo-decision`; contract tests and clean-wheel smoke invoke the commands from the built wheel.

### JSON discriminator mutation

Threat: an existing v1 JSON contract is silently redefined under the same `schema_version` discriminator.

Controls: `compatibility/v1-schema-baseline.json` pins baseline filenames/discriminators; schemas remain Draft 2020-12 with `additionalProperties: false`; CI rejects missing/mutated baseline discriminators. Required-field/enum removals are structurally classified as major-version changes by the compatibility policy.

### Fake independent review

Threat: automated code generation, a project author or a generic PR approval is represented as an independent security review.

Controls: `IndependentSecurityReviewChecklist` requires explicit `reviewer_id` and `reviewer_independence_confirmed=true`. The repository deliberately omits a completed `security-review/v1.0-review.json`. The tagged `v1.0.0` release workflow fails closed without that file.

Residual boundary: the software cannot independently prove that a human who asserts independence is genuinely organizationally independent; this remains an accountable governance fact.

### Blanket risk-acceptance laundering

Threat: unresolved findings are hidden under a generic project approval or single blanket acceptance.

Controls: each of twelve required review items has its own status, evidence and rationale. `risk_accepted` additionally requires an accountable-human identity and exact risk-acceptance digest; `closed` forbids risk-acceptance fields. Generic PR merge approval is not reinterpreted as risk acceptance.

### Missing review coverage

Threat: a favorable review package omits a difficult boundary.

Control: the checklist requires exactly twelve canonical review areas covering authorization, identity, approval, MCP, execution, data-purpose, assurance/nonclaims, tenant/crypto, production, provenance, capability creep and upgrade/recovery.

### Upgrade source/target substitution

Threat: a document says “0.9.x → 1.0” while actually evaluating or deploying different release artefacts.

Controls: `SupportedUpgradePath` binds exact source and target `DeploymentReleaseManifest` digests. Stable registration requires source version 0.9.x, target version 1.0.0, exact digest equality and currentness checks through the production registry.

### Stale release promoted as stable

Threat: a previously valid 1.0 release is treated as stable-ready after worker, egress, tool or tenant-isolation state changes.

Controls: first baseline registration requires current source and target production releases. `assert_baseline_current()` separately revalidates current eligibility later without destroying the immutable historical baseline.

### Stable-baseline backdating

Threat: review, upgrade or responsibility evidence is created after the claimed stable baseline and retroactively attached.

Controls: registry chronology requires target release after source release, public surface after compatibility policy, upgrade path after exact source/target releases, independent review no earlier than the exact 1.0 target release, and stable baseline assembly no earlier than every bound readiness artefact.

Residual boundary: application timestamps are evidence, not an independent trusted timestamp authority.

### Provenance/checksum substitution

Threat: the stable baseline references provenance or checksum evidence from another artifact.

Controls: baseline provenance and reproducible-checksum digests must exactly equal the target production release evidence. The release workflow builds twice under the same `SOURCE_DATE_EPOCH`, requires identical wheel SHA-256 values, then attests the wheel/checksum manifest only on version-matching tags.

Residual boundary: reproducibility in the workflow environment does not prove all future external toolchains reproduce bytes; provenance does not prove code is safe.

### Missing governance boundary

Threat: stable status is assembled from only the newest deployment evidence while omitting an earlier authorization/identity/approval control plane.

Control: `StableReleaseBaseline` requires exactly nine ordered v0.1-v0.9 boundary references. The production-reference entry must equal the exact target release manifest digest.

### Stable/compliant/accessible overclaim

Threat: the word “stable” is interpreted as certification, regulatory compliance, accessibility conformance or production fitness.

Controls: `LegalAccessibilityResponsibilityScope` structurally sets legal-advice, compliance-determination, certification and accessibility-conformance claims to false and requires institution-owned legal/privacy/accessibility/retention/jurisdiction/IAM review. Exact v1 non-claims are contract data.

### Security fix blocked by compatibility policy

Threat: an exploitable behavior is retained because changing it might inconvenience a 1.x consumer.

Control: compatibility documentation explicitly allows fail-closed patch-level tightening when preserving behavior would maintain a security bypass. SemVer stability is not an obligation to preserve unsafe behavior.

### Stability plane becomes release/deployment authority

Threat: stable evidence types acquire GitHub, shell, network, deployment or tool-execution capabilities.

Controls: `stability.py` is metadata/evidence-only. Generic CI and Stable Governance Reference Boundary statically reject network/process/deploy/invoke/tag/release capability markers. Tagged release actions remain external GitHub workflow operations.

## Production-reference threats retained

v0.9 controls remain active:

- wildcard/plaintext/non-canonical endpoint expansion;
- cross-tenant egress/tool/tenant-isolation substitution;
- policy-worker privilege escalation;
- stale worker or backdated worker/release evidence;
- release source/artifact/configuration/CodeQL/provenance/checksum substitution;
- stale release after policy/RLS drift;
- version rollback disguised as upgrade;
- rollback that does not exactly reverse an upgrade;
- recovery checkpoint substitution; and
- deployment metadata treated as execution authority.

`ProductionDeploymentRegistry.assert_release_current()` remains the v1 substrate for worker/egress/tool/tenant-isolation currentness.

## Earlier threats retained

All v0.2-v0.8 identity, approval replay/delegation, MCP server/tool binding, data-purpose under-reporting, execution freshness/one-time lease, emergency-stop, signed-receipt, assurance non-certification, RLS, KMS/HSM lifecycle, configuration-chain, AES-GCM and audit-anchor controls remain in scope.

## Supply-chain configuration risk

GitHub Actions and CodeQL workflow files are privileged build configuration. A malicious workflow change could weaken analysis, reproducibility or tag blockers.

Controls include version-controlled workflows, CodeQL `security-extended`, dedicated stability/release gates, exact workflow marker checks and reviewable permissions. Repository branch-protection and organizational GitHub administration remain external requirements.

## Residual risks

- reviewer independence is asserted, not cryptographically proven by RegAgentOps;
- risk acceptance can still be poor governance if the accountable human makes an unsound decision;
- CodeQL can miss vulnerabilities and provenance can faithfully attest vulnerable code;
- external runtime/container/database/network/KMS/HSM controls can be misconfigured despite correct reference artefacts;
- backup restorability, RTO/RPO and regional failover remain external operational facts;
- in-memory governance/deployment/stability registries and local SQLite approval/execution ledgers remain reference state rather than a distributed production datastore; and
- legal, regulatory and accessibility conclusions require qualified institution-specific review.

## Explicit non-claims

RegAgentOps 1.0 does not provide or claim:

- production deployment/orchestration or direct tool invocation by the governed core;
- live firewall/CNI/service-mesh/PostgreSQL enforcement verification;
- actual KMS/HSM hardware-custody proof;
- external-anchor immutability proof;
- CodeQL zero-vulnerability assurance;
- universal reproducible-build proof outside the defined workflow;
- backup restorability or RTO/RPO attainment proof;
- independent-review authenticity beyond the supplied assertion/evidence;
- legal advice, regulatory compliance determination, certification/conformity assessment or accessibility conformance; or
- production fitness.
