# RegAgentOps Architecture

## v1 boundary

RegAgentOps 1.0 is an **offline authorization, approval, MCP-governance, execution-evidence, data/purpose, assurance, tenant/cryptographic-hardening, production-reference and stability/release-readiness control plane**.

The v1 layer adds no autonomous deployment or tool-execution capability. It defines a stable public compatibility surface and a fail-closed release-evidence composition over the completed v0.1-v0.9 boundaries.

```text
                    EXECUTION CONTROL PLANE

OIDC + workload identity
          |
AgentActionEnvelope + PolicyBundle + MCP binding + DataUseDeclaration
          |
DataGovernanceDecision -> AuthenticatedAuthorizationDecision
          |
Human approval when required
          |
current MCP + data + emergency-stop checks
          |
one-time ExecutionLease -> external executor -> SignedToolExecutionReceipt

                    ASSURANCE / HARDENING

signed governance evidence -> human assurance crosswalk/package
PostgresRlsPolicy -> TenantIsolationProfile
KMS/HSM references -> signed configuration / AES-GCM evidence -> external anchor

                    PRODUCTION REFERENCE

current TenantIsolationProfile --+
EgressPolicy ---------------------+
ToolAllowlistPolicy ---------------+--> IsolatedPolicyWorkerProfile
                                         |
                                         v
                              DeploymentReleaseManifest
                          source/artifact/configuration
                          CodeQL/provenance/checksum evidence
                                         |
                              Upgrade / Rollback / Recovery

                    V1 STABILITY PLANE

StableCompatibilityPolicy ---> PublicSurfaceManifest
          |                         |
          |                 v1 API/CLI/schema baselines
          |
current exact 0.9.x release ---- SupportedUpgradePath ---- exact current 1.0 release
                                                        |
IndependentSecurityReviewChecklist + ResponsibilityScope
                                                        |
all v0.1-v0.9 boundary evidence -----------------------+
                                                        v
                                              StableReleaseBaseline
```

## Stable public surface

Only `regagentops.api` is the stable Python façade for major version 1. `compatibility/v1-public-api.json` pins the baseline exported symbols and stable CLI commands. `compatibility/v1-schema-baseline.json` pins the v1 JSON schema filenames and `schema_version` discriminators.

Internal modules remain transparent and importable, but they are implementation surfaces unless explicitly re-exported by `regagentops.api`.

`regagentops contract-snapshot` reports the stable runtime boundary without network access or execution.

## Stable compatibility semantics

`StableCompatibilityPolicy` requires semantic versioning and treats removal of stable Python symbols, stable CLI commands or baseline JSON contract semantics as breaking changes requiring a new major version. Public deprecations remain for at least two minor releases before removal.

Fail-closed security corrections are not required to preserve an unsafe bypass merely for compatibility.

## Supported v0.9.x → 1.0 path

`SupportedUpgradePath` binds the **exact source `DeploymentReleaseManifest` digest** from final 0.9.x and exact target 1.0 `DeploymentReleaseManifest` digest, together with migration, preflight, post-upgrade, rollback and backup requirements.

`StableReleaseRegistry` consumes the existing `ProductionDeploymentRegistry` and verifies both releases through `assert_release_current()`. Syntactically valid but stale release digests therefore cannot establish stable eligibility.

## Independent-review boundary

`IndependentSecurityReviewChecklist` requires twelve review areas in canonical order. Each item is either:

- `closed`, with exact review evidence and reviewer rationale; or
- `risk_accepted`, with those digests plus an accountable-human identity and exact risk-acceptance evidence digest.

`reviewer_independence_confirmed=true` is an explicit assertion supplied by the reviewer. RegAgentOps does not infer or fabricate reviewer independence.

A normal PR approval is not treated as independent review or item-level risk acceptance.

## Legal/accessibility responsibility boundary

`LegalAccessibilityResponsibilityScope` structurally retains the v1 non-claims. It cannot claim legal advice, regulatory compliance determination, certification/conformity or accessibility conformance. Institution-owned legal, privacy, accessibility, retention, jurisdiction-role and production-IAM reviews remain required.

## Stable release baseline

`StableReleaseBaseline` binds:

- exact compatibility policy;
- exact public surface;
- exact current 1.0 production release;
- exact supported upgrade path;
- exact independent security review;
- exact responsibility scope;
- exact reproducible checksum/provenance evidence; and
- one exact evidence reference for every v0.1-v0.9 governance boundary.

The nine boundary references are ordered: authorization, authenticated identity, human approval, MCP governance, execution receipts, data/purpose, assurance, tenant/crypto and production reference. The production-reference boundary must equal the exact 1.0 release manifest digest.

## Chronology

Stable baseline registration enforces monotonic provenance:

```text
0.9.x source release <= 1.0 target release
compatibility policy <= public surface
source + target release <= supported upgrade path
target release <= independent security review
all readiness evidence <= stable baseline assembly
```

This prevents a represented stable baseline from being backfilled with a later review or upgrade plan.

## Current eligibility versus historical evidence

A registered stable baseline remains immutable historical evidence. Current stable eligibility is a separate check through `StableReleaseRegistry.assert_baseline_current()`.

That currentness method verifies the exact registered stable baseline and revalidates both source and target production releases. Production drift in worker, egress, tool allowlist or tenant isolation therefore invalidates current stable eligibility without deleting historical evidence.

## Reproducible release and provenance

The release workflow builds the wheel twice from the same Git tree with the same `SOURCE_DATE_EPOCH`; both SHA-256 values must match before `SHA256SUMS` is produced. Tagged release artefacts are then eligible for GitHub artifact attestation.

For `v1.0.0`, the tag job additionally requires a genuine `security-review/v1.0-review.json`. The repository intentionally does not ship a fabricated completed review.

## Production-reference controls retained

v0.9 remains the deployment-evidence substrate:

- `IsolatedPolicyWorkerProfile`: network namespace isolation, non-root, read-only root, no-new-privileges, capability drop, `RuntimeDefault` seccomp, no host namespaces, no direct invocation;
- `EgressPolicy`: exact default-deny TLS/HTTPS endpoints, canonical IP identity, no wildcards/plaintext;
- `ToolAllowlistPolicy`: exact default-deny governed-tool→executor bindings;
- `DeploymentReleaseManifest`: source, artifact, worker/configuration, CodeQL, provenance and checksum evidence;
- `assert_release_current()`: current worker/egress/tool/tenant-isolation dependency check; and
- exact upgrade/rollback/recovery evidence.

## Authorization remains separate

The stability plane cannot create `ALLOW`, satisfy human approval, issue or consume an execution lease, bypass emergency stop or widen data/MCP authority.

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

## Capability separation

`stability.py` and `deployment.py` contain no deployment/network/process/tool-execution interface. Generic CI and the dedicated Stable Governance Reference Boundary statically reject capability creep.

Actual databases, container runtimes, network controls, KMS/HSM operations, executors, backup platforms and external immutable services remain accountable external systems.

## Trust boundaries

1. caller → authenticated identity/policy;
2. institution governance → MCP/data/approval registries;
3. authenticated authorization → approval/execution;
4. database/KMS/HSM/external anchor → hardening evidence;
5. tenant-isolation registry → production deployment registry;
6. network/executor/container platforms → egress/tool/worker reference controls;
7. build/security pipeline → release evidence;
8. exact v0.9/1.0 release manifests → supported upgrade path;
9. independent reviewer/accountable risk owner → security-review evidence;
10. institution legal/accessibility functions → responsibility review; and
11. v0.1-v0.9 evidence planes → stable release baseline.

## Non-claim posture

Stable compatibility means the defined public contract is versioned and release evidence is composed fail-closed. It does **not** mean the repository independently proves production fitness, regulatory compliance, certification, accessibility conformance, deployed RLS effectiveness, KMS/HSM hardware custody, backup restorability or external-anchor immutability.
