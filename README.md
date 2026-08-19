# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, reviewing, crosswalking, cryptographically hardening and production-scoping AI-agent governance evidence before and after enterprise actions.

Source package version: **1.0.0 — Stable Governance Reference**.

> **Release-readiness note:** the v1 code/contract boundary can be technically complete and merge-ready without implying that an independent human security review has occurred. The `v1.0.0` tagged-release workflow remains fail-closed until a genuine `security-review/v1.0-review.json` artefact is supplied.

## What RegAgentOps controls

RegAgentOps addresses five bounded questions:

> Under which authenticated identity, purpose, data-governance profile, policy, tool, delegated authority, human approval, governed MCP, emergency-stop and one-time execution conditions may an AI agent continue toward a specific enterprise action?

> Which human-confirmed assurance references and exact evidence digests apply to one AI-system/deployment scope, and where are the evidence gaps?

> Which exact tenant/RLS/key/configuration/encryption/audit-anchor artefacts must a production adapter bind?

> Which worker-isolation, egress/tool-allowlist, release-provenance, rollback/upgrade and recovery artefacts must be current before a production controller may promote a release?

> Which Python API, CLI and JSON-contract surfaces are stable in major version 1, and which evidence is required before a `v1.0.0` release may be treated as stable-tag eligible?

The project is **not** an autonomous agent framework, credential broker, generic MCP proxy, DLP scanner, legal rules engine, certification body, production orchestrator, KMS/HSM client, firewall manager, immutable-log service, accessibility-certification service or compliance-determination product.

## Control planes

```text
AUTHORIZATION / EXECUTION
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

ASSURANCE
existing governance/evidence -> AssuranceScope
          |
human applicability -> exact evidence crosswalk -> AssuranceEvidencePackage

TENANT / CRYPTO
PostgreSQL RLS refs + tenant profile
KMS/HSM refs + one-way lifecycle
signed config changes + AES-256-GCM evidence + external anchors

PRODUCTION REFERENCE
current tenant isolation + exact default-deny egress/tool policy
          |
isolated non-invoking policy-worker profile
          |
DeploymentReleaseManifest
(source + artifact + CodeQL + provenance + checksum)
          |
upgrade <-> exact rollback + recovery checkpoint

V1 STABILITY / RELEASE READINESS
compatibility policy + public surface + schema baseline
          |
exact current 0.9.x source -> exact current 1.0.0 target
          |
independent review + responsibility scope
          |
all v0.1-v0.9 boundary evidence
          |
StableReleaseBaseline
```

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

Assurance, hardening, deployment and stability artefacts never widen authorization or become tool-execution authority.

## v1 stable compatibility boundary

### Python

Only symbols re-exported by **`regagentops.api`** are covered by the v1 public Python compatibility guarantee. Internal modules remain inspectable/importable, but direct internal imports are not stable merely because they are accessible.

The exact baseline is committed in `compatibility/v1-public-api.json`.

### CLI

The stable v1 CLI commands are:

```bash
regagentops contract-snapshot
regagentops demo-decision
```

`contract-snapshot` outputs deterministic machine-readable version/API/CLI/schema-baseline information and performs no execution.

### JSON

`compatibility/v1-schema-baseline.json` pins the v1 schema files and `schema_version` discriminators. Within major version 1, baseline schemas cannot silently disappear or change discriminator. Breaking public-surface removals require a new major version; planned removals require at least two minor releases of deprecation.

See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Stable release baseline

`StableReleaseBaseline` binds:

- exact compatibility-policy and public-surface digests;
- exact current 1.0 `DeploymentReleaseManifest`;
- exact final 0.9.x → 1.0 upgrade-path evidence;
- exact independent-security-review checklist;
- exact legal/accessibility responsibility scope;
- exact reproducible checksum and provenance evidence; and
- evidence for all nine governance boundaries delivered from v0.1 through v0.9.

`StableReleaseRegistry` reuses `ProductionDeploymentRegistry` currentness. A stale worker, egress policy, tool allowlist or tenant-isolation profile makes current stable eligibility fail closed. Baseline chronology also prevents review/upgrade/release evidence from being backfilled after the represented stable baseline.

See [docs/STABLE_RELEASE.md](docs/STABLE_RELEASE.md) and [docs/UPGRADE_V1.md](docs/UPGRADE_V1.md).

## Independent security-review blocker

The v1 contract defines twelve required independent-review areas. Every item must be `closed` or explicitly `risk_accepted`; risk acceptance requires an accountable human identity and exact evidence digest.

The repository intentionally does **not** pre-populate a fake completed review. `v1.0.0` tagging remains blocked until `security-review/v1.0-review.json` is supplied by a genuine review/risk-acceptance process.

A PR merge approval is not silently interpreted as independent security review or item-level risk acceptance.

See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

## Reproducible build and provenance

The Release Provenance Gate builds the wheel twice from the same source with `SOURCE_DATE_EPOCH` set to the commit timestamp. Both wheel SHA-256 values must match before `SHA256SUMS` is generated.

Version-matching `v*` tagged releases use GitHub artifact attestations for the wheel and checksum manifest. Build provenance is supply-chain evidence, not proof that software is vulnerability-free or fit for a particular deployment.

## Legal and accessibility boundary

The v1 responsibility contract structurally states that RegAgentOps does not provide legal advice, determine regulatory compliance, claim certification/conformity, or claim accessibility conformance. Institutions remain responsible for legal, privacy/data-protection, accessibility, records-retention, jurisdiction-role and production-IAM review.

See [docs/LEGAL_ACCESSIBILITY.md](docs/LEGAL_ACCESSIBILITY.md).

## v0.9 production-reference boundary retained

`IsolatedPolicyWorkerProfile` requires non-root execution, read-only root filesystem, no-new-privileges, all Linux capabilities dropped, `RuntimeDefault` seccomp, no privileged/host namespaces and no direct tool invocation.

`EgressPolicy` and `ToolAllowlistPolicy` are tenant-scoped and default deny. Worker registration resolves the exact current v0.8 tenant-isolation profile, exact current egress policy and exact current tool allowlist. `DeploymentReleaseManifest` binds semantic version, source commit, artifact digest, configuration/worker digest, CodeQL evidence, provenance and checksum evidence.

`assert_release_current()` fails closed after worker/egress/tool/tenant-isolation drift.

See [docs/PRODUCTION_REFERENCE.md](docs/PRODUCTION_REFERENCE.md).

## Earlier boundaries retained

- **v0.8 Tenant/Crypto:** PostgreSQL RLS reference DDL, tenant profiles, KMS/HSM-only references, one-way key lifecycle, signed configuration changes, tenant-scoped AES-GCM and audit anchoring. See [docs/TENANT_CRYPTO_HARDENING.md](docs/TENANT_CRYPTO_HARDENING.md).
- **v0.7 Assurance:** human-reviewed NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689 evidence mapping with explicit non-certification semantics. See [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md).
- **v0.6 Data/Purpose:** exact resource/data-use/purpose/output/retention controls. See [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).
- **v0.5 Execution Receipts:** short-lived executor-bound one-time leases, emergency stop and signed receipts. See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).
- **v0.4 MCP:** approved/pinned servers, bounded snapshots and explicit governed tool bindings. See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).
- **v0.3 Human Approval:** requester/approver separation, delegated authority, signatures and replay prevention. See [docs/APPROVALS.md](docs/APPROVALS.md).
- **v0.2 Identity:** offline pinned OIDC/JWKS verification and institution-signed workload/authenticated context. See [docs/IDENTITY.md](docs/IDENTITY.md).

## Quick start

```bash
python -m pip install -e .
regagentops --version
regagentops contract-snapshot
regagentops demo-decision
```

Both CLI commands are synthetic/offline and perform no enterprise tool execution.

## Repository map

```text
src/regagentops/
  api.py                       stable v1 Python façade
  stability.py                 stable compatibility/review/release baseline
  models.py                    authorization artefacts and digests
  authenticated_policy.py      identity-gated authorization
  approval_*.py                approval/delegation/signature/replay
  mcp.py                       governed MCP adapter
  execution.py                 one-time leases and signed receipts
  data_governance.py           data/purpose/output/retention governance
  assurance.py                 human-reviewed assurance crosswalks
  hardening.py                 tenant/RLS/key/config/encryption/anchor boundary
  deployment.py                production-reference deployment contracts
  cli.py                       offline CLI

compatibility/
  v1-public-api.json
  v1-schema-baseline.json

security-review/
  README.md                    real v1 review evidence location

schemas/
  ... v0.1-v0.9 contracts ...
  stable-compatibility-policy.schema.json
  public-surface-manifest.schema.json
  supported-upgrade-path.schema.json
  independent-security-review-checklist.schema.json
  legal-accessibility-responsibility-scope.schema.json
  stable-release-baseline.schema.json
```

## CI boundary

GitHub Actions tests Python 3.11/3.12/3.13, clean-wheel installation, all historical boundary regressions, CodeQL, release reproducibility/provenance and a dedicated **Stable Governance Reference Boundary**. The v1 compatibility gate compares runtime API/CLI/schema state to committed baselines.

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md), [docs/STABLE_RELEASE.md](docs/STABLE_RELEASE.md) and boundary-specific documents above.

## Explicit non-claims

RegAgentOps 1.0 does **not** by itself prove deployed RLS/firewall/container enforcement, actual KMS/HSM hardware custody, external anchor immutability, backup restorability, regulator acceptance, legal sufficiency, accessibility conformance, regulatory compliance, certification or production fitness. It also does not autonomously invoke enterprise tools from the governed core.

## License

Apache License 2.0. See [LICENSE](LICENSE).
