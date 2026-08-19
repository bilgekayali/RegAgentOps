# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, reviewing, crosswalking, cryptographically hardening and production-scoping AI-agent governance evidence before and after enterprise actions.

Current version: **v0.9.0 — Production Reference Deployment**.

## Summary

RegAgentOps addresses four bounded control questions:

> Under which authenticated identity, purpose, data-governance profile, policy, tool, delegated authority, human approval, governed MCP, emergency-stop and one-time execution conditions may an AI agent continue toward a specific enterprise action?

> For one exact AI-system/deployment scope, which human-confirmed framework references are considered applicable, which exact governance-evidence digests map to them, and where are the evidence gaps?

> Which exact tenant/RLS/key/configuration/encryption/audit-anchor artefacts must a production adapter bind so that tenant separation and cryptographic custody are explicit rather than implicit?

> Which exact worker isolation, egress/tool allowlists, release provenance, rollback/upgrade and recovery artefacts must be current before a production controller may promote a release?

The project is designed for regulated and high-assurance environments. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, DLP scanner, legal rules engine, certification body, production orchestrator, Kubernetes client, KMS/HSM client, firewall manager, external immutable-log service or compliance-determination product.

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

TENANT / CRYPTO HARDENING
PostgreSQL RLS refs + tenant profile
KMS/HSM key refs + append-only lifecycle
signed configuration changes
AES-256-GCM evidence envelopes
external audit-anchor receipts

PRODUCTION REFERENCE
current v0.8 tenant-isolation profile
exact default-deny egress + tool allowlist
          |
isolated non-invoking policy-worker profile
          |
release manifest
(source commit + artifact + CodeQL + provenance + checksum evidence)
          |
upgrade <-> exact rollback + recovery checkpoint
```

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No v0.7-v0.9 assurance/hardening/deployment artefact can widen an authorization decision, override a denial or directly invoke a tool.

## v0.9 production-reference deployment boundary

### Isolated policy-enforcement worker

`IsolatedPolicyWorkerProfile` requires isolated network namespace, non-root execution, read-only root filesystem, no-new-privileges, all Linux capabilities dropped, `RuntimeDefault` seccomp, no privileged/host namespaces and **no direct tool invocation**.

`ProductionDeploymentRegistry` receives the v0.8 `TenantIsolationRegistry`. Worker registration must bind the exact **current** tenant-isolation profile together with exact current tenant egress/tool policies; a foreign, unknown or superseded tenant profile fails closed. Worker timestamps cannot predate those dependencies.

These are reference requirements. RegAgentOps does not deploy a container or independently prove that a runtime applied them.

### Strict egress and tool allowlisting

`EgressPolicy` is tenant-scoped, append-only, versioned and always default deny. It permits only exact `https`/`tls` host+port destinations, forbids wildcard destinations and plaintext transport, binds external trust-policy evidence, and requires canonical textual form for IP endpoints so equivalent IP aliases cannot bypass exact endpoint identity.

`ToolAllowlistPolicy` is also default deny. One governed tool can map to one exact external executor per policy version. The policy worker itself remains non-invoking.

### Release and currentness evidence

`DeploymentReleaseManifest` binds strict semantic version, exact source Git SHA, artifact SHA-256, worker/configuration digest, CodeQL evidence digest, provenance-attestation digest and checksum-manifest digest. A release cannot predate its worker profile.

`ProductionDeploymentRegistry.assert_release_current()` fails closed if the bound worker profile, egress policy, tool allowlist **or v0.8 tenant-isolation profile** has been superseded. Policy/RLS changes therefore require a new worker/release binding rather than silently reusing stale release evidence.

### Upgrade, rollback and recovery

A `RollbackPlan` must point from a newer registered release to an older registered release and bind trigger/verification evidence. An `UpgradePlan` requires a newer target and a registered rollback plan that **exactly reverses** the proposed transition. `RecoveryCheckpoint` binds exact release/configuration to encrypted-backup, external-audit-anchor and restore-verification evidence.

See [docs/PRODUCTION_REFERENCE.md](docs/PRODUCTION_REFERENCE.md).

## CodeQL and release provenance

The repository includes:

- **CodeQL** advanced Python analysis with the `security-extended` query suite;
- **Release Provenance Gate** that builds the wheel and deterministic `SHA256SUMS` on pull requests; and
- tag-scoped GitHub artifact attestations for version-matching `v*` release builds.

Build provenance is supply-chain evidence, not a claim that an artifact is vulnerability-free or production-safe.

## Operational runbooks

v0.9 includes accountable-operator runbooks for [deployment](docs/runbooks/DEPLOYMENT.md), [incident response](docs/runbooks/INCIDENT_RESPONSE.md), [KMS/HSM key rotation](docs/runbooks/KEY_ROTATION.md) and [disaster recovery](docs/runbooks/DISASTER_RECOVERY.md). They define preconditions, abort criteria and retained evidence; they do not automate privileged production actions.

## Earlier boundaries retained

- **v0.8 Tenant and Cryptographic Hardening:** PostgreSQL RLS reference DDL, tenant profiles, KMS/HSM-only key references, one-way key lifecycle, signed configuration changes, tenant-scoped AES-GCM evidence and external audit anchoring. See [docs/TENANT_CRYPTO_HARDENING.md](docs/TENANT_CRYPTO_HARDENING.md).
- **v0.7 Assurance Evidence:** human-reviewed NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689 evidence mapping with explicit non-certification semantics. See [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md).
- **v0.6 Data and Purpose Governance:** exact resource/data-use/purpose/output/retention controls and execution-time drift checks. See [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).
- **v0.5 Signed Execution Receipts:** short-lived executor-bound one-time leases, emergency stop and domain-separated signed receipts. See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).
- **v0.4 MCP Governance:** approved/pinned servers, bounded snapshots and explicit governed tool bindings. See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).
- **v0.3 Human Approval:** requester/approver separation, delegated authority, signatures and replay prevention. See [docs/APPROVALS.md](docs/APPROVALS.md).
- **v0.2 Authenticated Identity:** offline pinned OIDC/JWKS verification and institution-signed workload/authenticated context. See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

RegAgentOps v0.9 remains evidence/control focused:

- default deny for authorization, egress and tool dispatch;
- no autonomous resource, purpose, MCP-tool, egress-target or framework discovery;
- no production tool invocation from the governance/policy worker;
- no network/process capability in governed core modules;
- no embedded production credentials, private signing keys or symmetric evidence keys;
- worker registration resolves current tenant isolation plus current egress/tool policies;
- release evidence binds source, artifact, CodeQL, provenance and checksum digests;
- stale worker/egress/tool/tenant-isolation state invalidates release currentness;
- worker and release evidence cannot be backdated before their dependencies;
- upgrade cannot advertise a rollback path that does not exactly reverse the transition;
- historical backup/release evidence cannot justify weakening current RLS/egress/tool/key controls;
- human approval cannot override identity, policy or data-governance denial;
- signatures, receipts and attestations protect represented evidence/provenance but do not independently prove runtime truth or software safety;
- no compliance, certification, supervisory-acceptance or production-fitness claim.

## Quick start

```bash
python -m pip install -e .
regagentops --version
regagentops demo-decision
```

The CLI demo is synthetic and offline. It performs no tool execution and makes no network call.

## Repository map

```text
src/regagentops/
  models.py                    authorization artefacts and digests
  authenticated_policy.py      identity-gated authorization
  approval_*.py                human approval/delegation/signature/replay
  mcp.py                       governed MCP adapter
  execution.py                 one-time leases and signed receipts
  data_governance.py           data/purpose/output/retention governance
  assurance.py                 human-reviewed assurance crosswalks
  hardening.py                 tenant/RLS/key/config/encryption/anchor boundary
  deployment.py                v0.9 production-reference deployment contracts
  cli.py                       offline synthetic demo

schemas/
  ... v0.1-v0.8 contracts ...
  egress-policy.schema.json
  tool-allowlist-policy.schema.json
  isolated-policy-worker-profile.schema.json
  deployment-release-manifest.schema.json
  rollback-plan.schema.json
  upgrade-plan.schema.json
  recovery-checkpoint.schema.json

docs/
  PRODUCTION_REFERENCE.md
  runbooks/DEPLOYMENT.md
  runbooks/INCIDENT_RESPONSE.md
  runbooks/KEY_ROTATION.md
  runbooks/DISASTER_RECOVERY.md
  ... earlier boundary documentation ...
```

## CI boundary

GitHub Actions tests Python 3.11/3.12/3.13, compiles the package and performs clean-wheel smoke testing. Dedicated identity, approval, MCP, execution, data-purpose, assurance, tenant/crypto and production-reference workflows pin their respective invariants. CodeQL and Release Provenance are separate gates so application regressions, static security analysis and supply-chain evidence remain distinct control surfaces.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 human approval → v0.4 MCP → v0.5 execution receipts → v0.6 data/purpose → v0.7 assurance → v0.8 tenant/crypto → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/PRODUCTION_REFERENCE.md](docs/PRODUCTION_REFERENCE.md) and the boundary-specific documents linked above.

## Explicit non-claims

RegAgentOps v0.9 does **not** by itself prove deployed RLS/firewall/network/container enforcement, actual KMS/HSM hardware custody, CodeQL alert acceptance, external provenance verification, backup restorability, RTO/RPO attainment, external anchor immutability, secure cloud/database administration, regulatory compliance, certification, supervisory acceptance or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).
