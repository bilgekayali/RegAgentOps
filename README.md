# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, reviewing, crosswalking and cryptographically hardening AI-agent governance evidence before and after enterprise actions.

## Summary

RegAgentOps addresses three bounded control questions:

> Under which authenticated identity, business purpose, data-governance profile, policy, tool, delegated-authority, human-approval, governed MCP, emergency-stop and one-time execution conditions may an AI agent continue toward a specific enterprise action?

> For one exact AI-system/deployment scope, which human-confirmed framework references are considered applicable, which exact governance-evidence digests have been mapped to them, where are the evidence gaps, and what package can be reviewed later?

> Which exact tenant/RLS/key/configuration/encryption/audit-anchor artifacts must a production adapter bind so that tenant separation and cryptographic custody are explicit rather than implicit?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, DLP scanner, legal rules engine, certification body, conformity assessor, production database migrator, KMS/HSM client, external immutable-log service, workflow/BPM system, production executor, or compliance-determination product.

Current version: **v0.8.0 — Tenant and Cryptographic Hardening**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, data/purpose, delegated-authority, human-approval, MCP-governance, one-time execution-lease, emergency-stop, signed-evidence, assurance-crosswalk, tenant-isolation and cryptographic-hardening controls around that path.

The v0.8 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, PostgreSQL, KMS/HSM or external anchoring services, inspect live data for PII, infer legal purpose, determine framework applicability, issue production credentials, redact output bytes, or invoke requested actions.

## Control model

```text
Human OIDC identity             Institution workload identity
        \                               /
         +---- Signed authenticated agent ----+
                          |
AgentActionEnvelope ------+------ PolicyBundle
        |                 |
        |        governed MCP server/tool state
        |                 |
        +------ DataUseDeclaration
                          |
                  current DataResourceProfile
                          |
                          v
                 DataGovernanceDecision
                          |
                   evidence digest
                          v
               AuthenticatedAuthorizationDecision
                          |
                    MCP policy result
                          |
                if approval required
                          v
                     ApprovalGate
                          |
                          v
                  ApprovalResolution
                          |
       current MCP + data governance + emergency stop
                          |
                          v
                 one-time ExecutionLease
                          |
                 atomic lease consumption
                          |
                          v
                  external executor
                          |
                          v
             SignedToolExecutionReceipt

Existing governance/evidence artifacts
                 |
                 v
            AssuranceScope
                 |
       human applicability review
                 v
AssuranceApplicabilityAssertion
                 |
       exact evidence references
                 v
       AssuranceCrosswalkEntry
                 |
                 v
       AssuranceEvidencePackage

Production adapter hardening references
                 |
       +---------+---------+
       |                   |
Postgres RLS         KMS/HSM key refs
       |                   |
Tenant profile       signed config changes
                           |
                  AES-GCM evidence envelope
                           |
                  external anchor receipt
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means **DENY**. Identity failure means **DENY**. v0.6 data-governance denial also means **DENY**. Human approval never overrides those conditions. v0.7 assurance mappings and v0.8 hardening artifacts do not widen authorization or execution decisions.

## v0.8 tenant and cryptographic hardening boundary

v0.8 adds exact reference contracts for tenant isolation, institution-controlled cryptographic custody, signed configuration changes, tenant-scoped encrypted evidence and external audit anchoring.

### PostgreSQL RLS reference

`PostgresRlsPolicy` restricts table/policy/column names to safe identifiers and renders reference DDL that always enables and **forces** row-level security. The same institution+tenant predicate is emitted in both `USING` and `WITH CHECK`, preventing the reference policy from protecting reads while leaving writes unscoped.

`TenantIsolationProfile` binds one institution/tenant/environment/database role to exact RLS-policy digests. Policy and profile versions are append-only and contiguous.

### KMS/HSM key custody references

`InstitutionCryptoKeyReference` is institution-, tenant- and purpose-scoped. Custody is restricted to `kms` or `hsm`. Configuration-signing keys use Ed25519 and carry only the public verification key. Evidence-encryption keys use AES-256-GCM and carry **no symmetric key material**.

Private and symmetric keys stay behind external KMS/HSM adapters. Rotated references are versioned and use distinct key IDs.

### Signed configuration changes

`ConfigurationChangeRequest` binds exact previous/proposed configuration digests, tenant, object identity, sequence, requester, reason digest and chronology. `SignedConfigurationChange` uses domain-separated Ed25519 signatures and binds the exact KMS/HSM key-reference digest plus the previous signed-change digest.

`ConfigurationChangeRegistry` verifies each signature before append, enforces one contiguous tenant change chain and rejects forks and stale-object overwrites.

### Tenant-scoped encrypted evidence

`EncryptedGovernanceEvidence` records AES-256-GCM ciphertext plus exact tenant/key/subject bindings. Domain-separated authenticated additional data commits to institution, tenant, key-reference digest, envelope ID and subject-artifact digest. The core stores ciphertext and digests, not the encryption key.

### External audit anchoring

`AuditAnchorBatch` creates a tenant-scoped chained batch of exact evidence digests. `ExternalAuditAnchorReceipt` represents an opaque external-provider receipt for the exact batch. `AuditAnchorRegistry` rejects tenant substitution, wrong batch bindings, chain forks and backwards chronology.

See [docs/TENANT_CRYPTO_HARDENING.md](docs/TENANT_CRYPTO_HARDENING.md).

## v0.7 assurance evidence boundary

v0.7 remains active beneath v0.8. It adds a human-reviewed, digest-bound crosswalk for NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689. Applicability and mapping remain human-confirmed, and packages structurally cannot claim certification, conformity or legal compliance.

See [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md).

## v0.6 data and purpose governance boundary

`DataResourceProfile` is institution-scoped, append-only and contiguously versioned for an exact resource. `DataUseDeclaration` binds the exact request, resource, purpose, observed categories, output handling and retention intent. Category under-reporting, unregistered purposes and retention expansion fail closed; governance drift invalidates the old execution path.

See [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).

## v0.5 signed execution receipt boundary

Execution leases bind the exact request, authenticated authorization, policy decision, governed MCP state, intended executor, emergency-stop state and approval chain when required. Lease redemption is atomic and one-time. Receipt construction proves the exact consumption artifact exists before a signed receipt is built.

See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).

## v0.4 MCP governance boundary

Approved MCP servers are institution-scoped and identity-pinned; caller-supplied snapshots are bounded to 128 tools; descriptions/annotations are evidence only; and only explicit current bindings become governed tool actions. The MCP adapter remains offline and never executes a tool.

See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## v0.3 approval boundary

Requester/approver separation, bounded expiry, Ed25519 signatures, delegated authority and requirement-level one-time replay prevention remain active. Approval cannot override identity, policy or data-governance denial.

See [docs/APPROVALS.md](docs/APPROVALS.md).

## Identity boundary

OIDC verification remains offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed; the combined authenticated context is signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.8 remains governance/evidence focused and adapter-first:

- default deny for authorization;
- exact current resource profiles and request-bound data-use declarations;
- no autonomous resource, data-category, purpose, server, target or MCP-tool discovery;
- no automatic framework applicability, EU role or legal-compliance determination;
- PostgreSQL RLS reference DDL is rendered but never applied by the core;
- hardening code contains no PostgreSQL driver or cloud/KMS/HSM SDK;
- cryptographic key references allow KMS/HSM custody only;
- no private signing key or symmetric evidence-encryption key is embedded in governance artifacts;
- configuration changes are domain-separated, signed and chained before append;
- encrypted governance evidence binds institution, tenant, exact key reference and subject digest as AES-GCM AAD;
- external audit receipts must bind the exact local batch and chain but remain opaque external evidence;
- no byte-level redaction or deletion/retention scheduler in the core;
- no production tool invocation or arbitrary command/shell execution;
- no embedded production credentials or bearer tokens;
- human approval cannot override identity, policy or data-governance denial;
- signed receipts are evidence of represented bindings/signature, not independent proof of external runtime truthfulness or correctness;
- assurance packages cannot structurally claim certification, conformity or legal compliance;
- no regulatory or standards-certification claim.

## Quick start

```bash
python -m pip install -e .
regagentops --version
regagentops demo-decision
```

The CLI demo remains synthetic and offline. It performs no tool execution and makes no network call.

## Repository map

```text
src/regagentops/
  models.py                              authorization artifacts and evidence bindings
  registry.py                            institution-scoped agent/tool registry
  policy.py                              deterministic fail-closed policy engine
  identity_models.py                     identity artifacts and trust models
  authenticated_policy.py                identity-gated policy evaluation
  approval_*.py                          approval/delegation/signature/replay boundary
  mcp.py                                 governed MCP registry + offline PEP adapter
  execution.py                           one-time leases + signed execution receipts
  data_governance.py                     resource/purpose/output/retention governance
  assurance.py                           scoped human-reviewed assurance crosswalks
  hardening.py                           RLS/key/config/encryption/audit-anchor reference boundary
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1-v0.7 contracts ...
  postgres-rls-policy.schema.json
  tenant-isolation-profile.schema.json
  institution-crypto-key-reference.schema.json
  configuration-change-request.schema.json
  signed-configuration-change.schema.json
  encrypted-governance-evidence.schema.json
  audit-anchor-batch.schema.json
  external-audit-anchor-receipt.schema.json
  audit-anchor-record.schema.json

tests/
  ... earlier regression suites ...
  test_assurance.py
  test_hardening.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  MCP_GOVERNANCE.md
  EXECUTION_RECEIPTS.md
  DATA_PURPOSE_GOVERNANCE.md
  ASSURANCE_EVIDENCE.md
  TENANT_CRYPTO_HARDENING.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13, compiles the package and performs clean-wheel smoke testing. Generic CI rejects network/process capability imports across the governed core. Dedicated identity, approval, MCP, execution, data-purpose, assurance and **Tenant and Cryptographic Hardening** workflows pin their respective contracts and fail-closed invariants.

## Standards and ecosystem references

RegAgentOps uses external frameworks as design inputs and evidence-reference namespaces, not certification claims. v0.7 pins NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689. OpenID/JWT security guidance, workload-identity concepts, PostgreSQL RLS semantics and the Model Context Protocol remain implementation/design inputs for their respective boundaries.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 human approval/delegated authority → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), [docs/APPROVALS.md](docs/APPROVALS.md), [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md), [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md), [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md), [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md), and [docs/TENANT_CRYPTO_HARDENING.md](docs/TENANT_CRYPTO_HARDENING.md).

## Explicit non-claims

RegAgentOps v0.8 does **not** by itself prove deployed PostgreSQL RLS non-bypassability, actual KMS/HSM hardware custody, secure cloud/database administration, external anchor immutability, backup/replica tenant isolation, nonce uniqueness across every integration, framework applicability, evidence sufficiency, regulatory compliance, certification, external tool correctness, truthfulness of represented result bytes, supervisory acceptance or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).
