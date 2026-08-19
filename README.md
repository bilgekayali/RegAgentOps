# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, reviewing and crosswalking AI-agent governance evidence before and after enterprise actions.

## Summary

RegAgentOps answers two bounded questions:

> Under which authenticated identity, business purpose, data-governance profile, policy, tool, delegated-authority, human-approval, governed MCP, emergency-stop, and one-time execution conditions may an AI agent continue toward a specific enterprise action?

> For one exact AI-system/deployment scope, which human-confirmed framework references are considered applicable, which exact governance-evidence digests have been mapped to them, where are the evidence gaps, and what package can be reviewed later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, DLP scanner, legal rules engine, certification body, conformity assessor, workflow/BPM system, production executor, or compliance-determination product.

Current version: **v0.7.0 — Assurance Evidence**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, data/purpose, delegated-authority, human-approval, MCP-governance, one-time execution-lease, emergency-stop, signed-evidence and assurance-crosswalk controls around that path.

The v0.7 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, inspect live data for PII, infer legal purpose, determine framework applicability, classify EU AI Act risk, retrieve framework text, issue production credentials, redact output bytes, or invoke requested actions.

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
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means **DENY**. Identity failure means **DENY**. v0.6 data-governance denial also means **DENY**. Human approval never overrides those conditions. v0.7 assurance mappings do not alter authorization or execution decisions.

## v0.7 assurance evidence boundary

v0.7 adds a human-reviewed, digest-bound evidence crosswalk over the artifacts produced by earlier milestones.

### Exact scope

`AssuranceScope` binds an assurance review to one institution, system, deployment, accountable human owner, environment and SHA-256 digest of the external system/deployment context record.

### Pinned framework versions

v0.7 explicitly pins:

- NIST AI RMF `1.0`;
- ISO/IEC 42001 `2023`;
- EU AI Act Regulation `2024/1689`.

Framework upgrades are explicit contract changes rather than silent interpretation drift. `reference_id` remains operator supplied: RegAgentOps does not embed or validate full normative framework text.

### Human applicability and EU roles

`AssuranceApplicabilityAssertion` is required before a crosswalk entry can exist. It records exact scope, framework/version/reference, `applicable` or `not_applicable`, confirmation basis, confirming human and confirmation time.

EU AI Act assertions additionally require at least one human-confirmed operator role: provider, deployer, authorised representative, importer, distributor or product manufacturer. RegAgentOps does not infer those legal roles or high-risk status.

### Evidence coverage

`AssuranceEvidenceReference` records the exact digest, artifact type/schema and source component being mapped. `AssuranceCrosswalkEntry` links that evidence to the exact human applicability assertion using deliberately non-compliance coverage terms:

- `SUPPORTED`;
- `PARTIAL`;
- `GAP`; or
- `NOT_APPLICABLE`.

Supported/partial mappings require evidence. Gap/not-applicable mappings forbid evidence. Applicable and not-applicable human assertions cannot be silently reversed by a mapping.

### Evidence packages and non-claims

`AssuranceEvidencePackage` assembles exact assertion, entry and evidence-reference digests for one scope. Verification rejects substituted sets or cross-scope evidence.

The contract structurally fixes:

- `certification_claimed = false`;
- `conformity_claimed = false`;
- `legal_compliance_determined = false`; and
- `requires_human_review = true`.

See [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md).

## v0.6 data and purpose governance boundary

v0.6 remains active beneath the assurance layer. `DataResourceProfile` is institution-scoped, append-only and contiguously versioned for an exact resource. `DataUseDeclaration` binds the exact request, resource, purpose, observed categories, output handling and retention intent.

Category under-reporting, unregistered purposes and retention expansion fail closed. Sensitive resources emit minimization/output constraints, and the exact `DataGovernanceDecision` digest is bound into authenticated authorization. Data-governance drift invalidates the old execution path.

See [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).

## v0.5 signed execution receipt boundary

Execution leases bind the exact request, authenticated authorization, policy-decision digest, MCP result/snapshot, intended executor, emergency-stop state and approval chain when required. Authorization-to-lease freshness and lease lifetime are each capped at 120 seconds.

Lease redemption is atomic and one-time. Receipt construction requires the exact consumption artifact to exist in the append-only ledger. Signed receipts use domain-separated Ed25519 signatures and bind result digests rather than raw tool output.

See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).

## v0.4 MCP governance boundary

MCP metadata remains caller-supplied and offline. Approved servers are institution-scoped and identity-pinned; snapshots are bounded to 128 tools; descriptions/annotations are untrusted evidence; and only explicit current bindings can populate the existing `ToolRegistry`.

`McpPolicyEnforcementPoint` reuses `AuthenticatedPolicyEngine`, creates no parallel policy language and never executes a tool. See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## v0.3 approval boundary

Requester/approver separation, bounded expiry, Ed25519 signatures, delegated authority and requirement-level one-time replay prevention remain active. Data-governance denial cannot be overridden by human approval.

See [docs/APPROVALS.md](docs/APPROVALS.md).

## Identity boundary

OIDC verification remains offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed; the combined authenticated context is signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.7 remains governance/evidence focused and simulation-first:

- default deny for authorization;
- exact current resource profiles and request-bound data-use declarations;
- no autonomous resource, data-category, purpose, server, target or MCP-tool discovery;
- no PII/DLP scanning or semantic purpose inference;
- no automatic framework applicability, EU role or legal-compliance determination;
- framework versions are explicit and pinned;
- assurance applicability and mapping rationale require human identities;
- no byte-level redaction or deletion/retention scheduler in the core;
- no production tool invocation or arbitrary command/shell execution;
- no embedded production credentials, bearer tokens or long-lived private keys;
- no network-capable framework/MCP connection in governed core modules;
- no online OIDC discovery or JWKS retrieval;
- human approval cannot override identity, policy or data-governance denial;
- MCP, data-governance and emergency-stop drift invalidate an unconsumed governed execution path;
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
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1-v0.6 contracts ...
  assurance-scope.schema.json
  assurance-applicability-assertion.schema.json
  assurance-evidence-reference.schema.json
  assurance-crosswalk-entry.schema.json
  assurance-evidence-package.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py
  test_approvals.py
  test_mcp.py
  test_execution.py
  test_data_governance.py
  test_assurance.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  MCP_GOVERNANCE.md
  EXECUTION_RECEIPTS.md
  DATA_PURPOSE_GOVERNANCE.md
  ASSURANCE_EVIDENCE.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13, compiles the package and performs clean-wheel smoke testing. Generic CI rejects network/process capability imports across the governed core. Dedicated identity, human-approval, MCP-governance, signed-execution-receipt, data-purpose-governance and assurance-evidence workflows pin their respective contracts and fail-closed invariants.

## Standards and ecosystem references

RegAgentOps uses external frameworks as **design inputs and evidence-reference namespaces**, not certification claims. v0.7 pins NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689. OpenID/JWT security guidance, workload-identity concepts and the Model Context Protocol specification remain design inputs for earlier control boundaries.

RegAgentOps does not reproduce or independently interpret full normative framework text and does not claim protocol/framework conformance beyond the contracts it explicitly implements.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 human approval/delegated authority → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), [docs/APPROVALS.md](docs/APPROVALS.md), [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md), [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md), [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md), and [docs/ASSURANCE_EVIDENCE.md](docs/ASSURANCE_EVIDENCE.md).

## Explicit non-claims

RegAgentOps v0.7 does **not** by itself prove framework applicability, evidence sufficiency, NIST AI RMF compliance, ISO/IEC 42001 conformity or certification, EU AI Act role/high-risk/legal classification, regulatory compliance, legal-basis sufficiency, data-category correctness, byte-level redaction, retention/deletion enforcement, external tool correctness, truthfulness of represented result bytes, supervisory acceptance or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).