# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which authenticated identity, business purpose, data-governance profile, policy, tool, delegated-authority, human-approval, governed MCP, emergency-stop, and one-time execution conditions may an AI agent continue toward a specific enterprise action, and how can that decision and represented result be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, DLP scanner, consent-management system, workflow/BPM system, production executor, or compliance-certification product.

Current version: **v0.6.0 — Data and Purpose Governance**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, data/purpose, delegated-authority, human-approval, MCP-governance, one-time execution-lease, emergency-stop, and signed-evidence controls before and around any external execution layer.

The v0.6 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, inspect live data for PII, infer legal purpose, issue production credentials, discover tools autonomously, redact output bytes, or invoke requested actions.

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
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means **DENY**. Identity failure means **DENY**. v0.6 data-governance denial also means **DENY**. Human approval never overrides those conditions.

## v0.6 data and purpose governance boundary

v0.6 adds institution-owned data-resource governance without creating a second authorization language.

### Exact governed resource state

`DataResourceProfile` is institution-scoped, append-only and contiguously versioned for an exact resource identifier. It declares the governed classification, exact data categories, primary purposes, explicitly compatible secondary purposes, permitted output handling, redaction requirements, retention ceiling and enabled state.

The reference data categories include personal, sensitive-personal, financial, health, biometric, credential, location and confidential-business data. These are governance labels, not automatic legal classifications.

### Request-bound data use

`DataUseDeclaration` binds the exact request digest, resource, business purpose, observed categories, requested output handling and retention period. Category tuples must exactly match the current resource profile, preventing callers from silently omitting sensitive categories to obtain weaker controls.

### Purpose, sensitive data, output and retention

Primary purposes are directly eligible. A secondary purpose must be explicitly registered as compatible and receives a `purpose:compatible-secondary-use` constraint. Unregistered purposes fail closed.

Sensitive categories emit minimization constraints. Raw output for categories requiring redaction is deterministically downgraded to a permitted safer handling mode. Retention above the resource ceiling is denied; positive decisions bind the requested retention requirement into authorization constraints.

### Evidence and currentness

`DataGovernanceDecision` binds the exact request, declaration, profile, data-governance registry snapshot, purpose, categories, output handling, retention, constraints and reasons. Its SHA-256 digest is added to `AuthorizationDecision.governance_evidence_digests`, so authenticated authorization—and therefore the v0.5 execution lease/receipt chain—commits to the exact v0.6 evidence.

`DataGovernedExecutionGate` rechecks the data-governance snapshot and exact profile before lease issuance and redemption. Governance drift invalidates the old execution path and requires fresh authorization.

See [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).

## v0.5 signed execution receipt boundary

v0.5 remains active beneath v0.6. Execution leases bind the exact request, authenticated authorization, policy-decision digest, MCP result, MCP snapshot, intended executor, emergency-stop state and approval chain when required. Authorization-to-lease freshness and lease lifetime are each capped at 120 seconds.

Lease redemption is atomic and one-time. Receipt construction requires the exact consumption artifact to exist in the append-only ledger. Signed receipts use domain-separated Ed25519 signatures and bind result digests rather than raw tool output.

See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).

## v0.4 MCP governance boundary

MCP metadata remains caller-supplied and offline. Approved servers are institution-scoped and identity-pinned; snapshots are bounded to 128 tools; descriptions/annotations are untrusted evidence; and only explicit current bindings can populate the existing `ToolRegistry`.

`McpPolicyEnforcementPoint` reuses `AuthenticatedPolicyEngine`, creates no parallel policy language, and never executes a tool. The v0.6 adapter layers data-purpose governance over that existing PEP. See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## v0.3 approval boundary

Requester/approver separation, bounded expiry, Ed25519 signatures, delegated authority and requirement-level one-time replay prevention remain active. Data-governance denial cannot be overridden by human approval.

See [docs/APPROVALS.md](docs/APPROVALS.md).

## Identity boundary

OIDC verification remains offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed; the combined authenticated context is signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.6 remains governance/evidence focused and simulation-first:

- default deny;
- exact current resource profiles and request-bound data-use declarations;
- no autonomous resource, data-category, purpose, server, target or MCP-tool discovery;
- no PII/DLP scanning or semantic purpose inference;
- no byte-level redaction or deletion/retention scheduler in the core;
- no production tool invocation or arbitrary command/shell execution;
- no embedded production credentials, bearer tokens or long-lived private keys;
- no network-capable MCP connection in governed core modules;
- no online OIDC discovery or JWKS retrieval;
- human approval cannot override identity, policy or data-governance denial;
- MCP, data-governance and emergency-stop drift invalidate an unconsumed governed execution path;
- signed receipts are evidence of represented bindings/signature, not independent proof of external runtime truthfulness or correctness;
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
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1-v0.5 contracts ...
  data-resource-profile.schema.json
  data-use-declaration.schema.json
  data-governance-decision.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py
  test_approvals.py
  test_mcp.py
  test_execution.py
  test_data_governance.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  MCP_GOVERNANCE.md
  EXECUTION_RECEIPTS.md
  DATA_PURPOSE_GOVERNANCE.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13, compiles the package and performs clean-wheel smoke testing. Generic CI rejects network/process capability imports across the governed core. Dedicated identity, human-approval, MCP-governance, signed-execution-receipt and data-purpose-governance workflows pin their respective contracts and fail-closed invariants.

## Standards and ecosystem references

RegAgentOps uses external frameworks as **design inputs**, not certification claims, including NIST AI RMF, OpenID/JWT security guidance, workload-identity concepts and the Model Context Protocol specification. RegAgentOps does not claim protocol conformance beyond the contracts it explicitly implements.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 human approval/delegated authority → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), [docs/APPROVALS.md](docs/APPROVALS.md), [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md), [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md), and [docs/DATA_PURPOSE_GOVERNANCE.md](docs/DATA_PURPOSE_GOVERNANCE.md).

## Explicit non-claims

RegAgentOps v0.6 does **not** by itself prove data-category correctness, legal-basis sufficiency, purpose compatibility under applicable law, consent, byte-level redaction, retention/deletion enforcement, external tool correctness, truthfulness of represented result bytes, regulatory compliance, certification, supervisory acceptance or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).