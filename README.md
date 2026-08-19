# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, delegated-authority, human-approval, governed MCP, emergency-stop, and one-time execution conditions may an AI agent continue toward a specific enterprise action, and how can that decision and represented result be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, workflow/BPM system, production executor, or compliance-certification product.

Current version: **v0.5.0 — Signed Execution Receipts**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, delegated-authority, human-approval, MCP-governance, one-time execution-lease, emergency-stop, and signed-evidence controls before and around any external execution layer.

The v0.5 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, issue production credentials, discover tools autonomously, or invoke requested actions.

## Control model

```text
Human OIDC identity             Institution workload identity
        \                               /
         +---- Signed authenticated agent ----+
                          |
AgentActionEnvelope ------+------ PolicyBundle
                          |
Approved MCP server registration
        |
Caller-supplied tool snapshot
        |
Explicit governed tool binding
        |
        +-------------------------+
                                  v
                         MCP policy-enforcement adapter
                                  |
                                  v
                    AuthenticatedPolicyEngine
                                  |
                                  v
               AuthenticatedAuthorizationDecision
                                  |
                      if approval required
                                  v
                            ApprovalGate
                       /          |           \
              authority grants signatures replay ledger
                       \          |           /
                        +---------+----------+
                                  |
                                  v
                         ApprovalResolution
                                  |
                         current MCP state
                         emergency-stop state
                                  |
                                  v
                       one-time ExecutionLease
                                  |
                       atomic lease consumption
                                  |
                                  v
                       external tool executor
                                  |
                                  v
                    ToolExecutionReceipt
                                  |
                                  v
                 SignedToolExecutionReceipt
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching rule means **DENY**. Identity failure also means **DENY**. Human approval never overrides either condition.

## v0.5 signed execution receipt boundary

v0.5 introduces a non-invoking bridge from governed continuation evidence to an external executor.

### Exact execution binding

`ExecutionLease` binds the exact request digest, authenticated authorization digest, nested policy-decision digest, MCP policy-enforcement result, MCP registry snapshot, emergency-stop state, and—when required—the exact approval requirement and approval resolution.

A lease is issued only from a verified non-DENY MCP policy outcome whose governed MCP evidence is still current. Approval-required requests cannot produce a lease without the exact request/authorization-bound approval chain.

### One-time lease and emergency stop

Execution leases are capped at 120 seconds. Redemption occurs through an append-only SQLite ledger keyed by lease digest, so the same lease cannot be consumed twice.

Emergency-stop state is institution-scoped, append-only and versioned. A halted state blocks lease issuance and redemption. The lease binds the exact non-halted state; any stop-state change makes an unconsumed lease stale. MCP governance drift likewise invalidates the lease before redemption.

### Signed result evidence

`ToolExecutionReceipt` binds request/tool/action/resource/input evidence, lease and one-time consumption, MCP policy result, authenticated authorization, policy-decision digest, optional approval evidence, emergency-stop state, SHA-256 result digest, explicit `SUCCEEDED`/`FAILED` outcome, timestamps and executor identity.

`SignedToolExecutionReceipt` uses a domain-separated Ed25519 signing document and institution-owned `ExecutionTrustBundle` keys. Receipt/result modification breaks verification.

The core itself does not dispatch the tool. See [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).

## v0.4 MCP governance boundary

v0.4 controls remain active beneath the execution boundary. MCP metadata is caller-supplied and offline; approved servers are institution-scoped and identity-pinned; tool snapshots are bounded to 128 tools; descriptions/annotations are untrusted evidence; and only explicit current bindings can populate the existing `ToolRegistry`.

`McpPolicyEnforcementPoint` reuses `AuthenticatedPolicyEngine`, creates no parallel policy language, and never executes a tool. See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## v0.3 approval boundary

An approval requirement is issued when policy returns `REQUIRE_HUMAN_APPROVAL` or when configured escalation requires approval for high/critical risk. Requester/approver separation, bounded expiry, Ed25519 signatures, delegated authority, and requirement-level one-time replay prevention remain unchanged for execution-bound requests.

See [docs/APPROVALS.md](docs/APPROVALS.md).

## Identity boundary

v0.2 controls remain active. OIDC verification is offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed. The combined authenticated context is domain-separated and signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.5 remains governance/evidence focused and simulation-first:

- default deny;
- no production tool invocation in the RegAgentOps core;
- no arbitrary command or shell execution;
- no embedded production credentials, bearer tokens, or long-lived private keys;
- no autonomous target, resource, server, or MCP-tool discovery;
- no network-capable MCP connection in authorization, identity, approval, MCP-governance, or execution modules;
- no online OIDC discovery or JWKS retrieval;
- unsigned authenticated contexts are rejected;
- MCP annotations cannot weaken or expand authorization policy;
- human approval cannot override policy or identity denial;
- execution leases are short-lived and one-time;
- emergency-stop and MCP-governance drift invalidate unconsumed leases;
- signed receipts carry result digests, not raw tool output;
- a valid receipt is evidence of represented bindings/signature, not independent proof of external runtime truthfulness or correctness;
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
  models.py                              authorization artifacts and canonical digests
  registry.py                            institution-scoped agent/tool registry
  policy.py                              deterministic fail-closed policy engine
  identity_models.py                     identity artifacts and trust models
  oidc.py                                offline pinned-JWKS OIDC verification
  registered_identity.py                 owner/provider/subject binding
  workload_identity.py                   signed workload identity
  identity_binding.py                    human + workload + agent binding
  authenticated_identity_signature.py    signed authenticated-context boundary
  authenticated_policy.py                identity-gated policy evaluation
  approval_models.py                     approval/delegation artifacts
  approval_authority.py                  delegated-authority validation
  approval_signature.py                  signed human approval verification
  approval_replay.py                     one-time requirement redemption ledger
  approval_engine.py                     escalation and approval resolution
  mcp.py                                 governed MCP registry + offline PEP adapter
  execution.py                           one-time leases + signed execution receipts
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1-v0.4 contracts ...
  emergency-stop-state.schema.json
  execution-lease.schema.json
  execution-lease-consumption.schema.json
  execution-trust-bundle.schema.json
  tool-execution-receipt.schema.json
  signed-tool-execution-receipt.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py
  test_approvals.py
  test_mcp.py
  test_execution.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  MCP_GOVERNANCE.md
  EXECUTION_RECEIPTS.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13, compiles the package, and performs clean-wheel smoke testing. Generic CI rejects network/process capability imports across the governed core. Dedicated identity, human-approval, MCP-governance and signed-execution-receipt workflows pin their respective contracts and invariants.

## Standards and ecosystem references

RegAgentOps uses external frameworks as **design inputs**, not certification claims:

- NIST AI Risk Management Framework (AI RMF): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI RMF Generative AI Profile (NIST AI 600-1): https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- SPIFFE specifications: https://spiffe.io/docs/latest/spiffe-specs/
- Model Context Protocol specification: https://modelcontextprotocol.io/specification

These references inform trust and governance design. RegAgentOps does not claim protocol conformance beyond the contracts it explicitly implements.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 human approval/delegated authority → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), [docs/APPROVALS.md](docs/APPROVALS.md), [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md), and [docs/EXECUTION_RECEIPTS.md](docs/EXECUTION_RECEIPTS.md).

## Explicit non-claims

RegAgentOps v0.5 does **not** by itself prove external tool implementation safety/correctness, truthfulness or completeness of represented result bytes, runtime enforcement after lease redemption, MCP server behavior, regulatory compliance, legal applicability, certification, supervisory acceptance, or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).