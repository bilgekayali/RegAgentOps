# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, delegated-authority, human-approval, and governed MCP conditions may an AI agent continue toward a specific enterprise action, and how can that decision be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, workflow/BPM system, or compliance-certification product.

Current version: **v0.4.0 — MCP Governance Adapter**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, delegated-authority, human-approval, and MCP-governance controls before any future enforcement/execution layer.

The v0.4 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, issue production credentials, discover tools autonomously, or execute requested actions.

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
                                  v
                       future execution layer
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching rule means **DENY**. Identity failure also means **DENY**. Human approval never overrides either condition.

## v0.4 MCP governance boundary

v0.4 adds an offline governance adapter around MCP tool metadata. The core never performs MCP discovery or network connection. Operators or surrounding applications supply tool snapshots explicitly.

### Approved server identity

`McpServerRegistration` gives each approved MCP server an institution-owned `server_id`, expected server-reported name, transport profile, explicit identity-pin digest, metadata digest, approval state, and contiguous version history.

The server-reported name is metadata rather than the global identity. Governed MCP tool IDs are namespaced as `mcp:<server_id>:<tool_name>` so same-named tools on different approved servers cannot silently collide.

### Bounded tool snapshots

`McpToolSnapshot` binds caller-supplied tool metadata to an exact approved server-registration digest and observed server-identity pin. The reference boundary permits at most 128 tools per snapshot, rejects duplicate tool names within a server, and fails closed when different snapshots conflict at the same semantic latest timestamp.

### Untrusted metadata

Tool descriptions and MCP annotations are represented only through evidence digests. They never determine production eligibility, allowed data classifications, policy effect, risk tier, approval requirement, or execution permission.

`McpToolBinding` is the explicit institution-owned mapping from an exact current MCP tool descriptor to the existing RegAgentOps `ToolActionDescriptor` boundary. A new tool snapshot or server-registration version makes an older current binding stale until an explicit re-binding is registered.

### Policy enforcement

`McpPolicyEnforcementPoint` derives a `ToolRegistry` only from current explicit MCP bindings and then reuses the existing `AuthenticatedPolicyEngine`. It creates no second policy language.

If the authenticated policy decision requires human approval, the exact authorization object remains available to the existing v0.3 `ApprovalGate`. This preserves requester/approver separation, delegated authority, signature verification, expiry, and one-time replay controls.

`McpPolicyEnforcementResult.execution_performed` is always `false` in v0.4. A positive continuation decision is governance evidence only; it is not a tool execution or execution receipt.

See [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## v0.3 approval boundary

v0.3 controls remain active after authenticated policy evaluation.

An approval requirement is issued when policy returns `REQUIRE_HUMAN_APPROVAL` or when the configured escalation policy requires approval for high/critical risk. Requester/approver separation, bounded expiry, Ed25519 signatures, delegated authority, and requirement-level replay prevention remain unchanged for MCP-governed requests.

See [docs/APPROVALS.md](docs/APPROVALS.md).

## Identity boundary

v0.2 controls remain active. OIDC verification is offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed. The combined authenticated context is itself domain-separated and signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.4 remains governance-only and simulation-first:

- default deny;
- no production tool execution in the RegAgentOps runtime;
- no arbitrary command or shell execution;
- no embedded production credentials, bearer tokens, or long-lived private keys;
- no autonomous target, resource, server, or MCP-tool discovery;
- no network-capable MCP connection in authorization, identity, approval, or MCP-governance modules;
- no online OIDC discovery or JWKS retrieval;
- unsigned authenticated contexts are rejected;
- MCP annotations cannot weaken or expand authorization policy;
- human approval cannot override policy or identity denial;
- approval continuation is not execution permission from a runtime executor;
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
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1/v0.2/v0.3 contracts ...
  mcp-server-registration.schema.json
  mcp-tool-descriptor.schema.json
  mcp-tool-snapshot.schema.json
  mcp-tool-binding.schema.json
  mcp-policy-enforcement-result.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py
  test_approvals.py
  test_mcp.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  MCP_GOVERNANCE.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13, compiles the package, and performs clean-wheel smoke testing. Generic CI rejects network/process imports across authorization, identity, approval, and MCP-governance core modules. The MCP core is additionally guarded against autonomous discovery/network call markers.

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

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), [docs/APPROVALS.md](docs/APPROVALS.md), and [docs/MCP_GOVERNANCE.md](docs/MCP_GOVERNANCE.md).

## Explicit non-claims

RegAgentOps v0.4 does **not** by itself establish MCP server authenticity from supplied metadata, tool implementation safety/correctness, runtime enforcement by an external MCP client/server, successful execution, regulatory compliance, legal applicability, certification, supervisory acceptance, or production fitness.

## License

Apache License 2.0. See [LICENSE](LICENSE).
