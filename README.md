# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, delegated-authority, and human-approval conditions may an AI agent continue toward a specific enterprise action, and how can that decision be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, workflow/BPM system, or compliance-certification product.

Current version: **v0.3.0 — Human Approval and Delegated Authority**.

## Purpose

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic identity, policy, delegated-authority and human-approval controls before any future enforcement/execution layer.

The v0.3 core remains deliberately bounded and offline. It does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, issue production credentials, or execute requested actions.

## Control model

```text
Human OIDC identity             Institution workload identity
        \                               /
         +---- Signed authenticated agent ----+
                          |
AgentActionEnvelope ------+------ PolicyBundle
                          |
                          v
             AuthenticatedPolicyEngine
                          |
                          v
          AuthenticatedAuthorizationDecision
                          |
                          v
                    ApprovalGate
               /          |           \
      authority grants  signatures  replay ledger
               \          |           /
                +---------+----------+
                          |
                          v
                 ApprovalResolution
                          |
                          v
                future enforcement point
```

Policy precedence remains deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching rule means **DENY**. Identity failure also means **DENY**. Human approval never overrides either condition.

## v0.3 approval boundary

v0.3 introduces a separate approval gate after authenticated policy evaluation.

An approval requirement is issued when:

- policy returns `REQUIRE_HUMAN_APPROVAL`;
- the request risk tier is `high`; or
- the request risk tier is `critical`.

The reference escalation policy requires at least one independent approval for high risk and two distinct approvals for critical risk. Requester/approver separation applies to policy-required, high-risk and critical-risk approval flows.

Approval requirements bind the exact request digest, authenticated authorization digest, signed identity-context digest, requester, tool/action, environment, risk tier, escalation policy and expiry.

### Delegated authority

`ApprovalAuthorityGrant` separates the right to approve from the cryptographic key used to sign an approval. A grant scopes a principal to specific tools, actions, environments, maximum risk tier and validity interval.

Delegated grants cannot expand the parent grant: tool/action/environment scope must remain a subset, maximum risk cannot increase, validity cannot outlive the parent, the issuer must be the parent subject, and the parent must explicitly permit delegation. Delegation cycles fail closed.

### Signed approvals

Each `ApprovalStatement` binds the requirement, request, approver, authority grant, vote, timestamps and rationale digest. The signed artifact uses Ed25519 and domain-separated purpose `regagentops.human-approval.v1`.

Approval trust keys are institution- and principal-scoped. Disabled, expired, wrong-principal, ambiguous or invalid-signature keys are rejected.

### Replay prevention

The reference `ApprovalReplayLedger` uses append-only SQLite insertion and makes the **approval requirement digest** the one-time redemption key.

A valid denial or a sufficient approval set terminally consumes the requirement. A later package cannot redeem the same requirement using a different set of approvals. An insufficient package does not consume the requirement and may be completed before expiry.

See [docs/APPROVALS.md](docs/APPROVALS.md) for the full approval and delegation model.

## Identity boundary

v0.2 controls remain active. OIDC verification is offline against operator-supplied pinned JWKS, with issuer/client/audience/algorithm/nonce/subject/time checks and dynamic key-selection header rejection. Workload identity is short-lived and institution-signed. The combined authenticated context is itself domain-separated and signed before policy use.

See [docs/IDENTITY.md](docs/IDENTITY.md).

## Safety baseline

v0.3 remains governance-only and simulation-first:

- default deny;
- no production tool execution in the RegAgentOps runtime;
- no arbitrary command or shell execution;
- no embedded production credentials, bearer tokens, or long-lived private keys;
- no autonomous target/resource discovery;
- no network-capable MCP connection in authorization, identity, or approval modules;
- no online OIDC discovery or JWKS retrieval;
- unsigned authenticated contexts are rejected;
- human approval cannot override policy or identity denial;
- approval continuation is not execution permission from a runtime executor;
- no regulatory or standards-certification claim.

`ApprovalResolution.authorization_continuation_permitted=true` means only that the v0.3 governance gates were satisfied for the bound artifacts. **v0.3 contains no executor and does not prove that a later execution matches the approval.**

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
  cli.py                                 offline synthetic demo

schemas/
  ... v0.1/v0.2 contracts ...
  approval-authority-grant.schema.json
  approval-escalation-policy.schema.json
  approval-requirement.schema.json
  approval-trust-bundle.schema.json
  signed-approval-statement.schema.json
  signed-approval-package.schema.json
  approval-resolution.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py
  test_approvals.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  APPROVALS.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12 and 3.13 and performs clean-wheel smoke testing. Generic CI rejects network/process imports across authorization, identity and approval core modules.

Dedicated workflows additionally enforce:

- **Authenticated Identity Boundary** — offline pinned-trust identity verification and signed-context regression;
- **Human Approval Boundary** — approval regression tests, v0.3 version/dependency contract, Ed25519 domain separation, append-only replay-ledger SQL surface and no policy-`DENY` override.

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

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/IDENTITY.md](docs/IDENTITY.md), and [docs/APPROVALS.md](docs/APPROVALS.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
