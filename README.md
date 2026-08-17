# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, and human-authority conditions may an AI agent perform a specific enterprise action, and how can that decision be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, identity provider, or compliance-certification product.

Current version: **v0.2.0 — Authenticated Agent Identity**.

## Why this exists

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places deterministic governance and identity verification before any future enforcement/execution layer.

The v0.2 core remains deliberately offline. It evaluates authorization and identity artifacts; it does not discover identity-provider metadata, fetch remote JWKS, connect to MCP servers, hold production credentials, or execute requested actions.

## Control model

```text
Human owner OIDC token          Institution workload signer
        |                                |
        | pinned offline JWKS verify     | signed short-lived statement
        v                                v
HumanIdentityAssertion          SignedWorkloadIdentity
        \                                /
         \                              /
          +---- registered AgentDescriptor ----+
                         |
                         v
             AuthenticatedAgentIdentity
                         |
               institution signature
                         v
          SignedAuthenticatedAgentIdentity
                         |
AgentActionEnvelope -----+----- Institution Policy Bundle
                         |
                         v
              AuthenticatedPolicyEngine
                         |
                         v
          AuthenticatedAuthorizationDecision
                         |
                         v
              future enforcement point
```

The v0.1 `AgentActionEnvelope` binds the institution, agent, human owner, model, tool/action, resource, data classification, business purpose, environment, risk tier, input digest, and request timestamp.

v0.2 adds two independent identity sources:

- a human identity assertion verified from an OIDC ID token against operator-supplied pinned JWKS and a registered owner→provider→subject mapping;
- a short-lived workload identity statement signed by an institution-owned Ed25519 signer and verified against an institution trust bundle.

The two sources are bound to the registered agent/model. The resulting `AuthenticatedAgentIdentity` expires at the earlier underlying identity expiry, but that raw context is **not** accepted as policy authority. It must itself be domain-separated and institution-signed as `SignedAuthenticatedAgentIdentity`. Unsigned, tampered, expired, cross-institution, request-mismatched, or registration-drifted contexts fail closed.

The policy core emits exactly one of four decisions:

- `ALLOW`
- `DENY`
- `REQUIRE_HUMAN_APPROVAL`
- `ALLOW_WITH_CONSTRAINTS`

Conservative precedence is deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching rule means **DENY**. Identity verification failure also means a non-executable **DENY** before an allow rule can take effect.

## v0.2 identity boundary

OIDC verification requires a configured HTTPS issuer and client id, an explicit asymmetric algorithm allowlist, an exact `kid`, pinned JWKS, exact registered subject and transaction nonce, audience checks, time checks, and optional ACR policy. Dynamic key-selection headers (`jku`, `x5u`, `crit`) are rejected. Raw bearer tokens and raw nonces are not retained in evidence artifacts; SHA-256 bindings are retained instead.

Workload identity statements bind institution, agent, human owner, model provider/model id, workload id, challenge digest, issuance time, and expiry. Their lifetime is capped at 15 minutes. Provider-neutral signing interfaces allow private-key custody to remain in an HSM/KMS-backed or otherwise institution-controlled signing boundary.

The final authenticated context is also Ed25519-signed using a distinct signing-document purpose. This closes the boundary between “a dataclass that looks authenticated” and identity evidence the policy engine is willing to trust.

See [docs/IDENTITY.md](docs/IDENTITY.md) for the full trust and failure model.

## Safety baseline

v0.2 is still authorization/identity-only and simulation-first:

- default deny;
- no production tool execution in the RegAgentOps runtime;
- no arbitrary command or shell execution;
- no embedded production credentials, bearer tokens, or long-lived private keys;
- no autonomous target/resource discovery;
- no network-capable MCP connection in the authorization core;
- no online OIDC discovery or JWKS retrieval in the identity verifier;
- unsigned authenticated contexts are rejected by the authenticated policy path;
- raw prompts and raw tool arguments are not required in governance artifacts;
- human approval remains explicit where policy requires it;
- no OpenID Provider, SPIFFE-conformance, regulatory, or standards-certification claim.

An `ALLOW` decision means only that supplied policy permits the request after applicable identity checks. **v0.2 contains no executor.**

## Quick start

```bash
python -m pip install -e .
regagentops --version
regagentops demo-decision
```

The demo evaluates a synthetic request and emits a constrained authorization decision. It performs no tool execution and makes no network call.

## Repository map

```text
src/regagentops/
  models.py                              authorization artifacts and canonical digests
  registry.py                            institution-scoped agent and tool/action registries
  policy.py                              deterministic fail-closed policy engine
  identity_models.py                     OIDC/workload/authenticated identity artifacts
  oidc.py                                offline pinned-JWKS OIDC verification
  registered_identity.py                 owner/provider/subject registry binding
  workload_identity.py                   workload signing interface and Ed25519 verification
  identity_binding.py                    human + workload + agent binding
  authenticated_identity_signature.py    signed authenticated-context anti-forgery boundary
  authenticated_policy.py                signed-identity-gated policy evaluation
  cli.py                                 offline synthetic authorization demo

schemas/
  agent-action-envelope.schema.json
  authorization-decision.schema.json
  policy-bundle.schema.json
  oidc-verifier-config.schema.json
  human-identity-assertion.schema.json
  workload-identity-statement.schema.json
  workload-identity-trust-bundle.schema.json
  signed-workload-identity.schema.json
  authenticated-agent-identity.schema.json
  signed-authenticated-agent-identity.schema.json
  authenticated-authorization-decision.schema.json

tests/
  test_policy.py
  test_contracts.py
  test_identity.py
  test_registered_identity.py

docs/
  ARCHITECTURE.md
  IDENTITY.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12, and 3.13, performs a clean-wheel smoke test, and statically rejects network/process capability imports in the authorization and identity core. A dedicated **Authenticated Identity Boundary** workflow locks the v0.2 package/dependency surface, runs identity-specific cryptographic regression tests, forbids network-capable `PyJWKClient`, checks remote-key-header rejection guards, and regression-checks that authenticated policy requires signed context.

This separation is intentional: future approval, MCP, and execution adapters must remain outside the pure authorization/identity boundary unless their release explicitly changes the trust model.

## Standards and ecosystem references

RegAgentOps uses external frameworks as **design inputs**, not certification claims:

- NIST AI Risk Management Framework (AI RMF): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI RMF Generative AI Profile (NIST AI 600-1): https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- SPIFFE specifications: https://spiffe.io/docs/latest/spiffe-specs/
- Model Context Protocol specification: https://modelcontextprotocol.io/specification

MCP treats tool capabilities as security-sensitive and emphasizes user control. RegAgentOps' future MCP adapter is intended to add enterprise authorization evidence around that trust boundary rather than replace MCP itself.

SPIFFE is referenced conceptually for workload identity and trust separation. RegAgentOps v0.2 does not implement SPIFFE Workload API, SVID issuance, or SPIFFE conformance.

## Roadmap

`v0.1 authorization → v0.2 authenticated identity → v0.3 signed human approval → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md) for release gates.

## Security

See [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/IDENTITY.md](docs/IDENTITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
