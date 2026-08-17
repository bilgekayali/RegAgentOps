# Threat Model — v0.2

## Protected assets

- authorization policy integrity;
- institution, human-owner, agent, model, and workload identity bindings;
- OIDC verifier configuration and pinned JWKS integrity;
- institution workload trust-bundle integrity;
- tool/action registry integrity;
- authorization and authenticated-identity evidence integrity;
- raw bearer-token and nonce confidentiality;
- separation between identity/decision and execution capabilities.

## Trust boundaries

1. **Caller → identity/PDP**: the caller supplies the action request, raw OIDC token, transaction nonce, and externally governed trust material; all are untrusted until verified.
2. **Human identity registry → OIDC verifier**: owner→provider→subject mappings are privileged administrative configuration.
3. **Pinned JWKS/config → OIDC verifier**: trust material must come from a separately governed configuration path; the verifier performs no online discovery.
4. **Institution workload signer → verifier**: private-key custody remains outside the verifier; only signed statements and public trust bundles cross the boundary.
5. **Registry/policy configuration → PDP**: agent/tool/policy configuration is security-sensitive administrative input.
6. **PDP → future enforcement point**: v0.2 produces decisions but does not enforce or execute actions.

## Primary threats and v0.2 controls

### Human identity substitution

Threat: a caller presents a valid token for a different subject or provider and maps it to a privileged local owner.

Controls: institution-scoped human identity registration; exact provider and subject binding; issuer/client/audience checks; exact transaction nonce; authenticated context must match the registered agent owner.

### JWT algorithm or key confusion

Threat: a token selects an unsafe algorithm or redirects verification toward attacker-controlled key material.

Controls: explicit asymmetric algorithm allowlist; one exact `kid`; JWK algorithm/use/key-ops compatibility; rejection of `jku`, `x5u`, and `crit`; no `PyJWKClient` or online key retrieval in the verifier.

### Token replay or stale authentication

Threat: an old but once-valid identity token is replayed into a new authorization transaction.

Controls: exact transaction nonce; `iat`/`exp`/optional `nbf` checks; bounded maximum token age; optional ACR policy; authenticated context inherits the earliest identity expiry.

### Workload impersonation

Threat: a process claims to be an authorized agent/model workload.

Controls: short-lived workload statement; institution/agent/owner/model/workload/challenge binding; Ed25519 signature; institution-scoped trust bundle; exact key-id selection; active-key and validity-window checks.

### Registration drift after authentication

Threat: an authenticated context remains usable after the agent's registered owner/model configuration changes.

Control: `AuthenticatedAgentIdentity` binds the `AgentDescriptor` digest and `AuthenticatedPolicyEngine` rechecks it before policy evaluation.

### Cross-tenant identity replay

Threat: human/workload evidence from one institution is replayed for another.

Control: institution id is independently bound into provider config, human assertion, workload statement, trust keys/bundle, registered agent, request, and authenticated context. Mismatch fails closed.

### Unregistered tool/action use

Threat: an authenticated agent requests an action that was never governed.

Control: tool/action registry lookup remains mandatory; missing/disabled entries fail closed.

### Data-classification escalation

Threat: a tool registered for lower-sensitivity data is used against more sensitive data.

Control: requested classification must be explicitly present in the tool/action registration and matching policy rule.

### Policy ambiguity or permissive fallback

Threat: missing or overlapping rules accidentally grant access.

Control: no-match is `DENY`; multiple matches use conservative precedence (`DENY` > approval > constrained allow > allow). Identity failure is evaluated before a policy allow can take effect.

### Bearer material copied into governance evidence

Threat: raw OIDC tokens/nonces become retained in audit artifacts.

Control: returned identity artifacts retain SHA-256 bindings rather than the raw bearer token or raw nonce.

### Capability creep inside identity or PDP code

Threat: later changes quietly add network/process execution or online JWKS retrieval.

Control: generic CI and the dedicated Authenticated Identity Boundary statically reject network/process imports; `PyJWKClient` is explicitly forbidden.

## Residual risks

v0.2 assumes the separately governed JWKS/config path and workload trust-bundle distribution path are themselves protected. It also assumes the institution signer authenticates/attests the workload correctly before signing; RegAgentOps verifies the resulting evidence but does not implement host-level workload attestation in v0.2.

## Explicit non-claims

v0.2 does not provide or claim:

- OpenID Provider or OAuth authorization-server functionality;
- SPIFFE/SPIRE or SVID protocol conformance;
- online OIDC discovery or remote JWKS retrieval;
- runtime sandboxing;
- production credential brokerage;
- MCP server authentication or execution;
- tamper-proof external audit storage;
- signed human approvals;
- production tool execution;
- prompt-injection detection;
- regulatory or standards certification.

These remain later roadmap boundaries and must not be inferred from an authenticated authorization decision.
