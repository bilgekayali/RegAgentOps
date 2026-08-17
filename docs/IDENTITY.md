# Authenticated Agent Identity Boundary

RegAgentOps v0.2 adds authenticated human and workload identity to the v0.1 authorization core. The objective is not to become an identity provider. The objective is to produce bounded, evidence-oriented identity artifacts that can be tied deterministically to an authorization decision.

## Trust chain

```text
Registered human owner
       |
       | OIDC ID token + transaction nonce
       v
Pinned OIDC verifier configuration + operator-supplied JWKS
       |
       | offline signature / issuer / audience / subject / time checks
       v
HumanIdentityAssertion

Institution-owned workload signer / HSM / signing service
       |
       | short-lived signed workload statement
       v
WorkloadIdentityTrustBundle
       |
       | offline Ed25519 verification
       v
SignedWorkloadIdentity

HumanIdentityAssertion + SignedWorkloadIdentity + AgentDescriptor
       |
       v
AuthenticatedAgentIdentity
       |
       | institution Ed25519 context signature
       v
SignedAuthenticatedAgentIdentity
       |
       v
AuthenticatedPolicyEngine
       |
       v
AuthenticatedAuthorizationDecision
```

## Human identity

`OidcVerifierConfig` pins the institution, provider, HTTPS issuer, client id, accepted asymmetric signing algorithms, maximum token age, and optional accepted ACR values.

OIDC verification is deliberately offline. RegAgentOps does not perform provider discovery and does not retrieve JWKS over the network. The caller must supply the JWKS document from its separately governed configuration path.

The verifier requires and checks:

- an explicitly allowed asymmetric algorithm (`RS256`, `PS256`, `ES256`, or `EdDSA`);
- one bounded `kid` resolving to exactly one JWK;
- JWK `alg`, `use`, and `key_ops` compatibility when those fields are present;
- configured issuer and client/audience;
- `azp` when a token has multiple audiences;
- exact subject binding to an institution-scoped `HumanIdentityRegistry` entry;
- exact transaction nonce;
- `iat`, `exp`, optional `nbf`, and configured maximum token age;
- optional configured ACR requirement;
- rejection of `jku`, `x5u`, and `crit` headers so the token cannot redirect verification to dynamic key material.

The returned `HumanIdentityAssertion` stores SHA-256 digests of the token, claims, nonce, JWKS, and provider configuration. It does not retain the raw bearer token or raw nonce.

## Workload identity

A `WorkloadIdentityStatement` binds institution, agent id, human owner, model provider/model id, workload id, challenge digest, and issuance/expiry timestamps.

The lifetime is capped at 15 minutes. v0.2 signs workload statements with Ed25519 through the provider-neutral `WorkloadIdentitySigner` protocol. RegAgentOps therefore does not need to own or persist the institution private key; deployments can implement the signer with an HSM, KMS-backed signing service, or another institution-controlled signing boundary.

`WorkloadIdentityTrustBundle` contains public trust keys, validity intervals, and lifecycle status. Current authentication accepts only the exact active key referenced by the signed identity and verifies the signature entirely offline.

## Agent and context binding

`establish_authenticated_agent_identity()` succeeds only when the human assertion, signed workload identity, and registered `AgentDescriptor` agree on institution, agent, human owner, model provider, and model id.

The resulting `AuthenticatedAgentIdentity` binds digests of all three trust inputs and expires at the earlier human/workload identity expiry. **That unsigned dataclass is not sufficient for policy evaluation.** Before use it must be wrapped as `SignedAuthenticatedAgentIdentity` using an institution-controlled Ed25519 signer. The signing document is domain-separated and binds the institution, agent, owner, provider, workload id, complete identity digest, key id, and algorithm.

`AuthenticatedPolicyEngine` verifies the signed context against an institution trust bundle before evaluating policy. It then rechecks that:

- the identity context belongs to the same institution, agent, and human owner as the request;
- the context is currently valid;
- the registered agent still exists and is enabled;
- the agent registration digest has not changed since the context was established.

An unsigned context, invalid/tampered context signature, expired context, or any other identity failure produces a non-executable `DENY` before a policy allow can take effect.

## Failure semantics

Identity verification is fail-closed. Network failure is not a concept inside the verifier because the verifier has no network capability. Missing trust material, ambiguous key ids, invalid signatures, unsigned/fabricated contexts, expired identities, registration drift, subject mismatch, provider mismatch, or tenant mismatch all prevent authenticated authorization.

## Non-claims

v0.2 does **not** claim that RegAgentOps is:

- an OpenID Provider or OAuth authorization server;
- a SPIFFE or SPIRE implementation;
- JWT-SVID or X.509-SVID conformant;
- an online JWKS discovery/cache service;
- a credential broker;
- an MCP execution gateway;
- a production action executor;
- a regulatory or standards certification product.

SPIFFE concepts are used only as design inspiration for separating workload identity namespace, verifiable identity material, and trust bundles. RegAgentOps keeps its own artifact contracts and does not claim protocol compatibility.

## Reference inputs

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- SPIFFE specifications: https://spiffe.io/docs/latest/spiffe-specs/
