# RegAgentOps Architecture

## v0.2 boundary

RegAgentOps v0.2 is an **offline authenticated policy decision point (PDP)**. It verifies bounded human/workload identity inputs, binds them to a registered agent, signs that authenticated context with institution trust, evaluates a bounded authorization request, and emits evidence-oriented identity and authorization artifacts. It does not invoke the requested tool.

```text
OIDC ID token + pinned JWKS          Institution workload signer
              |                                 |
              v                                 v
    HumanIdentityAssertion          SignedWorkloadIdentity
              \                                 /
               \                               /
                +---- AgentDescriptor --------+
                            |
                            v
                AuthenticatedAgentIdentity
                            |
                  institution signature
                            v
             SignedAuthenticatedAgentIdentity
                            |
AgentActionEnvelope --------+-------- PolicyBundle
                            |
                            v
               AuthenticatedPolicyEngine
                            |
                            v
          AuthenticatedAuthorizationDecision
                            |
                            v
                 Caller / future PEP
```

A future MCP policy-enforcement point (PEP), signed human-approval service, credential broker, and execution-receipt layer remain outside the v0.2 runtime boundary.

## Authorization inputs

`AgentActionEnvelope` binds institution, agent identity, human owner, model provider/model identifier, tool/action, resource, data classification, business purpose, environment, risk tier, proposed-input SHA-256 digest, and request timestamp. Raw prompts, raw tool arguments, credentials, tokens, and secret values are not part of the authorization envelope.

## Identity inputs

Human identity is derived from an OIDC ID token verified offline against operator-supplied pinned JWKS. The local `HumanIdentityRegistry` binds an institution-local human owner to the expected OIDC provider and subject.

Workload identity is represented by a short-lived statement signed by an institution-controlled Ed25519 signer. The statement binds the institution, agent, human owner, model identity, workload id, challenge digest, and validity interval.

`AuthenticatedAgentIdentity` binds digests of the registered agent, verified human assertion, and verified workload identity. Its validity ends at the earlier underlying identity expiry. Before policy use, the context itself is domain-separated and Ed25519-signed as `SignedAuthenticatedAgentIdentity`. This prevents a caller from fabricating the context dataclass and presenting it as verified identity evidence.

## Decision semantics

Rules are explicit and institution-scoped. There are no wildcard identities in the current core. Multiple matches use conservative monotonic precedence:

1. `DENY`
2. `REQUIRE_HUMAN_APPROVAL`
3. `ALLOW_WITH_CONSTRAINTS`
4. `ALLOW`

No matching rule means `DENY`.

Authenticated evaluation adds a prior fail-closed gate. An unsigned context, invalid context signature, expired context, identity mismatch, disabled/missing agent registration, or registration-digest drift produces `DENY` before a policy allow can take effect.

An `ALLOW` result is an authorization artifact only. v0.2 contains no executor and therefore cannot itself perform the authorized action.

## Registry and trust binding

The request must match the registered agent's institution, human owner, model provider, and model identifier. The requested tool/action must also be registered for the same institution and data classification. Production use requires an explicit `production_registered` tool/action flag.

Human identity registration separately pins the institution-local owner to an OIDC provider and subject. Workload/context trust bundles are institution-scoped and key-id unique. Domain-separated signing documents prevent a workload statement signature from being reused as an authenticated-context signature.

## Deterministic evidence

Artifacts use canonical JSON and SHA-256 digests. Authorization evidence records the request digest, policy-bundle digest, matched rule IDs, constraints, reason codes, and evaluation timestamp. Authenticated authorization binds the **signed** identity-context digest.

Raw OIDC bearer tokens and raw transaction nonces are not persisted in returned identity artifacts; only cryptographic digests are retained.

## Capability separation

The authorization and identity modules are statically checked in CI to prevent network/process imports. OIDC verification does not use provider discovery, remote JWKS retrieval, or PyJWT `PyJWKClient`. Signing is exposed through provider protocols so production private-key custody can remain behind institution-owned HSM/KMS signing services.

## Standards posture

RegAgentOps is informed by NIST AI RMF risk-governance concepts, OpenID Connect/JWK/JWT security guidance, SPIFFE workload-identity concepts, and MCP trust/safety guidance. These references are design inputs, not protocol-conformance or certification claims.
