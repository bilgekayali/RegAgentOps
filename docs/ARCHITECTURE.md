# RegAgentOps Architecture

## v0.4 boundary

RegAgentOps v0.4 is an **offline authenticated authorization, human-approval and MCP-governance control plane**. It accepts caller-supplied MCP server/tool metadata only after institution-owned server approval and identity pinning, converts exact current tool metadata into explicit governed tool bindings, and then reuses the existing authenticated policy engine.

It still does **not** connect to an MCP server or invoke a requested tool.

```text
OIDC ID token + pinned JWKS       Institution workload signer
              |                              |
              v                              v
    HumanIdentityAssertion       SignedWorkloadIdentity
              \                              /
               +---- AgentDescriptor -------+
                            |
                            v
                AuthenticatedAgentIdentity
                            |
                  institution signature
                            v
             SignedAuthenticatedAgentIdentity
                            |
                            +-------------------------------+
                                                            |
Institution-approved MCP server                            |
      |                                                     |
      v                                                     |
McpServerRegistration                                      |
      |                                                     |
caller-supplied bounded tool snapshot                      |
      v                                                     |
McpToolSnapshot                                             |
      |                                                     |
explicit institution-owned tool binding                    |
      v                                                     |
McpToolBinding -> derived ToolRegistry                      |
      |                                                     |
      +------------- AgentActionEnvelope + PolicyBundle ----+
                            |
                            v
                 McpPolicyEnforcementPoint
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
                /           |            \
       authority grants   signatures   replay ledger
                \           |            /
                 +----------+-----------+
                            |
                            v
                  ApprovalResolution
                            |
                            v
                 Caller / future executor
```

## MCP server and tool identity

The MCP server-reported name is treated as metadata rather than the complete authorization identity. RegAgentOps assigns an institution-owned `server_id`, binds it to an explicit `server_identity_digest`, and versions the registration contiguously.

A governed MCP tool identity is derived as `mcp:<server_id>:<tool_name>`. This keeps same-named tools on different approved servers in separate namespaces.

`McpToolSnapshot` is caller supplied and bounded to 128 tools. It binds the exact server-registration digest, observed server name, observed server-identity digest and exact metadata digests for every represented tool. Duplicate names within a server and conflicting semantic-latest snapshots fail closed.

## Untrusted MCP metadata

Descriptions, input/output schemas and annotations are represented as immutable evidence digests. In particular, annotations are not translated into policy effects, risk tiers, production eligibility or approval requirements.

The institution-owned `McpToolBinding` is the only v0.4 artifact that maps an MCP tool to the existing `ToolActionDescriptor` control boundary. It explicitly sets allowed data classifications, production-registration state and enabled state.

Any new current server registration or newer tool snapshot makes an older binding non-current until an explicit binding version is registered against the new evidence.

## Policy-enforcement point

`McpPolicyEnforcementPoint` performs only governance precondition checks and authenticated policy evaluation. It derives a `ToolRegistry` from exact current bindings and delegates authorization to `AuthenticatedPolicyEngine`; it does not create a separate MCP policy language.

If MCP governance preconditions fail, the adapter returns `DENY` without entering the authenticated policy engine. If preconditions pass, `McpPolicyEnforcementResult` binds the MCP registry snapshot, exact server/snapshot/descriptor evidence, authenticated authorization digest, decision, constraints, approval requirement flag and continuation permission.

`execution_performed` is structurally fixed to `false` in v0.4.

## Authorization and identity

The v0.1/v0.2 controls remain in force: request, tenant, agent, owner, model, tool/action, resource, data classification, purpose, environment, risk tier, input digest and timestamp are bound into `AgentActionEnvelope`; human OIDC identity and institution-controlled workload identity are verified offline; the resulting authenticated context is itself institution-signed before policy use.

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means `DENY`. Human approval cannot override a `DENY` or an unverified identity.

## Human approval continuation

The v0.3 approval plane remains separate from the MCP adapter. When authenticated policy returns `REQUIRE_HUMAN_APPROVAL`, the exact `AuthenticatedAuthorizationDecision` retained in `McpPolicyEnforcementOutcome` can be passed to `ApprovalGate.build_requirement()`.

The requirement therefore continues to bind the exact request digest, authenticated authorization digest, signed identity-context digest, requester, namespaced MCP tool/action, environment, risk tier, escalation-policy digest and expiry. Requester/approver separation, delegated authority, Ed25519 signatures and one-time replay prevention are unchanged.

## One-time resolution

`ApprovalReplayLedger` remains the v0.3 append-only SQLite redemption boundary. A valid denial or sufficient set of valid approvals terminally consumes the approval requirement digest. Approval resolution is continuation evidence only and still does not prove execution.

## Trust boundaries

1. **Caller → MCP governance registry**: supplied server/tool metadata is untrusted evidence until exact server-registration, identity-pin and currentness checks pass.
2. **Institution MCP configuration → registry**: server approvals, identity pins, tool bindings, classification scope and production-registration flags are privileged institution-owned configuration.
3. **MCP governance registry → authenticated PDP**: only exact current explicit bindings are converted into the legacy `ToolRegistry`; annotations do not cross this boundary as authority.
4. **Caller → identity/PDP**: action and identity inputs remain untrusted until verified.
5. **Registry/policy/trust configuration → control plane**: privileged configuration.
6. **Authenticated PDP → approval gate**: the approval gate binds the authenticated authorization artifact by digest but does not independently sign the PDP result.
7. **Approval signer → approval verifier**: private-key custody remains outside RegAgentOps; only signed artifacts and public trust material cross the boundary.
8. **Approval gate → future executor**: v0.4 emits continuation evidence only; execution and execution receipts remain outside this milestone.

## Historical evidence versus current state

Server registrations, tool snapshots and bindings are append-only evidence in the MCP registry digest. Historical artifacts are not deleted when governance changes.

Current MCP authorization, however, requires the exact latest approved server registration, a unique latest snapshot bound to that registration and the latest explicit binding for the exact descriptor. This prevents historical metadata from silently becoming current authorization state.

## Capability separation

Authorization, identity, approval and MCP-governance modules are statically checked in CI to reject network/process capability imports. The MCP module additionally has no client/session/discovery interface and is checked for autonomous discovery/network markers. OIDC remains offline and approval verification performs no external lookup.

MCP connectivity, credential brokerage, one-time execution leases and signed execution receipts remain separate later roadmap boundaries.

## Standards posture

RegAgentOps uses NIST AI RMF, OpenID/JWT security guidance, workload-identity concepts and MCP trust/safety guidance as design inputs. These are not protocol-conformance or certification claims.
