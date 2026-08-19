# RegAgentOps Architecture

## v0.5 boundary

RegAgentOps v0.5 is an **offline authenticated authorization, human-approval, MCP-governance and signed execution-evidence control plane**. It takes the exact v0.4 MCP policy-enforcement outcome, optionally binds the exact v0.3 approval chain, verifies current MCP and emergency-stop state, issues a short-lived one-time execution lease, atomically consumes that lease, and builds a signed result-evidence artifact around an external executor.

It still does **not** connect to an MCP server, obtain production credentials or invoke a requested tool.

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
                            +------------------+
                                               |
current MCP governance ------------------------+
current EmergencyStopState --------------------+
                                               |
                                               v
                                         ExecutionGate
                                               |
                                   short-lived ExecutionLease
                                               |
                                   revalidate MCP + stop state
                                               |
                                   atomic one-time redemption
                                               v
                                  ExecutionLeaseConsumption
                                               |
                                  external executor boundary
                                               |
                                               v
                                      ToolExecutionReceipt
                                               |
                                      executor Ed25519 key
                                               v
                                  SignedToolExecutionReceipt
```

## MCP server and tool identity

The v0.4 MCP controls remain authoritative. The MCP server-reported name is metadata rather than complete authorization identity. RegAgentOps assigns an institution-owned `server_id`, binds it to an explicit `server_identity_digest`, versions the registration contiguously, and maps tools to `mcp:<server_id>:<tool_name>` identities.

`McpToolSnapshot` remains caller supplied and bounded to 128 tools. `McpToolBinding` remains the only institution-owned mapping from exact current MCP evidence into the existing `ToolActionDescriptor` control boundary. Descriptions and annotations remain evidence only and cannot become policy authority.

## Policy-enforcement point

`McpPolicyEnforcementPoint` performs governance precondition checks and authenticated policy evaluation only. `McpPolicyEnforcementResult.execution_performed` remains structurally `false`.

A non-DENY `McpPolicyEnforcementOutcome` retains the exact request and exact `AuthenticatedAuthorizationDecision`. v0.5 consumes this object as the source of authorization evidence instead of reconstructing or reinterpreting the policy decision.

## Exact authorization-to-execution binding

`ExecutionGate.issue_lease()` requires a verified non-DENY MCP outcome with complete server-registration, tool-snapshot, tool-descriptor and authenticated-authorization evidence. Before lease issuance it recomputes the institution MCP registry snapshot and verifies that the exact current binding still resolves to the same server, snapshot and descriptor represented by the policy-enforcement result.

The resulting `ExecutionLease` binds:

- exact `AgentActionEnvelope` digest;
- exact authenticated-authorization digest;
- exact nested policy-decision digest;
- exact MCP policy-enforcement-result digest;
- exact MCP registry-snapshot digest;
- exact current emergency-stop-state digest; and
- exact approval-requirement and approval-resolution digests when approval is required.

The authorization object is therefore not translated into a weaker boolean execution flag.

## Human approval continuation

When the MCP outcome requires approval because of policy effect or high/critical risk escalation, v0.5 requires both the exact `ApprovalRequirement` and exact `ApprovalResolution` before lease issuance.

The requirement must bind the same request and authenticated authorization, requester, tool/action, environment and risk tier. The resolution must bind the exact requirement and permit authorization continuation. An approval resolution from another request, requirement or authorization cannot be substituted.

For non-approval paths, attaching approval artifacts is rejected; the MCP policy result itself must indicate immediate continuation permission.

## Emergency-stop state

`EmergencyStopState` is institution-scoped, append-only and contiguously versioned. An explicit state must exist before execution lease issuance.

A halted state blocks both issuance and redemption. A lease binds the exact current non-halted state digest. Any subsequent state version makes that unconsumed lease stale, even when the new state is also non-halted. This intentionally favors fail-closed invalidation over continuity.

## One-time execution lease

Execution leases have a maximum 120-second lifetime. `ExecutionLeaseLedger` uses an append-only SQLite table keyed by `lease_digest` and an atomic `BEGIN IMMEDIATE` / `INSERT` transaction. A successful redemption yields `ExecutionLeaseConsumption`; a second redemption of the same lease fails closed.

Immediately before consumption, the gate revalidates:

- lease validity window;
- exact lease/outcome/request/authorization/policy linkage;
- unchanged MCP registry snapshot and exact current MCP binding; and
- unchanged non-halted emergency-stop state.

The gate itself still does not dispatch a tool. The intended integration point is that an external executor consumes the lease immediately before its own dispatch operation.

## Result and receipt evidence

After external execution, `ExecutionGate.build_receipt()` builds `ToolExecutionReceipt` from the exact request, outcome, lease and one-time consumption artifact.

The receipt binds request/tool/action/resource/input, the execution lease and consumption, MCP policy-enforcement result, authenticated authorization, policy-decision digest, optional approval chain, emergency-stop state observed at redemption, result digest, execution outcome, timestamps and executor identity.

Only a digest of the represented result is carried; raw output is outside the receipt contract. Both successful and failed attempts can therefore be evidenced without making failure replayable—the lease was already consumed before execution start.

## Signed execution receipt

`SignedToolExecutionReceipt` uses Ed25519 and a domain-separated signing document with purpose `regagentops.tool-execution-receipt.v1`.

The signing document includes the receipt digest plus request, lease, lease-consumption, MCP-result, authenticated-authorization, policy-decision and result digests. `ExecutionTrustBundle` pins executor public keys and validity windows. Verification detects result/receipt tampering and rejects unknown, disabled, expired or mismatched keys.

## Authorization and identity

The v0.1/v0.2 controls remain in force: request, institution, agent, owner, model, tool/action, resource, data classification, purpose, environment, risk tier, input digest and timestamp are bound into `AgentActionEnvelope`; human OIDC identity and institution-controlled workload identity are verified offline; and the resulting authenticated context is institution-signed before policy use.

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means `DENY`. Human approval cannot override a `DENY` or an unverified identity, and the execution layer cannot manufacture a lease from either condition.

## Trust boundaries

1. **Caller → MCP governance registry**: supplied server/tool metadata is untrusted evidence until exact server-registration, identity-pin and currentness checks pass.
2. **Institution MCP configuration → registry**: server approvals, identity pins, tool bindings, classification scope and production-registration flags are privileged institution-owned configuration.
3. **MCP governance registry → authenticated PDP**: only exact current explicit bindings are converted into `ToolRegistry`; annotations do not cross as authority.
4. **Caller → identity/PDP**: action and identity inputs remain untrusted until verified.
5. **Authenticated PDP → approval gate**: approval binds the exact authenticated authorization and cannot override denial.
6. **Approval signer → approval verifier**: private approval keys remain external; public trust material and signed artifacts cross the boundary.
7. **MCP/approval evidence → execution gate**: exact artifacts and digests are revalidated; the gate does not reduce them to caller-controlled booleans.
8. **Emergency-stop configuration → execution gate**: institution-owned append-only state is privileged runtime-governance input.
9. **Execution gate → external executor**: one-time lease consumption is the final RegAgentOps pre-dispatch boundary; actual invocation remains external.
10. **External executor → receipt builder**: executor-reported result digest/outcome is represented evidence, not independently observed truth.
11. **Executor signer → receipt verifier**: private executor keys remain external; signed receipt and public trust material cross the boundary.

## Historical evidence versus current state

Server registrations, MCP snapshots/bindings, approval artifacts, emergency-stop states and execution consumptions remain historical evidence. Current execution authorization is stricter: the exact current MCP state and exact current emergency-stop state must still match the unconsumed lease.

A later governance or stop-state change does not rewrite historical receipts. It prevents stale authorization evidence from being used for a new execution.

## Capability separation

Authorization, identity, approval, MCP-governance and execution modules are statically checked in CI to reject network/process capability imports. MCP has no client/session/discovery interface. The execution module has no tool invocation interface; it issues/consumes evidence and signs/verifies receipts only.

Production credential brokerage, network-isolated execution workers and runtime dispatch enforcement remain separate later roadmap boundaries.

## Standards posture

RegAgentOps uses NIST AI RMF, OpenID/JWT security guidance, workload-identity concepts and MCP trust/safety guidance as design inputs. These are not protocol-conformance or certification claims.