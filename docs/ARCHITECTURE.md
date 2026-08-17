# RegAgentOps Architecture

## v0.3 boundary

RegAgentOps v0.3 is an **offline authenticated authorization and human-approval control plane**. It verifies bounded human/workload identity, evaluates institution policy, determines whether human approval is required by policy or risk escalation, verifies scoped signed approvals, and emits evidence-oriented authorization/approval artifacts.

It still does **not** invoke the requested tool.

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
AgentActionEnvelope --------+-------- PolicyBundle
                            |
                            v
               AuthenticatedPolicyEngine
                            |
                            v
          AuthenticatedAuthorizationDecision
                            |
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
                 Caller / future PEP
```

## Authorization and identity

The v0.1/v0.2 controls remain in force: request, tenant, agent, owner, model, tool/action, resource, data classification, purpose, environment, risk tier, input digest and timestamp are bound into `AgentActionEnvelope`; human OIDC identity and institution-controlled workload identity are verified offline; the resulting authenticated context is itself institution-signed before policy use.

Policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching policy rule means `DENY`. Human approval cannot override a `DENY` or an unverified identity.

## Approval requirement

`ApprovalGate.build_requirement()` creates an approval requirement only when approval is actually required:

- policy returns `REQUIRE_HUMAN_APPROVAL`; or
- request risk is `high`; or
- request risk is `critical`.

The reference escalation policy requires at least one approval for high risk and two distinct approvals for critical risk. Policy-required, high-risk and critical-risk flows require requester/approver separation.

The requirement binds the exact request digest, authenticated authorization digest, signed identity-context digest, requester, tool/action, environment, risk tier, escalation-policy digest and expiry.

## Delegated authority

Approval authority is separate from signing-key trust.

`ApprovalAuthorityGrant` defines what a principal may approve: tool ids, actions, environments, maximum risk tier and validity interval. Direct grants can permit delegation. Delegated grants bind their parent grant digest and are recursively validated.

A delegated grant cannot widen the parent tool, action or environment scope, cannot raise its maximum risk tier, cannot outlive its parent and cannot be issued by anyone other than the parent grant subject. Cycles fail closed.

## Signed approvals

An `ApprovalStatement` binds the requirement, request, approver, authority-grant digest, vote, timestamps and rationale digest. The signed form uses Ed25519 with domain-separated purpose `regagentops.human-approval.v1`.

Approval trust keys are institution- and principal-scoped. Key status, key lifetime, statement lifetime, principal binding and signature are checked before authority evaluation.

## One-time resolution

`ApprovalReplayLedger` is a reference append-only SQLite redemption boundary. A valid denial or a sufficient set of valid approvals terminally consumes the **approval requirement digest** in a transaction. This prevents the same requirement from being resolved again using another approval package.

An insufficient package does not consume the requirement and may be completed with additional distinct valid approvals before expiry.

`ApprovalResolution.authorization_continuation_permitted=true` means only that the v0.3 approval gate has been satisfied. It is not proof of tool execution and it does not issue credentials.

## Trust boundaries

1. Caller → identity/PDP: caller input is untrusted until verified.
2. Registry/policy/trust configuration → control plane: privileged configuration.
3. Authenticated PDP → approval gate: v0.3 assumes the supplied authenticated authorization artifact is produced by the trusted local RegAgentOps PDP path; the approval gate binds it by digest but does not independently sign the PDP result.
4. Approval signer → approval verifier: private-key custody remains outside RegAgentOps; only signed artifacts and public trust material cross the boundary.
5. Approval gate → future PEP/executor: v0.3 emits continuation evidence only; execution is outside the milestone.

## Capability separation

Authorization, identity and approval modules are statically checked in CI to reject network/process capability imports. OIDC remains offline and approval verification performs no external lookup. The replay ledger uses local SQLite only and exposes no destructive update/delete API.

Future MCP connectivity, credential brokerage and execution receipts remain separate roadmap boundaries.

## Standards posture

RegAgentOps uses NIST AI RMF, OpenID/JWT security guidance, workload-identity concepts and MCP trust/safety guidance as design inputs. These are not protocol-conformance or certification claims.
