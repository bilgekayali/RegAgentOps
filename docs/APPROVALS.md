# Human Approval and Delegated Authority

## Scope

RegAgentOps v0.3 adds a bounded human-approval gate after authenticated policy evaluation. It does not create an execution service and it does not allow a human approval to override an identity or policy `DENY`.

The approval layer answers a narrower question:

> Has the already-authenticated, already-governed request received the required number of valid, in-scope, cryptographically verifiable human approvals for this specific request and authorization artifact?

## Control flow

```text
AgentActionEnvelope
        |
        v
AuthenticatedPolicyEngine
        |
        | AuthenticatedAuthorizationDecision
        v
ApprovalGate.build_requirement()
        |
        | ApprovalRequirement (when required)
        v
Human approver(s)
        |
        | SignedApprovalStatement
        v
Authority scope + signature + expiry checks
        |
        v
ApprovalReplayLedger
        |
        | one-time requirement redemption
        v
ApprovalResolution
```

An `ApprovalResolution` can permit **authorization continuation**. It does not execute a tool, create credentials, or prove that a later execution matched the approved request.

## Escalation policy

`ApprovalEscalationPolicy` applies a conservative floor:

- a policy decision of `REQUIRE_HUMAN_APPROVAL` requires at least the configured policy minimum;
- `high` risk requires at least the configured high-risk minimum;
- `critical` risk requires at least the configured critical-risk minimum;
- the default reference policy uses one approval for high risk and two distinct approvals for critical risk;
- high/critical and policy-required approvals enforce requester/approver separation.

A base `DENY` cannot enter the approval gate. Approval is therefore not an exception path around policy.

## Delegated authority

Approval authority is represented by `ApprovalAuthorityGrant` artifacts. Each grant binds:

- institution;
- issuer principal;
- subject/approver principal;
- role id;
- allowed tool ids;
- allowed actions;
- allowed environments;
- maximum risk tier;
- validity interval;
- whether further delegation is allowed;
- parent grant digest for delegated grants.

Delegated grants are validated against their parent. A child grant cannot:

- add tools or actions not present in the parent;
- add environments not present in the parent;
- increase the maximum risk tier;
- extend beyond the parent's validity interval;
- originate from anyone other than the parent grant subject;
- exist when the parent does not permit delegation.

Delegation cycles are rejected.

## Signed approval artifact

`ApprovalStatement` binds the exact:

- approval requirement digest;
- request digest;
- approver principal;
- authority grant digest;
- approve/deny vote;
- issue and expiry timestamps;
- rationale digest.

The raw rationale is not required in the cryptographic artifact; a SHA-256 digest can bind separately governed rationale/evidence.

The signed form uses Ed25519 and a domain-separated signing document with purpose:

`regagentops.human-approval.v1`

Approval trust keys are institution- and principal-scoped. Disabled, expired, ambiguous, wrong-principal, or invalid-signature keys fail closed.

Approval statements are limited to a 15-minute lifetime in v0.3.

## Replay prevention

The reference `ApprovalReplayLedger` is append-only at the API level and uses SQLite transactional insertion.

The primary one-time key is the **approval requirement digest**, not only the package digest. Once a valid denial or a sufficient approval set terminally resolves a requirement, the same requirement cannot be redeemed again using a different approval package.

An insufficient package does not consume the requirement; additional valid, distinct approvals may still complete it before expiry.

## Denial semantics

Any valid in-scope `DENY` vote makes the submitted approval set terminally denied and consumes the requirement. An alternative approval package cannot later redeem the same requirement.

To retry after a denial, the caller must obtain a new approval requirement through a new governed decision flow.

## Trust assumptions and residual risk

v0.3 assumes that the supplied `AuthenticatedAuthorizationDecision` came from the trusted local RegAgentOps PDP path. The approval gate binds that artifact by digest but does not independently sign the PDP decision in this milestone.

The reference authority bundle and approval trust bundle are privileged configuration inputs. v0.3 validates their internal scope and cryptographic use, but signed configuration change control and durable tenant-isolated governance storage are later roadmap boundaries.

The SQLite replay ledger provides application-level one-time redemption. It is not a physical WORM store, external audit anchor, or distributed consensus service.

## Non-claims

RegAgentOps v0.3 does not provide or claim:

- production tool execution;
- credential issuance or brokerage;
- a generic workflow/BPM approval system;
- non-repudiation beyond the defined cryptographic artifact boundary;
- independent timestamp authority;
- external immutable audit storage;
- regulatory approval or compliance certification;
- proof that a future execution matched an approved request.

Exact authorization-to-execution binding and signed execution receipts are intentionally reserved for the v0.5 roadmap boundary.
