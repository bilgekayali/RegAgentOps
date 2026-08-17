# Threat Model — v0.3

## Protected assets

- authorization policy integrity;
- institution, human-owner, agent, model and workload identity bindings;
- OIDC verifier configuration and pinned JWKS integrity;
- institution identity/context trust material;
- approval authority/delegation integrity;
- approver signing-key trust and approval-signature integrity;
- approval requirement and replay-ledger integrity;
- tool/action registry integrity;
- authorization, identity and approval evidence integrity;
- separation between governance decisions and execution capabilities.

## Trust boundaries

1. **Caller → identity/PDP**: action, identity and request inputs are untrusted until verified.
2. **Human identity registry / pinned JWKS → OIDC verifier**: privileged trust configuration; no online discovery.
3. **Institution workload/context signer → verifier**: private keys remain outside the verifier.
4. **Registry/policy configuration → PDP**: privileged administrative input.
5. **Trusted local PDP → approval gate**: v0.3 binds the authenticated authorization artifact by digest but does not independently sign the PDP result.
6. **Approval authority bundle → approval gate**: privileged role/delegation configuration.
7. **Human approval signer → approval verifier**: private approval keys remain outside RegAgentOps; signed statements and public trust material cross the boundary.
8. **Approval replay ledger → future PEP**: terminal approval resolution is one-time governance evidence, not execution proof.

## Primary threats and controls

### Identity substitution, JWT key confusion and stale authentication

Controls from v0.2 remain: registered owner→provider→subject binding, pinned issuer/client/audience/algorithm policy, nonce and time checks, rejection of remote key-selection headers, short-lived institution workload identity, institution-signed authenticated context and fail-closed registration-drift checks.

### Human approval overriding a policy denial

Threat: an operator uses an approval artifact as a break-glass bypass around policy or identity failure.

Control: `ApprovalGate.build_requirement()` refuses base `DENY`; `resolve()` also rejects unverified identity or `DENY`. Approval can satisfy a continuation condition only for requests not already denied.

### Requester self-approval

Threat: the agent owner approves their own high-risk or policy-gated request.

Control: policy-required, high-risk and critical-risk requirements set requester/approver separation. Authority verification rejects the request owner as approver in those flows.

### Delegation privilege expansion

Threat: a delegated approver creates a child grant with broader authority than the parent.

Controls: child tool/action/environment sets must be subsets of the parent; maximum risk tier cannot increase; child validity cannot extend beyond the parent; issuer must equal parent subject; parent must explicitly permit delegation; cycles are rejected.

### Approval key substitution

Threat: a valid signature from a different principal or key is presented as the required approver.

Controls: approval trust keys are bound to institution + principal + key id; statement approver must match signer principal; active status, validity interval, Ed25519 algorithm and signature are checked before authority evaluation.

### Approval artifact tampering

Threat: request, requirement, authority grant, vote, expiry or rationale binding changes after approval.

Control: `SignedApprovalStatement` signs a domain-separated document that binds the statement digest plus exact requirement/request/grant/principal identifiers. Tampering invalidates the signature or digest.

### Insufficient or duplicate approvals counted as quorum

Threat: one principal is counted multiple times or a critical request passes with too few approvals.

Controls: package approval IDs and approver principals are unique; high/critical escalation enforces configured minimums; default critical minimum is two distinct approvers.

### Approval replay with an alternative package

Threat: the same requirement is resolved once, then replayed with another combination of approvals.

Control: reference replay storage uses the approval **requirement digest** as its primary one-time key. A valid denial or sufficient approval set transactionally consumes the requirement. Later packages for that requirement fail closed.

### Denial omission / bypass

Threat: after a valid denial is presented and resolved, another package omits the denial and seeks approval.

Control: a valid denial terminally consumes the requirement; an alternative package cannot redeem it afterward. A retry requires a new governed requirement.

### Approval expiry abuse

Threat: stale approval or stale authority remains usable.

Controls: approval statement lifetime is capped at 15 minutes; requirement lifetime is bounded; authority grants and trust keys have explicit validity windows; every resolution rechecks current time.

### Capability creep

Threat: approval code quietly gains network/process or execution capability.

Controls: generic CI and the dedicated Human Approval Boundary reject network/process imports in approval modules. The replay ledger has no destructive update/delete API and the dedicated workflow checks the append-only SQL surface.

## Residual risks

v0.3 assumes the `AuthenticatedAuthorizationDecision` supplied to the approval gate came from the trusted local RegAgentOps PDP path. The gate binds its digest but does not independently sign PDP decisions in this milestone.

Authority bundles and approval trust bundles are privileged configuration and are not yet protected by signed configuration change control or tenant-isolated durable storage. Those are later roadmap boundaries.

The SQLite replay ledger is application-level local state. It is not distributed consensus, physical WORM storage or external audit anchoring.

v0.3 also does not prove that a future tool execution corresponds to an approved request. Exact authorization-to-execution binding is reserved for the signed execution receipt milestone.

## Explicit non-claims

v0.3 does not provide or claim:

- OpenID Provider or OAuth authorization-server functionality;
- SPIFFE/SPIRE or SVID protocol conformance;
- online OIDC discovery or remote JWKS retrieval;
- generic BPM/workflow approval functionality;
- production credential brokerage;
- MCP execution;
- production tool execution;
- runtime sandboxing;
- external immutable audit storage;
- independent timestamp authority;
- regulatory or standards certification.
