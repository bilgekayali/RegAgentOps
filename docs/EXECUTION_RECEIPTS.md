# Signed Execution Receipts

RegAgentOps v0.5 adds a non-executing control boundary between a positive governed authorization path and an external tool executor. The core issues freshness-bounded, executor-bound, one-time execution leases, atomically redeems them immediately before dispatch, and records cryptographically signed execution-result evidence. It still does not connect to MCP servers or invoke tools itself.

## Control sequence

```text
McpPolicyEnforcementOutcome
        |
        +-- exact request + authenticated authorization
        +-- exact MCP server/snapshot/descriptor evidence
        +-- policy decision + constraints
        |
        +-- authorization freshness <= 120 seconds
        +-- if required: fresh ApprovalRequirement + exact ApprovalResolution
        +-- intended executor_id
        +-- current EmergencyStopState must be non-halted
        +-- current MCP governance snapshot must be unchanged
        v
ExecutionLease (<= 120 seconds, executor-bound)
        |
        +-- current EmergencyStopState rechecked
        +-- current MCP governance snapshot rechecked
        +-- exact executor_id rechecked
        +-- atomic append-only one-time redemption
        v
ExecutionLeaseConsumption (executor-bound)
        |
        |  external executor performs the already-bound action
        v
ToolExecutionReceipt
        |
        +-- consumption must exist exactly in append-only ledger
        +-- exact request/input/tool/action/resource binding
        +-- exact executor/lease/consumption binding
        +-- exact MCP policy-enforcement result binding
        +-- exact authenticated authorization + policy-decision binding
        +-- exact approval chain digests when approval was required
        +-- exact emergency-stop state at lease redemption
        +-- result digest + SUCCEEDED/FAILED outcome
        v
SignedToolExecutionReceipt (Ed25519)
```

## Exact authorization-to-execution binding

An execution lease can be issued only from a non-DENY `McpPolicyEnforcementOutcome` with verified authenticated identity and complete governed MCP evidence. Lease issuance must occur no more than 120 seconds after the represented policy evaluation, preventing an otherwise unchanged but arbitrarily stale authorization from being converted into a fresh execution capability.

The lease binds the exact intended `executor_id`, request digest, authenticated authorization digest, nested policy-decision digest, MCP policy-enforcement result digest, MCP registry snapshot digest, and emergency-stop state digest.

For approval-required requests, the lease additionally binds both the exact `ApprovalRequirement` and exact `ApprovalResolution`. The requirement must reference the same request, authenticated authorization and signed identity-context evidence; its requester/tool/action/environment/risk scope must match the request; and it must still be valid at lease issuance. The resolution must reference that exact requirement, fall within the requirement validity window, and permit authorization continuation. A resolution from another request or authorization cannot be attached to the lease.

## One-time, executor-bound execution lease

`ExecutionLease` is intentionally short-lived. v0.5 caps the lease lifetime at 120 seconds. The executor identity is part of the lease digest. Redemption requires the same `executor_id`, so an issued lease cannot silently be transferred to another executor identity.

Redemption must occur inside the validity window and is recorded atomically in an append-only SQLite ledger keyed by the lease digest. The resulting `ExecutionLeaseConsumption` also carries the executor identity. A second redemption of the same lease fails closed.

Before redemption, RegAgentOps revalidates that the MCP governance snapshot is unchanged and that the exact server registration, tool snapshot, and tool descriptor represented by the original policy-enforcement result are still current.

## Emergency stop

`EmergencyStopState` is institution-scoped, append-only, versioned state. An institution must have explicit stop state before an execution lease can be issued. A halted state blocks lease issuance and redemption.

The lease binds the exact current non-halted stop-state digest. If the state changes after lease issuance, even to another non-halted version, the old lease becomes stale and must be replaced. This deliberately favors fail-closed behavior over lease continuity.

## Execution receipts and ledger provenance

RegAgentOps does not retain raw tool output in the receipt. The caller supplies a SHA-256 `result_digest` over the result artifact it intends to evidence and an explicit `SUCCEEDED` or `FAILED` execution outcome.

`ToolExecutionReceipt` binds:

- request, tool, action, resource and input digest;
- intended executor identity;
- execution lease and one-time lease-consumption digest;
- MCP policy-enforcement result;
- authenticated authorization and nested policy-decision digest;
- approval requirement/resolution digests when required;
- emergency-stop state observed at redemption;
- result digest and execution outcome; and
- start and completion timestamps.

Receipt construction does not trust a caller-supplied `ExecutionLeaseConsumption` merely because its fields are well formed. The exact consumption artifact must already match the append-only ledger record for that lease. This prevents a caller from manufacturing apparent one-time-redemption evidence and then obtaining a signed receipt over it.

The receipt builder also requires the executor to match the lease, execution start to occur after one-time lease consumption, and execution start to occur before lease expiry. Completion may follow start, including a failed execution, but the same lease cannot be retried.

## Signature boundary

Execution receipts are signed with Ed25519 using a domain-separated signing document whose purpose is `regagentops.tool-execution-receipt.v1`. The signing document includes the receipt digest, request digest, lease and consumption digests, MCP result digest, authenticated authorization digest, policy-decision digest, result digest, executor identity, key id and algorithm.

`ExecutionTrustBundle` pins institution-owned executor public keys and validity intervals. Verification rejects unknown, disabled, mismatched or cryptographically invalid keys and requires that the key was valid when the represented receipt completed. A historical receipt can still be verified after the key's signing-validity window has elapsed, provided the preserved trust bundle still treats that key as trusted for historical verification; key expiry does not by itself erase historical evidence.

## Failure semantics

The v0.5 boundary fails closed when, among other conditions:

- policy or identity produced a DENY/unverified outcome;
- authorization evidence is older than the issuance freshness bound;
- governed MCP evidence is incomplete or has drifted;
- an approval-required request lacks the exact, still-valid requirement/resolution chain;
- approval continuation is not permitted;
- emergency stop is active or its bound state changed;
- the lease is expired, not yet valid, already consumed, or presented by another executor;
- a purported lease consumption is absent from or differs from the append-only ledger record;
- a receipt is attached to a different executor, request, lease, consumption, MCP result or policy decision; or
- the signed receipt or result digest is modified.

## Assurance boundary and non-claims

A valid v0.5 receipt proves that the represented receipt artifact was signed by a trusted executor key and binds the represented authorization, governance, recorded lease-consumption and result digests. It does **not** independently prove that the external tool implementation was correct, that the represented result bytes were truthful, that an external executor checked emergency-stop state at any instant after lease redemption, that the MCP server behaved as represented, or that the action was legally/regulatorily compliant.

The RegAgentOps core remains offline and non-invoking. Runtime dispatch, credential handling, network isolation, executor authentication beyond the represented executor identity, and production executor enforcement remain outside the v0.5 core boundary and are addressed by later production-reference milestones.