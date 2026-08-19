# Threat Model — v0.5

## Protected assets

- authorization policy integrity;
- institution, human-owner, agent, model and workload identity bindings;
- OIDC verifier configuration and pinned JWKS integrity;
- institution identity/context trust material;
- approval authority/delegation integrity;
- approver signing-key trust and approval-signature integrity;
- approval requirement and replay-ledger integrity;
- MCP server approval and identity-pin integrity;
- MCP tool snapshot and explicit tool-binding integrity;
- execution-lease integrity and one-time consumption state;
- emergency-stop state integrity;
- executor signing-key trust and signed execution-receipt integrity;
- result-digest and policy-decision linkage;
- separation between untrusted MCP metadata and policy authority;
- separation between RegAgentOps governance/evidence and external execution capability.

## Trust boundaries

1. **Caller → MCP governance registry**: supplied MCP server/tool metadata is untrusted until exact governed server, identity-pin and currentness checks pass.
2. **Institution MCP configuration → registry**: server approval, server identity pins, tool bindings, classification scope and production-registration flags are privileged administrative input.
3. **MCP registry → authenticated PDP**: only exact current explicit bindings become `ToolActionDescriptor` entries; tool annotations do not become policy authority.
4. **Caller → identity/PDP**: action, identity and request inputs are untrusted until verified.
5. **Human identity registry / pinned JWKS → OIDC verifier**: privileged trust configuration; no online discovery.
6. **Institution workload/context signer → verifier**: private keys remain outside the verifier.
7. **Registry/policy configuration → PDP**: privileged administrative input.
8. **Trusted local PDP → approval gate**: exact authenticated authorization is digest-bound and cannot be overridden by approval.
9. **Approval authority bundle → approval gate**: privileged role/delegation configuration.
10. **Human approval signer → approval verifier**: private approval keys remain outside RegAgentOps; signed statements and public trust material cross the boundary.
11. **MCP/approval evidence → execution gate**: exact request, authorization, policy-decision, MCP result and approval artifacts are revalidated before lease issuance.
12. **Emergency-stop configuration → execution gate**: institution-owned append-only stop state is privileged execution-governance input.
13. **Execution lease ledger → external executor**: atomic one-time consumption is the final RegAgentOps pre-dispatch boundary.
14. **External executor → receipt builder**: executor-reported result digest/outcome is represented evidence, not independently observed truth.
15. **Executor signer → receipt verifier**: private executor keys remain outside RegAgentOps; signed receipt and public trust material cross the boundary.

## Primary threats and controls

### Authorization-to-execution substitution

Threat: an authorization for one request, tool, policy result or input is reused to execute another action.

Controls: `ExecutionLease` binds the exact request digest, authenticated-authorization digest, nested policy-decision digest, MCP policy-enforcement-result digest and MCP registry-snapshot digest. Receipt construction requires the exact authorized `AgentActionEnvelope`, lease and one-time consumption artifact. Tool/action/resource/input evidence is copied from that exact request, not supplied independently as execution authority.

### Approval substitution

Threat: a valid approval resolution for another request or authorization is attached to an approval-required execution.

Controls: v0.5 requires both the exact `ApprovalRequirement` and `ApprovalResolution`. The requirement must bind the same request and authenticated authorization plus requester/tool/action/environment/risk scope. The resolution must bind that exact requirement and permit continuation. Non-approval paths reject attached approval artifacts.

### Execution-lease replay

Threat: the same authorization is used to execute a tool more than once.

Controls: leases are capped at 120 seconds and consumed atomically in an append-only SQLite ledger keyed by `lease_digest`. `BEGIN IMMEDIATE` plus a primary-key insert makes a successful second redemption fail closed. The resulting `ExecutionLeaseConsumption` is itself digest-bound into the receipt.

Residual boundary: the reference ledger is local SQLite state, not distributed consensus. A production deployment with multiple executors must provide a serialization boundary with equivalent or stronger one-time semantics.

### Lease use after MCP governance drift

Threat: MCP server approval, tool metadata or explicit binding changes after policy evaluation but an old authorization is still used.

Controls: lease issuance recomputes the MCP registry snapshot and resolves the exact current server registration, tool snapshot and descriptor represented by the policy result. Redemption repeats this check. Any MCP registry-snapshot change invalidates an unconsumed lease.

### Emergency-stop bypass

Threat: an action proceeds while the institution has activated an emergency stop, or an old non-halted state is reused after stop-state change.

Controls: emergency-stop state is explicit, institution-scoped, append-only and contiguously versioned. A halted current state blocks lease issuance and redemption. Every lease binds the exact current non-halted stop-state digest; any later state version invalidates the old unconsumed lease.

Residual boundary: RegAgentOps checks stop state at lease redemption, immediately before the intended external dispatch boundary. It cannot independently prove that an external executor rechecked or honored state changes occurring after redemption.

### Result substitution or receipt tampering

Threat: a signed receipt is presented with a different result digest, policy decision, lease, request or authorization.

Controls: `ToolExecutionReceipt` binds those digests explicitly. The Ed25519 signing document is domain separated with `regagentops.tool-execution-receipt.v1` and includes receipt, request, lease, lease-consumption, MCP-result, authenticated-authorization, policy-decision and result digests. Any modification changes the signing document and fails verification.

### Executor key substitution

Threat: an untrusted principal signs an execution receipt under another executor identity or key id.

Controls: `ExecutionTrustBundle` binds institution, executor id and key id to an Ed25519 public key, status and validity window. Signing rejects signer institution/executor mismatch; verification requires a unique active matching key and valid signature.

### Failed execution replay

Threat: a failed tool attempt is retried under the same authorization/lease until it succeeds.

Control: the lease is consumed before external execution begins. Both `SUCCEEDED` and `FAILED` receipts therefore refer to an already-consumed lease; retries require a new lease and fresh current-state checks.

### Forged execution chronology

Threat: a receipt claims execution started before one-time lease redemption or after lease expiry.

Controls: receipt construction requires `started_at >= consumed_at` and `started_at < lease.expires_at`; completion cannot predate start. The signed receipt binds these timestamps through the receipt digest.

### MCP server substitution

Threat: metadata from a different server is presented under an approved server name.

Controls from v0.4 remain: current snapshots bind an institution-owned `server_id`, exact current server-registration digest, expected server-reported name and out-of-band `server_identity_digest`; mismatched identity pins and stale registrations fail closed.

Residual boundary: RegAgentOps still does not perform a live cryptographic MCP transport handshake. Correctness of caller-supplied observed server evidence remains an integration responsibility.

### Untrusted annotation privilege escalation

Controls from v0.4 remain: descriptions and annotations are evidence digests only. Explicit `McpToolBinding` defines data-classification scope, production registration and enabled state; metadata annotations cannot change policy effect, risk tier or approval requirements.

### Conflicting or stale MCP state

Controls from v0.4 remain: bounded snapshots, duplicate rejection, conflicting-semantic-latest failure, latest approved server enforcement and explicit re-binding after metadata drift.

### MCP adapter bypassing identity/policy controls

Control from v0.4 remains: `McpPolicyEnforcementPoint` delegates to `AuthenticatedPolicyEngine` and does not introduce a weaker policy language. `execution_performed` remains false in the MCP result.

### Human approval overriding a policy denial

Control from v0.3 remains: approval cannot create a requirement from base `DENY`, and v0.5 refuses to issue an execution lease from any `DENY` or unverified outcome.

### Requester self-approval, delegation expansion and approval replay

Controls from v0.3 remain: requester/approver separation, bounded non-expanding delegation, Ed25519 approval signatures and one-time approval-requirement redemption.

### Identity substitution, JWT key confusion and stale authentication

Controls from v0.2 remain: registered owner→provider→subject binding, pinned issuer/client/audience/algorithm policy, nonce/time checks, rejection of remote key-selection headers, short-lived signed workload identity and institution-signed authenticated context.

### Capability creep

Threat: execution-receipt code quietly becomes a production tool executor or gains network/process capability.

Controls: generic CI includes `execution.py` in the offline capability surface. The dedicated Signed Execution Receipt Boundary rejects network/process imports and invocation markers, pins the 120-second lease constant, requires domain-separated Ed25519 receipt signing, and checks that the lease ledger remains append-only and lease-keyed.

## Residual risks

RegAgentOps records exact bindings but still relies on caller/integration correctness for observed live MCP identity and tool metadata.

The MCP registry and emergency-stop registry are reference in-memory state. Institution configuration is not yet protected by signed change control, tenant-isolated durable storage, KMS/HSM keys or external immutable anchoring.

The approval and execution SQLite ledgers are application-level local serialization boundaries, not distributed consensus or physical WORM storage.

A signed execution receipt proves signature validity and integrity of the represented artifact. It does not independently prove that the external executor actually invoked the represented tool, that the represented result bytes are truthful/complete, or that an external system did not perform additional unrecorded actions.

Executor private-key custody, secure key generation, hardware protection, rotation and compromise response are deployment responsibilities until later cryptographic-hardening milestones.

A stop-state change after lease redemption but before/during external dispatch cannot be independently observed or enforced by the offline RegAgentOps core. Production reference deployment must minimize this gap and enforce equivalent state checks in the isolated executor boundary.

## Explicit non-claims

v0.5 does not provide or claim:

- OpenID Provider or OAuth authorization-server functionality;
- SPIFFE/SPIRE or SVID protocol conformance;
- online OIDC discovery or remote JWKS retrieval;
- autonomous MCP server/tool discovery;
- live MCP transport authentication or connectivity;
- MCP protocol/server/client conformance certification;
- truthfulness of MCP tool descriptions or annotations;
- tool implementation safety or correctness;
- generic BPM/workflow approval functionality;
- production credential brokerage;
- production tool invocation by the RegAgentOps core;
- independent proof that an external executor actually performed the represented action;
- independent proof that represented result bytes are truthful or complete;
- distributed exactly-once execution guarantees across multiple executor nodes;
- runtime sandboxing;
- external immutable audit storage;
- independent timestamp authority;
- regulatory or standards certification;
- production fitness.