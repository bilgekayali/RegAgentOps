# MCP Governance Boundary — RegAgentOps v0.4

RegAgentOps v0.4 adds an offline governance adapter for Model Context Protocol (MCP) tools. The adapter does not connect to MCP servers, execute tools, discover targets, or trust server-provided descriptions as authorization policy.

## Design objective

The MCP layer answers a bounded governance question:

> Given an institution-approved MCP server identity and a caller-supplied tool snapshot, which exact server/tool metadata may be represented as a RegAgentOps governed tool, and may an authenticated agent continue toward that tool under the existing RegAgentOps policy and human-approval controls?

The boundary is intentionally narrower than an MCP client or proxy.

## Server governance

`McpServerRegistration` is institution-scoped and versioned. It records:

- a stable institution-owned `server_id`;
- expected server-reported name;
- transport profile;
- an out-of-band server-identity pin digest;
- a metadata/evidence digest;
- explicit current approval state; and
- registration time.

The server-reported name is not treated as the global identity. RegAgentOps uses the institution-owned `server_id` to namespace governed tool IDs and uses the explicit identity digest as the pinning evidence.

A newer server registration makes older server-bound current assertions stale. A registration with `approved=false` revokes the current MCP governance path until a later approved version is explicitly registered.

## Bounded tool snapshots

`McpToolSnapshot` is caller supplied. The governance core has no network or discovery capability.

A snapshot:

- binds one exact current server registration;
- records observed server name and observed server-identity digest;
- contains at most 128 tool descriptors;
- rejects duplicate tool names within the same server; and
- is immutable by `snapshot_id`.

Multiple different snapshots at the same semantic latest timestamp fail closed rather than relying on insertion order.

## Tool metadata and annotations

`McpToolDescriptor` binds exact digests for:

- input schema;
- optional output schema;
- optional description;
- optional annotations; and
- complete raw tool metadata.

Descriptions and annotations are evidence only. They do not determine:

- allowed data classification;
- production eligibility;
- enabled/disabled state;
- policy effect;
- risk tier;
- human-approval requirement; or
- execution permission.

A change in annotations or other raw metadata changes the descriptor/snapshot digest and therefore makes an old current binding stale, even though the annotation value itself is not trusted as policy authority.

## Explicit governed bindings

`McpToolBinding` is the institution-owned decision that maps an exact current MCP descriptor to the existing RegAgentOps `ToolActionDescriptor` boundary.

A binding explicitly defines:

- exact server registration digest;
- exact latest tool snapshot digest;
- exact tool descriptor digest;
- collision-safe governed tool ID `mcp:<server_id>:<tool_name>`;
- allowed data classifications;
- production-registration state;
- enabled state; and
- fixed governed action `invoke`.

Binding versions are contiguous and append-only. A binding identity cannot silently move to a different governed tool.

## Policy-enforcement point

`McpPolicyEnforcementPoint` is an offline adapter over the existing `AuthenticatedPolicyEngine`.

Flow:

```text
Caller-supplied MCP snapshot
        |
        v
McpGovernanceRegistry
  server pin + latest snapshot + exact binding
        |
        v
ToolRegistry (derived only from current explicit bindings)
        |
        +---------------- Signed authenticated agent identity
        |                                  |
        v                                  v
          AuthenticatedPolicyEngine
                    |
                    v
       AuthenticatedAuthorizationDecision
                    |
                    v
        McpPolicyEnforcementResult
                    |
          if approval required
                    v
               ApprovalGate (v0.3)
```

The MCP adapter does not create a parallel policy language. Existing RegAgentOps precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

Unknown, stale, changed, cross-scope, unapproved or unbound MCP state fails closed before policy continuation.

## Execution semantics

`McpPolicyEnforcementResult.execution_performed` is always `false` in v0.4.

`execution_permitted=true` means only that the represented authenticated policy decision permits continuation without a pending human-approval gate. It is not proof that an external MCP client/server will enforce the decision, and it is not an execution receipt.

When policy returns `REQUIRE_HUMAN_APPROVAL`, the adapter preserves the exact `AuthenticatedAuthorizationDecision` so the existing v0.3 `ApprovalGate` can issue and resolve the bound approval requirement.

## Historical evidence and currentness

Historical server registrations, snapshots and bindings remain immutable in the registry snapshot digest.

Current-state assertions require:

- the latest server registration to be approved;
- the binding to reference that exact server registration;
- the binding to reference the unique latest tool snapshot for that server registration;
- the descriptor to remain present in that exact snapshot; and
- the binding version itself to be current.

This distinguishes audit history from present authorization state.

## Explicit non-claims

RegAgentOps v0.4 does **not** by itself establish:

- cryptographic authenticity of an MCP server from supplied metadata alone;
- protocol conformance of an MCP server or client;
- safety or correctness of tool implementation;
- truthfulness of tool descriptions or annotations;
- runtime enforcement by an external MCP host/client/server;
- successful or correct tool execution;
- source/result authenticity;
- regulatory compliance, legal applicability, certification, or supervisory acceptance;
- production fitness.

The next roadmap layer, v0.5, is intended to bind authorization to one-time execution leases and signed execution receipts. v0.4 deliberately stops before execution.
