# Threat Model — v0.4

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
- tool/action registry integrity;
- authorization, identity, approval and MCP-governance evidence integrity;
- separation between untrusted MCP metadata and policy authority;
- separation between governance decisions and execution capabilities.

## Trust boundaries

1. **Caller → MCP governance registry**: supplied MCP server/tool metadata is untrusted until exact governed server, identity-pin and currentness checks pass.
2. **Institution MCP configuration → registry**: server approval, server identity pins, tool bindings, classification scope and production-registration flags are privileged administrative input.
3. **MCP registry → authenticated PDP**: only exact current explicit bindings become `ToolActionDescriptor` entries; tool annotations do not become policy authority.
4. **Caller → identity/PDP**: action, identity and request inputs are untrusted until verified.
5. **Human identity registry / pinned JWKS → OIDC verifier**: privileged trust configuration; no online discovery.
6. **Institution workload/context signer → verifier**: private keys remain outside the verifier.
7. **Registry/policy configuration → PDP**: privileged administrative input.
8. **Trusted local PDP → approval gate**: the authenticated authorization artifact is digest-bound but not independently signed by the approval gate.
9. **Approval authority bundle → approval gate**: privileged role/delegation configuration.
10. **Human approval signer → approval verifier**: private approval keys remain outside RegAgentOps; signed statements and public trust material cross the boundary.
11. **Approval replay ledger → future executor**: terminal approval resolution is one-time governance evidence, not execution proof.

## Primary threats and controls

### MCP server substitution

Threat: metadata from a different server is presented under an approved server name.

Controls: current snapshots bind an institution-owned `server_id`, exact current server-registration digest, expected server-reported name and out-of-band `server_identity_digest`. A mismatched observed identity pin is rejected. A newer server registration makes older server-bound current assertions stale.

Residual boundary: v0.4 does not itself perform a cryptographic MCP transport handshake, so the correctness/authenticity of the supplied identity digest remains an operator/integration responsibility.

### Tool identity collision across MCP servers

Threat: two servers expose the same tool name and one is mistaken for the other.

Control: governed tool IDs are namespaced as `mcp:<server_id>:<tool_name>`. Tool names need only be unique inside one governed server snapshot; the institution-owned server id supplies cross-server disambiguation.

### Untrusted annotation privilege escalation

Threat: an MCP tool claims benign annotations such as read-only/non-destructive and uses them to obtain broader access or production eligibility.

Controls: descriptions and annotations are stored only as evidence digests. `McpToolBinding` separately and explicitly defines allowed data classifications, production-registration state and enabled state. No annotation field is translated into policy effect, risk tier or approval requirement.

### Tool-metadata drift after approval

Threat: an approved tool changes schema, description, annotations or other metadata while retaining the same tool name.

Controls: descriptor and raw-metadata digests are bound into an immutable snapshot. A newer unique snapshot makes the prior binding stale. Authorization resumes only after a new explicit binding version references the new exact descriptor.

### Conflicting latest MCP snapshots

Threat: multiple different tool snapshots claim the same latest capture time, causing insertion-order-dependent authorization.

Control: semantic timestamp selection is used and different snapshots at the same latest instant fail closed. No insertion-order tie-breaker is used.

### Unbounded or autonomous discovery

Threat: the governance component enumerates arbitrary MCP servers/tools or gains network capability beyond institution-approved scope.

Controls: the v0.4 registry accepts caller-supplied snapshots only, caps each snapshot at 128 tools, exposes no discovery/client/session API, and generic plus dedicated MCP CI reject network/process imports and selected autonomous-discovery/network markers.

### Stale or revoked MCP server approval

Threat: an old binding remains executable after server governance is revoked or changed.

Controls: every current binding assertion resolves the latest server-registration version. `approved=false`, a changed identity pin, or any later registration invalidates older bindings for current authorization.

### MCP adapter bypassing existing identity/policy controls

Threat: an MCP-specific path introduces a second, weaker authorization engine.

Control: `McpPolicyEnforcementPoint` derives the existing `ToolRegistry` contract from current explicit bindings and delegates to the existing `AuthenticatedPolicyEngine`. Existing identity and policy precedence remain unchanged.

### MCP human-approval bypass

Threat: an MCP adapter treats `REQUIRE_HUMAN_APPROVAL` as an executable allow.

Controls: the PEP result explicitly represents `human_approval_required=true` and `execution_permitted=false`; it retains the exact authenticated authorization object so the existing v0.3 `ApprovalGate` can create the bound requirement. `execution_performed` is structurally fixed to false.

### Identity substitution, JWT key confusion and stale authentication

Controls from v0.2 remain: registered owner→provider→subject binding, pinned issuer/client/audience/algorithm policy, nonce and time checks, rejection of remote key-selection headers, short-lived institution workload identity, institution-signed authenticated context and fail-closed registration-drift checks.

### Human approval overriding a policy denial

Control from v0.3 remains: `ApprovalGate.build_requirement()` refuses base `DENY`; `resolve()` also rejects unverified identity or `DENY`. Approval can satisfy a continuation condition only for requests not already denied.

### Requester self-approval and delegation expansion

Controls from v0.3 remain: requester/approver separation for policy-required/high/critical flows; child delegation cannot widen tool/action/environment scope, increase risk tier, outlive the parent, or break issuer/subject relationships; cycles fail closed.

### Approval key substitution, tampering and replay

Controls from v0.3 remain: institution/principal/key binding, Ed25519 signed approval statements, exact requirement/request/grant binding, package/principal uniqueness and approval-requirement-digest one-time redemption.

### Capability creep

Threat: MCP governance code quietly gains network/process or execution capability.

Controls: generic CI and the dedicated MCP Governance Boundary reject network/process imports in `mcp.py`; the dedicated workflow also checks bounded ingestion and non-execution markers. `McpPolicyEnforcementResult.execution_performed` must remain false.

## Residual risks

v0.4 assumes caller-supplied MCP snapshots accurately represent what an external integration observed. The project records exact evidence digests and pinning relationships but does not itself authenticate a live MCP transport.

The MCP registry is in-memory reference state in this milestone. Server approvals and bindings are not yet protected by signed configuration change control, tenant-isolated durable storage, KMS/HSM keys or external immutable anchoring.

The authenticated authorization supplied to the approval gate is produced by the trusted local RegAgentOps PDP path and is digest-bound but not independently signed as a PDP decision in this milestone.

The SQLite replay ledger remains application-level local state rather than distributed consensus, physical WORM storage or external audit anchoring.

Most importantly, v0.4 does not prove that a future MCP tool execution corresponds to the governed authorization/approval artifacts. Exact authorization-to-execution binding is reserved for v0.5 signed execution receipts.

## Explicit non-claims

v0.4 does not provide or claim:

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
- MCP tool execution;
- production tool execution;
- execution receipts or authorization-to-execution proof;
- runtime sandboxing;
- external immutable audit storage;
- independent timestamp authority;
- regulatory or standards certification;
- production fitness.
