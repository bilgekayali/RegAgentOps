# RegAgentOps Architecture

## v0.6 boundary

RegAgentOps v0.6 is an **offline authenticated authorization, data/purpose governance, human-approval, MCP-governance and signed execution-evidence control plane**. v0.6 does not create a parallel policy language: the existing authenticated policy decision remains authoritative, while institution-owned data-resource profiles and exact request-bound data-use declarations can only preserve, constrain or deny that path.

It still does **not** discover data, scan for PII, infer legal purpose, connect to an MCP server, obtain production credentials, redact output bytes or invoke a requested tool.

```text
OIDC + pinned trust             Institution workload signer
        \                               /
         +---- Signed authenticated agent ----+
                          |
AgentActionEnvelope ------+------ PolicyBundle
        |                 |
        |        current governed MCP binding
        |                 |
        +------ DataUseDeclaration
                          |
                  DataResourceProfile
                          |
                          v
                 DataGovernanceDecision
                          |
               governance evidence digest
                          v
               AuthenticatedAuthorizationDecision
                          |
                    MCP policy result
                          |
                  if approval required
                          v
                     ApprovalGate
                          |
                          v
                  ApprovalResolution
                          |
      current MCP + data profile + emergency stop
                          |
                          v
                 one-time ExecutionLease
                          |
                  atomic consumption
                          |
                          v
                  external executor
                          |
                          v
             SignedToolExecutionReceipt
```

## Data-resource identity and classification

`DataResourceProfile` is institution-scoped, append-only and contiguously versioned for an exact resource identifier. It binds the resource to a governed `DataClassification`, exact data-category tuple, primary purposes, explicitly compatible secondary purposes, permitted output handling modes, redaction requirements, retention ceiling, enabled state and registration time.

The data categories are governance labels rather than automatic legal classifications. v0.6 performs no fuzzy resource matching or autonomous discovery: a request must resolve to an exact current enabled profile.

A newer resource-profile version invalidates the old profile for current authorization while retaining the historical artifact for evidence.

## Request-bound data use

`DataUseDeclaration` binds the exact `AgentActionEnvelope` digest, exact resource, business purpose, observed data categories, requested output handling and retention period. The declaration cannot predate the request and cannot be future-dated relative to evaluation.

The declared observed categories must exactly equal the current resource-profile categories. This is intentionally stricter than subset matching because subset matching permits a caller to omit a sensitive category and obtain weaker controls.

## Purpose limitation and compatibility

The base `PolicyBundle` still decides whether the agent/tool/action/purpose combination is authorized. v0.6 independently verifies whether the same purpose is permitted for the governed resource.

A profile primary purpose is directly eligible. An explicitly compatible secondary purpose is allowed only with a `purpose:compatible-secondary-use` constraint. A purpose outside both sets fails closed.

Purpose compatibility is institution-owned configuration. Tool descriptions, MCP annotations, prompts and model output cannot create or widen a compatibility relationship.

## Sensitive-data, output and retention constraints

Sensitive categories emit `data:minimize`. Positive decisions also bind the required output mode and requested retention behavior into authorization constraints.

If raw output is requested for categories requiring redaction, the evaluator deterministically selects a permitted safer mode in this order: redacted, aggregated, metadata-only. If no safe permitted mode exists, authorization is denied. The core records the requirement but does not transform bytes itself.

Retention above the resource ceiling is denied. A positive decision records either `retention:no-persist` or `retention:seconds=<n>`. The configured ceiling is a technical governance bound, not a legal recommendation.

## Evidence linkage

`DataGovernanceDecision` binds:

- exact request digest;
- exact `DataUseDeclaration` digest;
- exact current `DataResourceProfile` digest;
- institution data-governance registry snapshot digest;
- purpose and governed categories;
- requested output handling and retention;
- resulting decision, constraints and reasons; and
- evaluation time.

Its SHA-256 artifact digest is inserted into `AuthorizationDecision.governance_evidence_digests`. Because `AuthenticatedAuthorizationDecision` contains that authorization object, the authenticated-authorization digest commits to the exact v0.6 evidence.

The v0.5 `ExecutionLease` and `ToolExecutionReceipt` already bind the authenticated-authorization digest. v0.6 therefore extends execution evidence without creating a second lease or receipt format.

When base policy requires human approval, the data-governance decision remains separately available and its digest remains bound into the authenticated authorization. Approval cannot turn a v0.6 data-governance `DENY` into continuation.

## MCP composition

`DataPurposeMcpPolicyEnforcementPoint` layers v0.6 over the existing `McpPolicyEnforcementPoint`. The v0.4 adapter still performs MCP server/tool currentness and authenticated policy evaluation. v0.6 then applies the request-bound resource/purpose guardrail and rebuilds the standard MCP result around the governed authenticated authorization.

This preserves the existing `McpPolicyEnforcementOutcome` contract for approval and execution integration. No MCP annotation becomes data-policy authority.

## Execution currentness

`DataGovernedExecutionGate` wraps the v0.5 `ExecutionGate`. It requires a positive `DataGovernanceDecision` and, before lease issuance and again before redemption, checks:

- the institution data-governance registry snapshot is unchanged; and
- the exact resource profile referenced by the authorization is still current.

Any data-governance drift invalidates the old execution path. The underlying execution gate continues to enforce MCP currentness, emergency-stop state, authorization freshness, executor binding, one-time lease redemption and receipt provenance.

## Existing boundaries retained

v0.1 deterministic default-deny policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

v0.2 signed authenticated identity remains mandatory for positive authenticated authorization. v0.3 human approval cannot override denial. v0.4 MCP governance remains bounded and non-executing. v0.5 execution leases remain short-lived, one-time, executor-bound and non-invoking from the RegAgentOps core.

## Trust boundaries

1. **Caller → identity/policy plane**: request and identity inputs are untrusted until verified.
2. **Institution data governance → data registry**: resource classifications, categories, purpose compatibility, output modes, redaction rules and retention ceilings are privileged governance configuration.
3. **Caller → data-use declaration**: declaration fields are untrusted claims until exact request/profile checks pass.
4. **Data registry → authenticated authorization**: only the exact current profile and deterministic decision digest cross as governance evidence; profile text does not bypass policy precedence.
5. **Institution MCP configuration → MCP registry**: server approvals, pins and tool bindings remain privileged configuration.
6. **Authenticated authorization → approval gate**: approval binds the exact authorization and cannot override a denial.
7. **MCP/data/approval evidence → execution gate**: currentness is revalidated before lease issuance/redemption; caller booleans are insufficient.
8. **Execution gate → external executor**: one-time consumption is the final RegAgentOps pre-dispatch boundary; invocation remains external.
9. **External executor → signed receipt**: represented result digest/outcome is signed evidence, not independently observed truth.

## Historical evidence versus current state

Resource-profile versions, data-governance decisions, MCP registrations/snapshots/bindings, approval artifacts, emergency-stop states and execution consumptions remain historical evidence. Current execution is stricter: exact current MCP state, data-governance state and emergency-stop state must still satisfy the unconsumed path.

A later governance change does not rewrite a historical signed receipt. It prevents stale authorization evidence from authorizing a new execution.

## Capability separation

Authorization, identity, approval, MCP-governance, execution and data-governance modules are statically checked in CI to reject network/process capability imports. Data governance contains no DLP scanner, data connector, semantic inference service, redaction engine or tool invocation interface.

Production credential brokerage, data-discovery/DLP integrations, deletion enforcement, network-isolated execution workers and external immutable audit anchoring remain outside this milestone.

## Standards posture

RegAgentOps uses NIST AI RMF, OpenID/JWT security guidance, workload-identity concepts and MCP trust/safety guidance as design inputs. The data-purpose labels and controls are reference governance constructs rather than claims of legal classification, protocol conformance or certification.