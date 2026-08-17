# RegAgentOps Architecture

## v0.1 boundary

RegAgentOps v0.1 is an **offline policy decision point (PDP)**. It evaluates a bounded authorization request and emits an evidence-oriented decision artifact. It does not invoke the requested tool.

```text
Agent / Orchestrator
       |
       | AgentActionEnvelope
       v
+---------------------------+
| RegAgentOps v0.1 PDP      |
|                           |
| Agent Registry            |
| Tool/Action Registry      |
| Deterministic Policy      |
| Default-Deny Evaluation   |
+---------------------------+
       |
       | AuthorizationDecision
       v
Caller / future PEP
```

A future policy-enforcement point (PEP), MCP adapter, workload-identity layer, approval service, and execution receipt layer are deliberately outside the v0.1 runtime boundary.

## Decision inputs

`AgentActionEnvelope` binds:

- institution;
- agent identity;
- human owner;
- model provider and model identifier;
- tool and action;
- resource identifier;
- data classification;
- business purpose;
- environment;
- risk tier;
- SHA-256 digest of the proposed tool input;
- request timestamp.

The raw prompt, raw tool arguments, credentials, tokens, and secret values are not part of the v0.1 envelope.

## Decision semantics

Rules are explicit and institution-scoped. There are no wildcard identities in v0.1.

When multiple rules match, RegAgentOps applies conservative monotonic precedence:

1. `DENY`
2. `REQUIRE_HUMAN_APPROVAL`
3. `ALLOW_WITH_CONSTRAINTS`
4. `ALLOW`

If no rule matches, the result is `DENY`.

An `ALLOW` result is an authorization artifact only. v0.1 contains no executor and therefore cannot itself perform the authorized action.

## Registry binding

The request must match the registered agent's institution, human owner, model provider, and model identifier. The requested tool/action must also be registered for the same institution and data classification. Production use requires an explicit `production_registered` tool/action flag.

## Deterministic evidence

Artifacts use canonical JSON and SHA-256 digests. The decision records the request digest, policy-bundle digest, matched rule IDs, constraints, reason codes, and evaluation timestamp.

## Standards posture

RegAgentOps is informed by NIST AI RMF risk-governance concepts and MCP trust/safety guidance around explicit authorization and human control. These references are design inputs, not certification claims.
