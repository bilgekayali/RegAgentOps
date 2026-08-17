# Threat Model — v0.1

## Protected assets

- authorization policy integrity;
- institution and agent identity bindings;
- tool/action registry integrity;
- authorization-decision integrity;
- evidence digests and reason codes;
- separation between decision and execution capabilities.

## Trust boundaries

1. **Caller → PDP**: the caller supplies the action envelope and must be treated as untrusted.
2. **Registry/policy configuration → PDP**: policy and registry configuration are security-sensitive administrative inputs.
3. **PDP → future enforcement point**: v0.1 produces a decision but does not enforce or execute it.

## Primary threats and v0.1 controls

### Identity substitution

Threat: an action request claims a different owner, model, agent, or institution.

Control: exact request-to-registry binding; mismatch fails closed.

### Cross-tenant policy replay

Threat: a policy bundle for one institution is replayed for another.

Control: institution IDs are bound into the request, registry entries, policy rules, policy bundle, and artifact digests.

### Unregistered tool/action use

Threat: an agent requests an action that was never governed.

Control: tool/action registry lookup is mandatory; missing/disabled entries fail closed.

### Data-classification escalation

Threat: a tool registered for lower-sensitivity data is used against more sensitive data.

Control: requested classification must be explicitly present in the tool/action registration and matching policy rule.

### Policy ambiguity or permissive fallback

Threat: missing or overlapping rules accidentally grant access.

Control: no-match is `DENY`; multiple matches use conservative precedence (`DENY` > approval > constrained allow > allow).

### Hidden raw secrets in governance artifacts

Threat: prompts, credentials, or tool payloads become copied into authorization logs.

Control: v0.1 binds only an input SHA-256 digest; the governance artifact does not require raw tool arguments or credentials.

### Capability creep inside the PDP

Threat: later changes quietly add network/process execution into authorization code.

Control: CI statically rejects network/process capability imports in the v0.1 core.

## Explicit non-claims

v0.1 does not provide:

- runtime sandboxing;
- credential isolation;
- MCP server authentication;
- workload identity;
- tamper-proof external audit storage;
- signed human approvals;
- production tool execution;
- prompt-injection detection;
- regulatory or standards certification.

These are future roadmap boundaries and must not be inferred from an authorization decision.
