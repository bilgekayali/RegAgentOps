# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, and human-authority conditions may an AI agent perform a specific enterprise action, and how can that decision be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, or compliance-certification product.

Current version: **v0.1.0 — Governed Agent Authorization Core**.

## Why this exists

Agentic systems can request tools that read enterprise data, call APIs, modify records, or trigger business processes. RegAgentOps places a deterministic governance decision point between an agent request and any future enforcement/execution layer.

The v0.1 core is deliberately offline. It evaluates authorization artifacts; it does not connect to MCP servers, hold credentials, or execute the requested action.

## v0.1 control model

```text
Agent / Orchestrator
       |
       | AgentActionEnvelope
       v
+-----------------------------+
| RegAgentOps Policy Decision |
| Point (offline)             |
|                             |
| Agent Registry              |
| Tool / Action Registry      |
| Institution Policy Bundle   |
| Default-Deny Evaluation     |
+-----------------------------+
       |
       | AuthorizationDecision
       v
Caller / future enforcement point
```

An `AgentActionEnvelope` binds the institution, agent, human owner, model, tool/action, resource, data classification, business purpose, environment, risk tier, input digest, and request timestamp.

The core emits exactly one of four decisions:

- `ALLOW`
- `DENY`
- `REQUIRE_HUMAN_APPROVAL`
- `ALLOW_WITH_CONSTRAINTS`

When multiple rules match, conservative precedence is deterministic:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

No matching rule means **DENY**.

## Safety baseline

v0.1 is authorization-only and simulation-first:

- default deny;
- no production tool execution in the RegAgentOps runtime;
- no arbitrary command or shell execution;
- no embedded credentials, tokens, or secrets;
- no autonomous target/resource discovery;
- no network-capable MCP connection in the authorization core;
- raw prompts and raw tool arguments are not required in governance artifacts;
- human approval remains explicit where policy requires it;
- no regulatory or standards certification claim.

An `ALLOW` decision means only that the supplied policy permits the requested action. **v0.1 contains no executor.**

## Quick start

```bash
python -m pip install -e .
regagentops --version
regagentops demo-decision
```

The demo evaluates a synthetic request and emits a constrained authorization decision. It performs no tool execution and makes no network call.

## Repository map

```text
src/regagentops/
  models.py       immutable authorization artifacts and canonical digests
  registry.py     institution-scoped agent and tool/action registries
  policy.py       deterministic fail-closed policy engine
  cli.py          offline synthetic authorization demo

schemas/
  agent-action-envelope.schema.json
  authorization-decision.schema.json
  policy-bundle.schema.json

tests/
  test_policy.py
  test_contracts.py

docs/
  ARCHITECTURE.md
  THREAT_MODEL.md
  ROADMAP.md
```

## CI boundary

GitHub Actions tests Python 3.11, 3.12, and 3.13, performs a clean-wheel smoke test, and statically rejects network/process capability imports in the authorization core. This separation is intentional: future identity, MCP, approval, and execution adapters must remain outside the pure decision boundary unless their release explicitly changes the trust model.

## Standards and ecosystem references

RegAgentOps uses external frameworks as **design inputs**, not certification claims:

- NIST AI Risk Management Framework (AI RMF): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI RMF Generative AI Profile (NIST AI 600-1): https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
- Model Context Protocol specification: https://modelcontextprotocol.io/specification/2025-11-25

MCP explicitly treats tool capabilities as security-sensitive and emphasizes user consent/control; RegAgentOps' future MCP adapter is intended to add enterprise authorization evidence around that trust boundary rather than replace MCP itself.

## Roadmap

The control sequence is intentionally staged:

`v0.1 authorization → v0.2 identity → v0.3 signed human approval → v0.4 MCP governance → v0.5 signed execution receipts → v0.6 data/purpose governance → v0.7 assurance evidence → v0.8 tenant/crypto hardening → v0.9 production reference → v1.0 stable release`

See [docs/ROADMAP.md](docs/ROADMAP.md) for release gates.

## Security

See [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
