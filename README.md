# RegAgentOps

**Evidence-backed authorization and governance control plane for AI agents in regulated enterprises.**

RegAgentOps is an open-source reference architecture for deciding, constraining, recording, and reviewing AI-agent actions before they reach enterprise tools or data systems.

## Summary

RegAgentOps answers a narrow question:

> Under which identity, purpose, policy, data, tool, and human-authority conditions may an AI agent perform a specific enterprise action, and how can that decision be evidenced later?

The project is designed for regulated and high-assurance environments such as financial institutions. It is **not** an autonomous agent framework, credential broker, generic MCP proxy, or compliance-certification product.

## Safety baseline

The initial releases are authorization-only and simulation-first:

- default deny;
- no production tool execution;
- no arbitrary command or shell execution;
- no embedded credentials or secrets;
- no autonomous target/resource discovery;
- no network-capable MCP connection in the authorization core;
- no compliance-certification claim;
- human approval remains explicit where policy requires it.

## v0.1 goal

**Governed Agent Authorization Core**

- agent registry;
- tool/action registry;
- deterministic policy evaluation;
- immutable `AgentActionEnvelope` input artifact;
- decisions: `ALLOW`, `DENY`, `REQUIRE_HUMAN_APPROVAL`, `ALLOW_WITH_CONSTRAINTS`;
- strict JSON contracts;
- evidence-oriented decision output;
- offline tests and CI.

See `docs/ROADMAP.md` once the v0.1 implementation PR lands.

## License

Apache-2.0.
