# RegAgentOps Roadmap

RegAgentOps evolves from an offline authorization core into a production-reference governance control plane. Version numbers represent completed control boundaries, not calendar dates.

## v0.1.0 — Governed Agent Authorization Core

- [x] institution-scoped agent registry;
- [x] institution-scoped tool/action registry;
- [x] immutable `AgentActionEnvelope` contract;
- [x] deterministic default-deny policy evaluation;
- [x] `ALLOW`, `DENY`, `REQUIRE_HUMAN_APPROVAL`, `ALLOW_WITH_CONSTRAINTS` decisions;
- [x] evidence-oriented decision artifact and SHA-256 bindings;
- [x] strict JSON schemas;
- [x] offline CLI demonstration;
- [x] Python 3.11/3.12/3.13 CI and capability boundary.

## v0.2.0 — Authenticated Agent Identity

- [x] offline OIDC/JWKS verification with pinned issuer/client/algorithm policy;
- [x] institution-owned workload identity signing boundary;
- [x] short-lived signed workload identity attestations;
- [x] exact human-owner/agent/model/workload binding;
- [x] key lifecycle and offline trust-bundle verification;
- [x] registered owner→provider→OIDC subject binding;
- [x] institution-signed authenticated context with unsigned/tampered-context rejection;
- [x] authenticated policy evaluation with expiry and registration-drift rejection;
- [x] strict identity JSON contracts and dedicated identity CI boundary.

## v0.3.0 — Human Approval and Delegated Authority

- [ ] signed approval artifacts;
- [ ] role and delegation boundaries;
- [ ] separation of requester and approver where required;
- [ ] approval expiry and replay prevention;
- [ ] high-risk action escalation policy.

## v0.4.0 — MCP Governance Adapter

- [ ] bounded MCP tool-registry ingestion;
- [ ] server/tool identity pinning;
- [ ] untrusted tool-annotation handling;
- [ ] policy enforcement point interface;
- [ ] no autonomous discovery outside approved MCP servers.

## v0.5.0 — Signed Execution Receipts

- [ ] exact authorization-to-execution binding;
- [ ] one-time execution lease;
- [ ] signed tool execution receipt;
- [ ] result digest and policy-decision linkage;
- [ ] emergency-stop state verification.

## v0.6.0 — Data and Purpose Governance

- [ ] richer data classification policy;
- [ ] purpose limitation and purpose compatibility;
- [ ] PII/sensitive-data constraints;
- [ ] output handling and redaction requirements;
- [ ] retention-aware action policy.

## v0.7.0 — Assurance Evidence

- [ ] NIST AI RMF evidence crosswalk;
- [ ] ISO/IEC 42001 governance evidence mapping;
- [ ] EU AI Act deployment-role evidence mapping;
- [ ] human-confirmed applicability and explicit non-certification semantics.

## v0.8.0 — Tenant and Cryptographic Hardening

- [ ] PostgreSQL RLS reference boundary;
- [ ] institution-owned KMS/HSM keys;
- [ ] signed configuration change control;
- [ ] immutable/external audit anchoring;
- [ ] tenant-scoped encrypted governance evidence.

## v0.9.0 — Production Reference Deployment

- [ ] isolated policy-enforcement worker;
- [ ] strict egress and tool allowlisting;
- [ ] recovery/upgrade/rollback contracts;
- [ ] CodeQL and release-provenance gates;
- [ ] deployment, incident, key-rotation, and DR runbooks.

## v1.0.0 — Stable Regulated-Agent Governance Reference

- [ ] stable CLI/API/JSON compatibility policy;
- [ ] end-to-end production-reference deployment;
- [ ] reproducible release checksums and provenance;
- [ ] supported upgrade path from final v0.9.x;
- [ ] independent security-review checklist closed or explicitly risk-accepted;
- [ ] legal/accessibility responsibilities scoped;
- [ ] explicit v1 non-claims retained.
