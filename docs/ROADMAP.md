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

- [x] domain-separated Ed25519 signed approval artifacts;
- [x] scoped direct/delegated authority grants with non-expanding delegation validation;
- [x] requester/approver separation for policy-required and high/critical-risk approval;
- [x] bounded approval expiry and requirement-level one-time replay prevention;
- [x] high-risk escalation and default dual approval for critical risk;
- [x] valid denial terminally consumes a requirement and cannot be bypassed with an alternate package;
- [x] strict approval JSON contracts and dedicated approval CI boundary.

## v0.4.0 — MCP Governance Adapter

- [x] bounded caller-supplied MCP tool-registry ingestion with a 128-tool snapshot ceiling;
- [x] institution-scoped, versioned MCP server approval and server-identity pinning;
- [x] server-scoped MCP tool identity mapped to collision-safe governed tool IDs;
- [x] untrusted tool descriptions/annotations represented only as evidence digests and never as policy authority;
- [x] exact current snapshot and explicit institution-owned tool-binding state;
- [x] authenticated policy-enforcement-point adapter reusing the existing authorization engine;
- [x] v0.3 human-approval continuation preserved for MCP requests requiring approval;
- [x] default-deny handling for stale/unapproved/changed/unknown MCP state;
- [x] no autonomous MCP discovery or network capability in the governance core;
- [x] strict MCP JSON contracts, adversarial tests, Python 3.11/3.12/3.13 CI and clean-wheel smoke.

## v0.5.0 — Signed Execution Receipts

- [x] exact authorization-to-execution binding;
- [x] one-time execution lease with atomic append-only redemption;
- [x] domain-separated Ed25519 signed tool execution receipt;
- [x] result digest and exact policy-decision linkage;
- [x] append-only emergency-stop state verification at lease issuance and redemption;
- [x] MCP governance drift invalidates unconsumed leases;
- [x] exact approval requirement/resolution binding for approval-required execution;
- [x] strict execution JSON contracts, adversarial tests and dedicated execution CI boundary.

## v0.6.0 — Data and Purpose Governance

- [x] versioned institution-owned resource profiles with richer governed data categories;
- [x] exact request-bound data-use declarations and category under-reporting rejection;
- [x] primary-purpose limitation and explicit compatible-secondary-purpose handling;
- [x] PII/sensitive-data minimization constraints;
- [x] output handling and mandatory redaction/aggregation downgrade requirements;
- [x] retention-aware action policy with explicit per-resource ceilings;
- [x] data-governance evidence digests bound into authenticated authorization;
- [x] data-governance snapshot/profile drift invalidates lease issuance or redemption;
- [x] strict data-purpose JSON contracts, adversarial tests and dedicated data-governance CI boundary.

## v0.7.0 — Assurance Evidence

- [x] exact assurance scope for institution/system/deployment/context evidence;
- [x] NIST AI RMF 1.0 evidence crosswalk with explicit framework-version pinning;
- [x] ISO/IEC 42001:2023 governance evidence mapping without conformity/certification claims;
- [x] EU AI Act Regulation (EU) 2024/1689 evidence mapping with human-confirmed operator roles;
- [x] mandatory human-confirmed applicability and mapping rationale;
- [x] `SUPPORTED`, `PARTIAL`, `GAP`, `NOT_APPLICABLE` evidence coverage semantics;
- [x] exact assertion/evidence/crosswalk digest linkage and cross-scope substitution rejection;
- [x] evidence-package verification with explicit non-certification, non-conformity and non-legal-determination semantics;
- [x] strict assurance JSON contracts, adversarial tests and dedicated assurance CI boundary.

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