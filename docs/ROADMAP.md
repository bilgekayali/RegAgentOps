# RegAgentOps Roadmap

RegAgentOps evolves from an offline authorization core into a stable production-reference governance control plane. Version numbers represent completed control boundaries, not calendar dates.

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

- [x] exact assurance scope for institution/system/deployment/context evidence with append-only context history;
- [x] NIST AI RMF 1.0 evidence crosswalk with explicit framework-version pinning;
- [x] ISO/IEC 42001:2023 governance evidence mapping without conformity/certification claims;
- [x] EU AI Act Regulation (EU) 2024/1689 evidence mapping with human-confirmed operator roles;
- [x] mandatory human-confirmed applicability and mapping rationale;
- [x] one immutable applicability assertion per exact scope/framework/version/reference;
- [x] `SUPPORTED`, `PARTIAL`, `GAP`, `NOT_APPLICABLE` evidence coverage semantics;
- [x] one immutable crosswalk entry per exact applicability assertion;
- [x] exact assertion/evidence/crosswalk digest linkage and cross-scope substitution rejection;
- [x] monotonic scope → applicability/evidence → crosswalk → package chronology;
- [x] immutable institution/package identity and duplicate-entry rejection;
- [x] evidence-package verification with explicit non-certification, non-conformity and non-legal-determination semantics;
- [x] strict assurance JSON contracts, adversarial tests and dedicated assurance CI boundary.

## v0.8.0 — Tenant and Cryptographic Hardening

- [x] PostgreSQL RLS reference boundary with safe identifiers, forced RLS and exact institution+tenant `USING`/`WITH CHECK` predicates;
- [x] append-only tenant-isolation profiles binding exact RLS policy digests;
- [x] institution/tenant/purpose-scoped KMS/HSM key references with no embedded private or symmetric key bytes;
- [x] append-only key lifecycle states with one-way `ACTIVE → RETIRED/DISABLED` transitions and no reactivation;
- [x] Ed25519 domain-separated signed configuration changes with contiguous tenant chain, stale-object overwrite rejection and effective-time activation;
- [x] new cryptographic operations reject backdated artifact times and require a valid active key at operation time;
- [x] tenant-scoped AES-256-GCM governance-evidence envelopes with authenticated institution/tenant/key/subject bindings and core-generated 96-bit nonces;
- [x] append-only external audit-anchor chain bound to exact opaque provider receipt digests with idempotent exact retries;
- [x] strict tenant/crypto JSON contracts, adversarial tests, generic offline capability checks and dedicated hardening CI boundary.

## v0.9.0 — Production Reference Deployment

- [x] isolated policy-enforcement worker profile with non-root/read-only/no-new-privileges/capability-drop/seccomp and host-namespace restrictions;
- [x] strict tenant-scoped default-deny TLS/HTTPS egress with exact endpoints, wildcard/plaintext rejection, canonical IP enforcement and trust-policy evidence binding;
- [x] strict tenant-scoped default-deny governed-tool→executor allowlisting with direct tool invocation forbidden in the policy worker;
- [x] worker registration resolves the exact current v0.8 tenant-isolation profile rather than accepting an unverified digest;
- [x] worker dependency chronology rejects profiles predating egress/tool/tenant-isolation state;
- [x] release manifests binding exact source commit, artifact/checksum, worker/configuration, CodeQL and build-provenance evidence digests;
- [x] release chronology rejects manifests predating the bound worker profile;
- [x] release currentness invalidation after worker/egress/tool-policy **or tenant-isolation** drift;
- [x] exact recovery, upgrade and rollback contracts with reverse-transition validation and chronological provenance;
- [x] CodeQL `security-extended` gate using `github/codeql-action@v4`;
- [x] release provenance gate with deterministic wheel checksums and tag-scoped `actions/attest@v4` artifact attestations;
- [x] deployment, incident-response, KMS/HSM key-rotation and disaster-recovery runbooks;
- [x] strict production-reference JSON contracts, adversarial tests, generic offline capability checks and dedicated deployment CI boundary.

## v1.0.0 — Stable Regulated-Agent Governance Reference

- [x] stable `regagentops.api`, CLI and JSON discriminator compatibility policy with committed v1 baselines;
- [x] end-to-end stable release baseline binding every v0.1-v0.9 governance boundary to an exact current production-reference release;
- [x] reproducible two-build wheel checksum gate and tag-scoped provenance attestations;
- [x] exact supported upgrade path from a current final v0.9.x release to the exact 1.0.0 release;
- [x] independent security-review **contract and v1.0.0 tag blocker** with item-level accountable-human risk-acceptance semantics;
- [ ] real independent v1.0 security review completed, or each residual item explicitly risk-accepted by an accountable human;
- [x] legal, privacy, accessibility, retention, jurisdiction-role and production-IAM responsibilities explicitly scoped;
- [x] explicit v1 non-claims retained as machine-readable contract data;
- [x] stable baseline chronology and current-eligibility revalidation fail closed after production drift.

The unchecked review item is deliberately external to code generation. A PR merge or generic project approval is not treated as an independent review or as item-level risk acceptance. The `v1.0.0` tagged-release workflow remains blocked until genuine review evidence is supplied.
