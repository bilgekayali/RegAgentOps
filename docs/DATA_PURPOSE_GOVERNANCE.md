# Data and Purpose Governance

RegAgentOps v0.6 adds a deterministic, offline data-use governance boundary on top of the existing authenticated policy, MCP governance, human-approval and signed-execution-receipt chain. It does not introduce a second authorization language. Existing `PolicyBundle` evaluation remains authoritative; v0.6 adds institution-owned resource metadata and request-bound data-use evidence that may only preserve, constrain or deny the existing authorization path.

## Resource profiles

`DataResourceProfile` is append-only, institution-scoped and contiguously versioned for an exact resource identifier. A profile declares the governed `DataClassification`, exact data categories, primary purposes, explicitly compatible secondary purposes, permitted output handling modes, categories requiring redaction, a maximum retention period, enabled state and registration time.

The reference categories are `personal`, `sensitive_personal`, `financial`, `health`, `biometric`, `credential`, `location`, and `confidential_business`. They are governance labels rather than automatic legal classifications.

No wildcard resource discovery or fuzzy matching is performed. A request must resolve to an exact current enabled profile.

## Request-bound declaration

`DataUseDeclaration` binds the exact `AgentActionEnvelope` digest, resource, business purpose, observed categories, requested output handling and requested retention period. The declaration cannot predate the request or come from the future relative to evaluation.

The observed category tuple must equal the current resource profile category tuple. This deliberately rejects category under-reporting: a caller cannot omit a sensitive category to obtain weaker controls.

## Purpose limitation and compatibility

A request purpose must be either a profile primary purpose or an explicitly registered compatible secondary purpose. Primary purpose use is directly eligible for the remaining controls. Compatible secondary use is permitted only with an explicit `purpose:compatible-secondary-use` constraint. An unregistered purpose fails closed.

The compatibility relationship is institution-owned governance configuration. RegAgentOps does not infer purpose compatibility from tool descriptions, model output, user text or external ontologies.

## Sensitive-data and output handling

Profiles may require redaction for selected categories. If a declaration requests raw output for data that requires redaction, v0.6 deterministically selects a permitted safer mode in this order: redacted, aggregated, metadata-only. The resulting requirement is emitted as an authorization constraint.

Sensitive categories also emit a `data:minimize` constraint. Positive decisions bind the chosen output handling as `output:handling=<mode>` so the requirement is represented in the authorization evidence rather than remaining implicit profile metadata.

These constraints are requirements on the surrounding executor. v0.6 does not itself redact bytes or inspect live tool output.

## Retention

Every declaration includes an explicit requested retention period. A request exceeding the resource profile ceiling is denied. Positive decisions bind either `retention:no-persist` or `retention:seconds=<n>` into authorization constraints.

The reference maximum accepted profile value is ten years in seconds. This is a technical bound, not a legal retention recommendation.

## Evidence linkage

`DataGovernanceDecision` binds the exact request, declaration, current profile, institution data-governance registry snapshot, purpose, categories, output handling, retention, decision, constraints and reasons.

Its SHA-256 artifact digest is added to `AuthorizationDecision.governance_evidence_digests`. The authenticated-authorization digest therefore commits to the exact v0.6 data-governance evidence, and the v0.5 execution lease and signed receipt continue to bind that authenticated authorization without changing the execution receipt format.

When base policy explicitly requires human approval, data-governance constraints remain available in the separate bound `DataGovernanceDecision`; the authenticated authorization still binds its digest. Human approval cannot override a v0.6 data-governance denial.

## Execution currentness

`DataGovernedExecutionGate` wraps the v0.5 `ExecutionGate`. Before lease issuance and again before redemption it verifies that the v0.6 registry snapshot and exact resource profile still match the data-governance decision used during authorization. Any profile or registry drift invalidates the old execution path and requires fresh authorization.

MCP governance, emergency-stop state, authorization freshness, executor binding and one-time lease redemption remain enforced by the underlying v0.5 gate.

## Fail-closed conditions

The v0.6 path denies or blocks continuation when, among other conditions, the data-use declaration is missing, bound to another request/resource/purpose, under-reports categories, references a future or pre-request declaration time, lacks a current enabled resource profile, disagrees with resource classification, uses an incompatible purpose, exceeds the retention ceiling, requests an output mode for which no permitted safe transformation exists, or becomes stale because governance state changed.

## Assurance boundary and non-claims

v0.6 is governance metadata and deterministic policy evidence. It does not perform data discovery, DLP scanning, PII detection, semantic purpose inference, legal-basis determination, consent management, byte-level redaction, deletion enforcement, retention scheduling or regulatory certification.

Resource categories, compatible purposes and output requirements are institution-owned assertions. Their correctness remains an operator and governance responsibility. Later assurance and production-reference milestones add evidence mapping, tenant/crypto hardening and runtime deployment controls.