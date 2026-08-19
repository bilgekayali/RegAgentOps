# RegAgentOps Architecture

## v0.7 boundary

RegAgentOps v0.7 is an **offline authenticated authorization, data/purpose governance, human-approval, MCP-governance, signed execution-evidence and human-reviewed assurance-evidence control plane**.

The v0.7 assurance layer is downstream and non-authoritative for execution: it crosswalks exact evidence digests to human-confirmed framework references, but it cannot widen an authorization decision, satisfy an approval requirement, issue an execution lease or create a regulatory/compliance conclusion.

It still does **not** discover data, scan for PII, infer legal purpose, determine framework applicability, classify EU AI Act risk, retrieve framework text, connect to MCP servers, obtain production credentials, redact output bytes or invoke a requested tool.

```text
                    EXECUTION CONTROL PLANE

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

                    ASSURANCE EVIDENCE PLANE

       external system/deployment context digest
                          |
                          v
                    AssuranceScope
                          |
                  human applicability
                          v
          AssuranceApplicabilityAssertion
                /                    \
               /                      \
      exact evidence digests          explicit GAP / N/A
             |                         |
             v                         |
  AssuranceEvidenceReference           |
             \                         /
              +-----------------------+
                          |
                          v
              AssuranceCrosswalkEntry
                          |
                          v
              AssuranceEvidencePackage
```

## Assurance scope identity and history

`AssuranceScope` binds an assurance review to one institution, AI-system identifier, deployment identifier, accountable human owner, environment and an exact SHA-256 digest of the external deployment/system context record.

The registry identity includes institution, system, deployment **and context digest**. A changed external context therefore creates a new immutable historical scope rather than rewriting the existing deployment scope. New context scopes for the same deployment must be chronologically non-decreasing; a later-registered context cannot claim an earlier `recorded_at` than the existing deployment scope history.

The core does not ingest or interpret the external context document. The digest makes scope substitution detectable while leaving inventory, architecture, model-card, risk-assessment or deployment records in their source systems.

## Pinned framework-version boundary

v0.7 recognizes three framework namespaces with explicit versions:

- `nist_ai_rmf` → `1.0`;
- `iso_iec_42001` → `2023`;
- `eu_ai_act` → `2024/1689`.

The pin is enforced in Python and JSON Schema. A framework revision cannot silently change historical or current crosswalk semantics; support for a new version requires an explicit software/contract update.

`reference_id` is intentionally operator supplied. RegAgentOps does not embed or validate full normative framework text and therefore does not act as a framework-content authority.

## Human-confirmed applicability

`AssuranceApplicabilityAssertion` is a required artefact, not a derived boolean. It binds exact scope, framework/version/reference, applicability, confirmation basis, human reviewer and time. EU AI Act assertions additionally bind at least one human-confirmed operator role; EU roles are rejected on NIST and ISO mappings.

For one exact scope/framework/version/reference tuple, the v0.7 registry permits one immutable applicability assertion. A contradictory second assertion under another ID is rejected. A changed applicability judgment therefore belongs to a new assurance scope/context.

Applicability confirmation cannot predate the referenced scope. No prompt, model output, policy decision, data classification, risk tier or tool metadata can automatically create framework applicability.

The human identity field is evidence metadata rather than a new signed identity protocol. Cryptographically signed configuration/change-control is deferred to v0.8.

## Evidence references

`AssuranceEvidenceReference` binds an evidence identifier to exact assurance scope, subject artifact SHA-256 digest, artifact type/schema version, source component and recording time.

The record is a digest reference. It does not independently establish external artifact existence, truthfulness, completeness, immutability or legal sufficiency. An evidence reference cannot predate its scope.

Earlier RegAgentOps artefacts can be referenced without changing their schemas: authenticated authorization decisions, data-governance decisions, approval resolutions, MCP policy-enforcement results, execution leases, signed execution receipts and other evidence can be addressed by digest.

## Crosswalk semantics and uniqueness

`AssuranceCrosswalkEntry` binds one exact human applicability assertion to zero or more exact evidence-reference digests and one coverage state:

`SUPPORTED | PARTIAL | GAP | NOT_APPLICABLE`

These states describe evidence coverage, not compliance. `SUPPORTED` and `PARTIAL` require evidence; `GAP` and `NOT_APPLICABLE` forbid evidence. A human `NOT_APPLICABLE` assertion can only produce `NOT_APPLICABLE` coverage, while an `APPLICABLE` assertion cannot be rewritten to `NOT_APPLICABLE`.

Each exact applicability assertion can have one immutable crosswalk entry. Parallel entries with conflicting coverage are rejected. Mapping cannot predate either the applicability confirmation or any mapped evidence reference.

Every mapping requires a human mapper identity, rationale and mapping time. The registry does not infer coverage from the number or type of artifacts.

## Assurance package integrity

`AssuranceEvidencePackage` is assembled from exact registered crosswalk-entry digests for one scope. The package contains derived exact sets of crosswalk entries, applicability assertions, evidence references and framework namespaces.

Package assembly must occur at or after every included crosswalk entry. Duplicate crosswalk-entry inputs are rejected instead of silently deduplicated.

Built packages are registered by institution and `package_id`. Reusing a package identity with different content fails closed. `verify_package()` also checks any registered package identity before resolving entries and recomputing the expected assertion/evidence/framework sets. Substitution, unknown digests, chronology violations or cross-scope references fail closed.

Package semantics are structurally constrained:

- `certification_claimed` must be `false`;
- `conformity_claimed` must be `false`;
- `legal_compliance_determined` must be `false`; and
- `requires_human_review` must be `true`.

The assurance layer therefore cannot manufacture a valid object that represents itself as an ISO certificate, conformity statement or legal-compliance determination.

## Chronological provenance

The registry enforces this dependency ordering:

```text
scope.recorded_at <= applicability.confirmed_at <= crosswalk.mapped_at <= package.assembled_at
scope.recorded_at <= evidence.recorded_at       <= crosswalk.mapped_at <= package.assembled_at
```

Equal timestamps are allowed. The timestamps are application evidence and are not an independent trusted timestamp authority.

## Relationship to execution authorization

v0.7 is one-way with respect to earlier governance evidence:

```text
v0.1-v0.6 artifacts --> assurance evidence references --> crosswalk/package

assurance package -X-> policy allow
assurance package -X-> approval continuation
assurance package -X-> execution lease
```

No v0.7 class is accepted by the policy engine, approval gate, MCP PEP or execution gate. An assurance mapping cannot override `DENY`, satisfy `REQUIRE_HUMAN_APPROVAL`, relax data constraints, suppress emergency stop or make stale governance current.

## Existing authorization and execution boundaries retained

v0.1 policy precedence remains:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

v0.2 signed authenticated identity remains mandatory. v0.3 approval cannot override denial. v0.4 MCP governance remains explicit and non-executing. v0.5 leases remain short-lived, one-time and executor-bound. v0.6 data-purpose governance remains exact, request-bound and currentness checked before execution. The authenticated-authorization and signed-receipt chains are not modified by v0.7.

## Trust boundaries

1. **Caller → identity/policy plane**: action and identity inputs remain untrusted until verified.
2. **Institution data governance → data registry**: resource categories, purpose compatibility, output and retention configuration remain privileged governance input.
3. **Institution MCP configuration → MCP registry**: server approvals, pins and tool bindings remain privileged configuration.
4. **Authenticated authorization → approval/execution**: exact digests and current state remain execution authority; assurance objects are not accepted here.
5. **External assurance context → `AssuranceScope`**: the caller provides an exact context digest; RegAgentOps does not interpret the source record.
6. **Human reviewer → applicability assertion**: framework applicability and EU operator roles are accountable human assertions, not machine-derived facts.
7. **Evidence source → evidence reference**: exact subject digests cross into the assurance registry; source truth/immutability is not independently proven.
8. **Human mapper → crosswalk entry**: coverage and rationale are human judgments constrained by exact assertion/evidence linkage and chronology.
9. **Crosswalk registry → evidence package**: exact entries determine immutable package identity and contents; verification rejects digest-set substitution.
10. **Assurance package → external auditor/legal/compliance process**: the package is organized evidence only; acceptance, sufficiency and legal conclusions remain external.

## Historical evidence versus current state

The assurance registry is append-only by identity. Scope context history is retained; exact scope/framework/reference applicability is singular within a scope; each applicability assertion has one crosswalk; and built package identities are immutable.

Unlike the v0.5/v0.6 execution path, assurance packages are historical review artifacts and do not become invalid merely because unrelated evidence is later registered. When the external context, applicability judgment or material mapping changes, the v0.7 model expects a new assurance scope/context and a newly assembled package rather than mutating the old review.

## Capability separation

Authorization, identity, approval, MCP-governance, execution, data-governance and assurance modules are statically checked in CI to reject network/process capability imports.

`assurance.py` contains no framework web client, document scraper, legal classifier, automatic applicability engine, certification scorer, MCP connection or tool invocation interface. It consumes explicit human and digest artefacts only.

Signed configuration change control, tenant-isolated durable storage, KMS/HSM keys and external immutable audit anchoring remain v0.8 concerns.

## Standards posture

NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689 are framework/version namespaces for evidence mapping. RegAgentOps does not reproduce full normative text or claim that a mapped reference has been legally or auditorily satisfied.

A `SUPPORTED` crosswalk state means only that a human mapper associated exact evidence with that reference for the exact assurance scope. It is not a compliance, conformity or certification result.