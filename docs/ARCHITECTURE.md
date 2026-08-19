# RegAgentOps Architecture

## v0.7 boundary

RegAgentOps v0.7 is an **offline authenticated authorization, data/purpose governance, human-approval, MCP-governance, signed execution-evidence and human-reviewed assurance-evidence control plane**.

The v0.7 assurance layer is intentionally downstream and non-authoritative for execution: it crosswalks exact evidence digests to human-confirmed framework references, but it cannot widen an authorization decision, satisfy an approval requirement, issue an execution lease or create a regulatory/compliance conclusion.

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

## Assurance scope identity

`AssuranceScope` binds an assurance review to one institution, AI-system identifier, deployment identifier, accountable human owner, environment and an exact SHA-256 digest of the external deployment/system context record.

The core does not ingest or interpret that external context document. The digest makes scope substitution detectable while leaving inventory, architecture, model-card, risk-assessment or deployment records in their source systems.

## Pinned framework-version boundary

v0.7 recognizes three framework namespaces with explicit versions:

- `nist_ai_rmf` → `1.0`;
- `iso_iec_42001` → `2023`;
- `eu_ai_act` → `2024/1689`.

The pin is enforced in Python and JSON Schema. A framework revision cannot silently change historical or current crosswalk semantics; support for a new version requires an explicit software/contract update.

`reference_id` is intentionally operator supplied. RegAgentOps does not embed or validate full normative framework text and therefore does not act as a framework-content authority.

## Human-confirmed applicability

`AssuranceApplicabilityAssertion` is a required artefact, not a derived boolean. It binds:

- exact assurance-scope digest;
- framework and pinned framework version;
- operator-supplied framework reference identifier;
- `APPLICABLE` or `NOT_APPLICABLE` status;
- human confirmation basis;
- confirming human identity; and
- confirmation time.

No prompt, model output, policy decision, data classification, risk tier or tool metadata can automatically create framework applicability.

For EU AI Act mappings, the assertion additionally carries at least one human-confirmed operator role: provider, deployer, authorised representative, importer, distributor or product manufacturer. EU-role fields are rejected for NIST AI RMF and ISO/IEC 42001 assertions.

The human identity field is evidence metadata rather than a new signed identity protocol. Cryptographically signed configuration/change-control is intentionally deferred to v0.8.

## Evidence references

`AssuranceEvidenceReference` binds an evidence identifier to:

- exact assurance scope;
- exact subject artifact SHA-256 digest;
- artifact type;
- artifact schema version;
- source component; and
- evidence-recording time.

The record is a digest reference. It does not independently establish external artifact existence, truthfulness, completeness, immutability or legal sufficiency.

Earlier RegAgentOps artefacts can be referenced without changing their schemas: authenticated authorization decisions, data-governance decisions, approval resolutions, MCP policy-enforcement results, execution leases, signed execution receipts and other evidence can be addressed by digest.

## Crosswalk semantics

`AssuranceCrosswalkEntry` binds one exact human applicability assertion to zero or more exact evidence-reference digests and one coverage state:

`SUPPORTED | PARTIAL | GAP | NOT_APPLICABLE`

These states describe evidence coverage, not compliance.

- `SUPPORTED` and `PARTIAL` require at least one evidence reference.
- `GAP` and `NOT_APPLICABLE` forbid evidence references.
- a human `NOT_APPLICABLE` assertion can only produce `NOT_APPLICABLE` coverage;
- a human `APPLICABLE` assertion cannot be rewritten to `NOT_APPLICABLE`.

Every mapping requires a human mapper identity, rationale and mapping time. The registry does not infer coverage from the number or type of artifacts.

## Assurance package integrity

`AssuranceEvidencePackage` is assembled from exact registered crosswalk-entry digests for one scope. The package contains the derived exact sets of:

- crosswalk-entry digests;
- applicability-assertion digests;
- evidence-reference digests; and
- framework namespaces.

`AssuranceEvidenceRegistry.verify_package()` resolves those exact entries and recomputes the expected assertion/evidence/framework sets. Substitution, unknown digests or cross-scope references fail closed.

Package semantics are structurally constrained:

- `certification_claimed` must be `false`;
- `conformity_claimed` must be `false`;
- `legal_compliance_determined` must be `false`; and
- `requires_human_review` must be `true`.

The assurance layer therefore cannot manufacture a valid object that represents itself as an ISO certificate, conformity statement or legal-compliance determination.

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

v0.2 signed authenticated identity remains mandatory. v0.3 approval cannot override denial. v0.4 MCP governance remains explicit and non-executing. v0.5 leases remain short-lived, one-time and executor-bound. v0.6 data-purpose governance remains exact, request-bound and currentness checked before execution.

The authenticated-authorization and signed-receipt chains are not modified by v0.7.

## Trust boundaries

1. **Caller → identity/policy plane**: action and identity inputs remain untrusted until verified.
2. **Institution data governance → data registry**: resource categories, purpose compatibility, output and retention configuration remain privileged governance input.
3. **Institution MCP configuration → MCP registry**: server approvals, pins and tool bindings remain privileged configuration.
4. **Authenticated authorization → approval/execution**: exact digests and current state remain execution authority; assurance objects are not accepted here.
5. **External assurance context → `AssuranceScope`**: the caller provides an exact context digest; RegAgentOps does not interpret the source record.
6. **Human reviewer → applicability assertion**: framework applicability and EU operator roles are accountable human assertions, not machine-derived facts.
7. **Evidence source → evidence reference**: exact subject digests cross into the assurance registry; source truth/immutability is not independently proven.
8. **Human mapper → crosswalk entry**: coverage and rationale are human judgments constrained by exact assertion/evidence linkage.
9. **Crosswalk registry → evidence package**: selected exact entries determine package contents; package verification rejects digest-set substitution.
10. **Assurance package → external auditor/legal/compliance process**: the package is organized evidence only; acceptance, sufficiency and legal conclusions remain external.

## Historical evidence versus current state

The assurance registry is append-only by identity: reusing a scope/assertion/evidence/entry identity with different content fails. New entries do not rewrite old package digests.

Unlike the v0.5/v0.6 execution path, assurance packages are historical review artifacts and are not required to become invalid merely because new evidence is later registered. A new review can assemble a new package when scope, applicability or evidence changes.

## Capability separation

Authorization, identity, approval, MCP-governance, execution, data-governance and assurance modules are statically checked in CI to reject network/process capability imports.

`assurance.py` contains no framework web client, document scraper, legal classifier, automatic applicability engine, certification scorer, MCP connection or tool invocation interface. It consumes explicit human and digest artefacts only.

Signed configuration change control, tenant-isolated durable storage, KMS/HSM keys and external immutable audit anchoring remain v0.8 concerns.

## Standards posture

NIST AI RMF 1.0, ISO/IEC 42001:2023 and Regulation (EU) 2024/1689 are framework/version namespaces for evidence mapping. RegAgentOps does not reproduce full normative text or claim that a mapped reference has been legally or auditorily satisfied.

A `SUPPORTED` crosswalk state means only that a human mapper associated exact evidence with that reference for the exact assurance scope. It is not a compliance, conformity or certification result.