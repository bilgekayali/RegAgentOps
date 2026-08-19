# Assurance Evidence

RegAgentOps v0.7 adds an offline assurance-evidence crosswalk over the governance artifacts produced by earlier milestones. It does not turn RegAgentOps into a certification product, legal-compliance engine, ISO conformity assessor, NIST checklist, or EU AI Act classifier.

The v0.7 boundary answers a narrower question:

> For one exact AI-system/deployment scope, which human-confirmed framework references are considered applicable, which exact governance-evidence digests have been mapped to those references, where are the gaps, and what evidence package can be reviewed later?

## Framework versions pinned by v0.7

v0.7 deliberately pins framework versions rather than silently following future revisions:

- NIST AI Risk Management Framework: `1.0`;
- ISO/IEC 42001: `2023`;
- EU Artificial Intelligence Act: Regulation `2024/1689`.

A future framework revision requires an explicit RegAgentOps contract/code change. Existing evidence packages therefore retain the framework-version semantics under which they were assembled.

Primary reference sources:

- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- ISO/IEC 42001: https://www.iso.org/standard/81230.html
- EU AI Act: https://eur-lex.europa.eu/eli/reg/2024/1689/oj

RegAgentOps stores operator-supplied `reference_id` values. It does not embed, reproduce, interpret, or validate the full normative text of those frameworks.

## Control sequence

```text
AssuranceScope
  institution + system + deployment + environment + context digest
                         |
                         v
        human applicability assessment
                         |
                         v
AssuranceApplicabilityAssertion
  framework + pinned version + reference id
  applicable / not_applicable
  confirmed_by_human_id + confirmation basis
  EU AI Act: human-confirmed operator role(s)
                         |
                         +----------------------+
                         |                      |
                         v                      v
          AssuranceEvidenceReference      explicit GAP / N/A
          exact subject artifact digest
                         |
                         v
             AssuranceCrosswalkEntry
       SUPPORTED / PARTIAL / GAP / N/A
                         |
                         v
             AssuranceEvidencePackage
     exact assertion + entry + evidence digests
     certification_claimed = false
     conformity_claimed = false
     legal_compliance_determined = false
     requires_human_review = true
```

## Exact assurance scope

`AssuranceScope` binds evidence mapping to one institution, AI-system identifier, deployment identifier, accountable human owner, environment and a SHA-256 digest of the external system/deployment context record.

The context digest lets an operator bind the crosswalk to an inventory, architecture, risk assessment or deployment record without RegAgentOps needing to ingest that document. A different deployment or context record requires a different scope digest.

## Human-confirmed applicability

`AssuranceApplicabilityAssertion` is mandatory before a crosswalk entry can be registered. It binds:

- exact assurance scope;
- framework and pinned framework version;
- operator-supplied framework `reference_id`;
- `applicable` or `not_applicable` status;
- human confirmation basis;
- confirming human identity; and
- confirmation time.

RegAgentOps does not infer applicability from prompts, model output, tool metadata, sector, data classification, risk tier or framework text.

The confirming human identity is typed evidence, not a new cryptographic identity boundary. v0.7 trusts the surrounding integration to ensure that `confirmed_by_human_id` corresponds to a real accountable reviewer. Signed configuration/change-control is a later v0.8 milestone.

## EU AI Act role mapping

EU AI Act applicability assertions additionally require at least one human-confirmed operator role from the v0.7 role vocabulary:

- provider;
- deployer;
- authorised representative;
- importer;
- distributor; or
- product manufacturer.

EU-role fields are forbidden on NIST AI RMF and ISO/IEC 42001 assertions.

This is evidence scoping only. RegAgentOps does not determine whether an organization legally has a particular role, whether a system is high-risk, whether Article 25 changes an operator's role, or which obligations ultimately apply. Those are human/legal-governance determinations outside the v0.7 core.

## Evidence references

`AssuranceEvidenceReference` records an exact SHA-256 digest of an evidence artifact together with its artifact type, schema version, source component, scope and recording time.

Typical subjects may include earlier RegAgentOps artifacts such as authenticated authorization decisions, data-governance decisions, approval resolutions, MCP governance results, execution leases or signed execution receipts.

The evidence-reference record proves what digest was mapped. It does not independently prove that an external artifact is complete, truthful, legally sufficient or available in immutable storage. External immutable anchoring remains a later milestone.

## Crosswalk coverage semantics

`AssuranceCrosswalkEntry` binds the exact human applicability assertion and exact evidence-reference digests to one framework reference.

Coverage states are deliberately non-compliance terms:

- `SUPPORTED`: mapped evidence exists and the human mapper considers it relevant support;
- `PARTIAL`: mapped evidence exists but the mapper records incomplete support;
- `GAP`: the reference is applicable but no evidence is mapped;
- `NOT_APPLICABLE`: the human applicability assertion says the reference is not applicable.

`SUPPORTED` and `PARTIAL` require evidence. `GAP` and `NOT_APPLICABLE` forbid evidence references. An applicable assertion cannot be rewritten as `NOT_APPLICABLE`, and a not-applicable assertion cannot be rewritten as `SUPPORTED`, `PARTIAL` or `GAP`.

The mapping rationale and mapper human identity are mandatory. RegAgentOps does not infer a coverage state from the presence or absence of artifacts.

## Evidence packages

`AssuranceEvidenceRegistry.build_package()` assembles exact crosswalk-entry, applicability-assertion and evidence-reference digests for one assurance scope. Package verification recomputes those sets from registered entries and rejects substitution or cross-scope evidence.

The package contract structurally fixes these non-claims:

- `certification_claimed = false`;
- `conformity_claimed = false`;
- `legal_compliance_determined = false`; and
- `requires_human_review = true`.

Callers cannot construct a valid v0.7 package with opposite values.

## NIST AI RMF crosswalk posture

v0.7 pins NIST AI RMF `1.0`. Framework reference IDs are supplied by the operator, for example a function/category/subcategory identifier. RegAgentOps does not treat the AI RMF or its Playbook as a mandatory checklist and does not calculate a NIST compliance score.

A `SUPPORTED` mapping means only that the human reviewer mapped specific evidence to the selected NIST reference for the exact scope.

## ISO/IEC 42001 mapping posture

v0.7 pins ISO/IEC 42001 `2023`. Operators may use clause/control identifiers as `reference_id` values, but RegAgentOps does not embed ISO normative text and does not decide whether a requirement is fulfilled.

A v0.7 evidence package is not an ISO/IEC 42001 certificate, audit report, statement of conformity or substitute for an accredited/qualified conformity-assessment process.

## EU AI Act mapping posture

v0.7 pins Regulation (EU) `2024/1689`. Operators may map exact evidence to selected Article/Annex/reference identifiers and must explicitly record the relevant operator role(s) on the applicability assertion.

RegAgentOps does not determine territorial scope, prohibited-practice status, high-risk classification, GPAI status, role conversion, legal deadlines or compliance. The crosswalk is an evidence-organizing aid for accountable human/legal review.

## Failure semantics

The v0.7 registry fails closed when, among other conditions:

- a framework version differs from the pinned v0.7 version;
- an applicability assertion references an unknown assurance scope;
- an EU AI Act assertion lacks a human-confirmed operator role;
- NIST/ISO assertions carry EU operator roles;
- a crosswalk entry does not match the exact human applicability assertion;
- applicable/not-applicable status is contradicted by coverage;
- supported/partial coverage lacks evidence;
- gap/not-applicable coverage carries evidence;
- evidence belongs to a different assurance scope;
- a package substitutes its assertion, evidence or framework set; or
- a package attempts to claim certification, conformity or legal compliance.

## Assurance boundary and non-claims

v0.7 provides deterministic digest linkage and evidence organization. It does **not** provide:

- automatic framework applicability determination;
- automated legal interpretation;
- AI-system or high-risk classification under the EU AI Act;
- ISO/IEC 42001 conformity assessment or certification;
- a NIST AI RMF compliance score;
- proof that mapped evidence is sufficient for an auditor, regulator or court;
- proof that referenced external artifacts are immutable, complete or truthful;
- regulatory, supervisory or certification acceptance; or
- production fitness.

The core remains offline and contains no framework web client, legal rules engine, network lookup, document scraper or production execution capability.
