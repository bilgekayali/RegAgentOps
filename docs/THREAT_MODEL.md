# Threat Model — v0.7

## Protected assets

- authorization policy integrity and governance-evidence binding;
- institution, human-owner, agent, model and workload identity bindings;
- data-resource classification/category, purpose, output and retention governance;
- approval authority, signature and replay integrity;
- MCP server approval, identity-pin, snapshot and binding integrity;
- execution-lease integrity, executor binding and one-time consumption state;
- emergency-stop state and signed execution-receipt integrity;
- assurance-scope identity, context history and chronology;
- human-confirmed framework applicability and EU operator-role assertions;
- unique exact-reference applicability and crosswalk identities;
- exact evidence-reference and assurance-package digest linkage;
- immutable package identity;
- pinned framework-version semantics; and
- separation between assurance evidence and authorization/execution authority.

## Trust boundaries

1. **Caller → identity/policy plane**: action, identity and request inputs are untrusted until verified.
2. **Institution data configuration → data-governance registry**: classification, categories, purposes, output and retention settings are privileged governance input.
3. **Institution MCP configuration → MCP registry**: server approvals, identity pins and tool bindings remain privileged administrative input.
4. **Authenticated authorization → approval/execution**: exact policy/governance artifacts remain execution authority; assurance objects are not accepted here.
5. **External system inventory/context → `AssuranceScope`**: RegAgentOps receives an exact context digest but does not interpret or attest the source document.
6. **Human reviewer → applicability assertion**: applicability and EU operator roles are accountable human assertions rather than machine-derived facts.
7. **Evidence source → evidence reference**: exact subject-artifact digests and metadata are registered; source existence/truthfulness is not independently established.
8. **Human mapper → crosswalk entry**: evidence-coverage state and rationale are human judgments constrained by exact assertion/evidence linkage and chronology.
9. **Assurance registry → evidence package**: package contents are derived from exact registered entry digests and protected by immutable package identity.
10. **Assurance package → auditor/legal/compliance process**: sufficiency, conformity, certification and legal conclusions remain external.
11. **Execution lease ledger → external executor**: atomic one-time consumption remains the final RegAgentOps pre-dispatch boundary.
12. **External executor → signed receipt**: represented result digest/outcome is evidence, not independently observed truth.

## Primary threats and controls

### Framework-version drift

Threat: a framework changes while old evidence mappings are silently interpreted against new requirements.

Controls: v0.7 pins NIST AI RMF `1.0`, ISO/IEC 42001 `2023` and EU AI Act Regulation `2024/1689` in Python and JSON Schema. Supporting a revised framework requires an explicit contract/code change.

Residual boundary: RegAgentOps does not retrieve amendment/revision status online.

### Automated applicability laundering

Threat: a model, prompt, policy engine or caller labels a framework reference applicable/not-applicable and presents that as an authoritative legal/governance determination.

Controls: every crosswalk entry must bind an exact human-confirmed applicability assertion containing confirmation basis, reviewer identity and time. The assurance module has no automatic applicability/legal-rules interface.

Residual boundary: the human identity is typed evidence metadata, not a signed reviewer assertion in v0.7. Signed configuration/change-control is deferred to v0.8.

### Contradictory applicability assertions

Threat: the same exact scope/framework/reference is simultaneously represented as applicable and not applicable through different assertion IDs.

Control: the registry permits one immutable `AssuranceApplicabilityAssertion` per exact scope/framework/version/reference tuple. A second assertion for that tuple fails closed. A changed judgment requires a new assurance context/scope.

### EU AI Act role substitution

Threat: evidence is mapped under provider/deployer or another operator role without accountable review, or EU roles leak into unrelated framework mappings.

Controls: EU AI Act assertions require at least one explicit governed operator role. NIST AI RMF and ISO/IEC 42001 assertions reject EU-role fields. The exact role tuple is digest-bound.

Residual boundary: RegAgentOps does not determine whether the asserted legal role, high-risk/GPAI status or resulting obligations are correct.

### Assurance-scope substitution or backdating

Threat: a changed deployment context overwrites the previous review scope, or a later context is backdated to appear historically valid.

Controls: scope identity includes institution/system/deployment/context digest, preserving changed context as a new historical scope. For the same deployment, a new context cannot have `recorded_at` earlier than the latest existing scope history. All downstream assurance artifacts bind the exact scope digest.

### Chronology fabrication

Threat: applicability, evidence, mapping or package artifacts claim to have existed before their dependencies.

Controls enforce:

`scope.recorded_at <= applicability.confirmed_at <= mapping.mapped_at <= package.assembled_at`

and

`scope.recorded_at <= evidence.recorded_at <= mapping.mapped_at <= package.assembled_at`.

Package verification repeats the mapping/package chronology check.

Residual boundary: these are application timestamps, not an independent trusted timestamp authority.

### Applicability-state reversal

Threat: a human assertion is applicable, but a crosswalk silently labels it not applicable, or vice versa.

Controls: a human `NOT_APPLICABLE` assertion requires `NOT_APPLICABLE` coverage; an `APPLICABLE` assertion cannot be mapped as `NOT_APPLICABLE`.

### Evidence-free support claim

Threat: a crosswalk claims evidence support without exact mapped evidence.

Controls: `SUPPORTED` and `PARTIAL` require at least one evidence-reference digest. `GAP` and `NOT_APPLICABLE` forbid evidence references.

### Conflicting crosswalk entries

Threat: the same exact applicability assertion receives parallel `SUPPORTED`, `PARTIAL` or `GAP` mappings.

Control: the registry permits one immutable crosswalk entry per exact applicability-assertion digest. Material mapping changes require a new assurance context/scope.

### Cross-scope evidence substitution

Threat: evidence from another system, deployment or context is reused in the current assurance scope.

Controls: scopes, applicability assertions, evidence references and crosswalk entries bind the exact scope digest. Cross-scope evidence is rejected during entry registration and package verification.

### Crosswalk assertion substitution

Threat: evidence for one framework reference is attached to a different applicability assertion/reference.

Controls: entry registration requires exact equality of scope, framework, pinned version and `reference_id` with the referenced applicability assertion.

### Package set substitution or duplicate-entry ambiguity

Threat: a package advertises assertion/evidence/framework sets different from its entries, or duplicate entry inputs are silently collapsed.

Controls: package assembly rejects duplicate crosswalk-entry digests. Verification resolves exact registered entries and recomputes the expected assertion, evidence and framework sets.

### Package-identity reuse

Threat: the same `package_id` is reused for different evidence content, reviewer or assembly time.

Controls: built packages are registered by institution/package ID. Reuse with a different artifact digest fails closed. Verification rejects an object that conflicts with an already registered package identity.

### Certification or legal-compliance overclaim

Threat: mapped evidence is represented as certification, ISO conformity or legal compliance.

Controls: `AssuranceEvidencePackage` structurally requires `certification_claimed = false`, `conformity_claimed = false`, `legal_compliance_determined = false` and `requires_human_review = true`.

Residual boundary: downstream users can still misdescribe an artifact outside RegAgentOps; process and contractual controls remain necessary.

### Evidence-reference fabrication

Threat: a caller registers a digest for an artifact that is unavailable, incomplete or unauthoritative.

Control: v0.7 makes the exact declared digest/type/schema/source immutable in the evidence reference and subsequent package linkage.

Residual boundary: v0.7 does not fetch, independently verify or externally anchor the referenced artifact. Immutable anchoring is a v0.8 milestone.

### Evidence-sufficiency overclaim

Threat: valid mapped artifacts are assumed to fully satisfy a framework requirement merely because they are present.

Controls: coverage states are evidence terms, not compliance states. Mapping rationale and human mapper identity are mandatory; no compliance score is calculated.

### Assurance-to-execution privilege escalation

Threat: an assurance package is used to override policy/data denial, approval, emergency stop or stale execution state.

Controls: assurance classes are not inputs to the policy engine, approval gate, MCP PEP or execution gate. Flow is one-way from existing governance artifacts into assurance evidence.

### Existing v0.2-v0.6 threats

Prior controls remain active: signed authenticated identity; approval separation/delegation/replay controls; bounded explicit MCP governance; exact data-purpose governance with category/purpose/output/retention checks; execution authorization freshness; executor-bound one-time leases; emergency-stop currentness; and signed execution-result evidence.

### Capability creep

Threat: assurance code becomes a framework scraper, online legal rules engine, certification scorer or execution capability.

Controls: generic CI and the dedicated Assurance Evidence Boundary reject network/process imports, invocation markers and automatic compliance-classification markers in `assurance.py`. The module consumes explicit human/digest artifacts only.

## Residual risks

Applicability, EU operator roles, framework reference identifiers, evidence coverage and mapping rationale remain human/institution assertions. RegAgentOps enforces exact linkage and non-claim semantics but cannot establish that those judgments are legally or auditorily correct.

Evidence references are digest records, not immutable external storage. v0.7 does not prove that a referenced artifact is available, complete, truthful, generated by a trusted system or retained for a sufficient period.

The assurance/data/MCP/emergency-stop registries are reference in-memory state. Configuration is not yet protected by signed change control, tenant-isolated durable storage, KMS/HSM keys or external immutable anchoring.

SQLite approval/execution ledgers remain local serialization boundaries rather than distributed consensus or physical WORM storage.

The core records output/retention constraints but does not transform output bytes, schedule deletion, prove downstream retention enforcement or inspect post-execution data flows.

A signed execution receipt proves integrity of represented evidence, not that an external executor actually performed the action exactly as represented. An assurance package organizes such evidence but does not increase that underlying proof strength.

## Explicit non-claims

v0.7 does not provide or claim:

- automatic NIST AI RMF applicability or compliance scoring;
- ISO/IEC 42001 conformity assessment, certification or audit opinion;
- EU AI Act territorial-scope, operator-role, prohibited-practice, high-risk, GPAI or obligation determination;
- legal advice, legal-basis determination or regulatory-compliance determination;
- proof that mapped evidence is sufficient for an auditor, regulator, supervisor or court;
- immutable/external storage or independent timestamp authority for assurance evidence;
- automatic PII/sensitive-data discovery or DLP scanning;
- consent-management functionality;
- semantic purpose inference or legal purpose-compatibility determination;
- byte-level redaction, tokenization or anonymization;
- retention scheduling, deletion enforcement or proof of deletion;
- autonomous MCP discovery or live MCP connectivity;
- production credential brokerage or tool invocation by the RegAgentOps core;
- distributed exactly-once execution across multiple executor nodes;
- runtime sandboxing;
- regulatory or standards certification; or
- production fitness.