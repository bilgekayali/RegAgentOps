# Threat Model — v0.7

## Protected assets

- authorization policy integrity and governance-evidence binding;
- institution, human-owner, agent, model and workload identity bindings;
- data-resource classification/category integrity;
- primary-purpose and compatible-secondary-purpose configuration;
- sensitive-data minimization, output-handling and retention requirements;
- data-governance registry/profile currentness;
- approval authority, signature and replay integrity;
- MCP server approval, identity-pin, snapshot and binding integrity;
- execution-lease integrity, executor binding and one-time consumption state;
- emergency-stop state integrity;
- executor signing-key trust and signed execution-receipt integrity;
- assurance-scope identity and context digest;
- human-confirmed framework applicability and EU operator-role assertions;
- exact evidence-reference, crosswalk and assurance-package digest linkage;
- pinned NIST AI RMF, ISO/IEC 42001 and EU AI Act framework-version semantics;
- explicit non-certification, non-conformity and non-legal-determination semantics;
- separation between assurance evidence and authorization/execution authority.

## Trust boundaries

1. **Caller → identity/policy plane**: action, identity and request inputs are untrusted until verified.
2. **Institution data configuration → data-governance registry**: classification, categories, purposes, output and retention settings are privileged governance input.
3. **Institution MCP configuration → MCP registry**: server approvals, identity pins and tool bindings remain privileged administrative input.
4. **Authenticated authorization → approval/execution**: exact policy/governance artifacts remain execution authority; assurance objects are not accepted here.
5. **External system inventory/context → `AssuranceScope`**: RegAgentOps receives an exact context digest but does not interpret or attest the source document.
6. **Human reviewer → applicability assertion**: applicability and EU operator roles are accountable human assertions rather than machine-derived facts.
7. **Evidence source → evidence reference**: exact subject-artifact digests and metadata are registered; source existence/truthfulness is not independently established.
8. **Human mapper → crosswalk entry**: evidence-coverage state and rationale are human judgments constrained by exact assertion/evidence linkage.
9. **Assurance registry → evidence package**: package contents are derived from exact registered entry digests and verified against them.
10. **Assurance package → auditor/legal/compliance process**: sufficiency, conformity, certification and legal conclusions remain external.
11. **Execution lease ledger → external executor**: atomic one-time consumption remains the final RegAgentOps pre-dispatch boundary.
12. **External executor → signed receipt**: represented result digest/outcome is evidence, not independently observed truth.

## Primary threats and controls

### Framework-version drift

Threat: a framework changes, but old evidence mappings are silently interpreted against new requirements.

Controls: v0.7 pins NIST AI RMF `1.0`, ISO/IEC 42001 `2023` and EU AI Act Regulation `2024/1689` in both Python and JSON Schema. An assertion or crosswalk entry with another version is rejected. Supporting a revised framework requires an explicit contract/code change.

Residual boundary: RegAgentOps does not retrieve amendment/revision status online. Framework maintenance is a product/version-management responsibility.

### Automated applicability laundering

Threat: a model, prompt, policy engine or caller labels a framework reference applicable/not-applicable and presents that as a legal/governance determination.

Controls: every `AssuranceCrosswalkEntry` must bind an exact `AssuranceApplicabilityAssertion` containing a confirmation basis, `confirmed_by_human_id` and confirmation time. The assurance module has no automatic applicability or legal-rules interface. Dedicated CI rejects markers for automatic compliance determination.

Residual boundary: v0.7 records the human identity as typed evidence metadata; it does not cryptographically prove that the named human actually performed the review. Signed configuration/change-control is deferred to v0.8.

### EU AI Act role substitution

Threat: evidence is mapped under a role such as deployer/provider without accountable review, or an EU role is reused in unrelated framework mappings.

Controls: EU AI Act assertions require at least one explicit governed operator role. NIST AI RMF and ISO/IEC 42001 assertions reject EU-role fields. The exact role tuple is digest-bound into the applicability assertion.

Residual boundary: RegAgentOps does not determine whether the role is legally correct, whether Article 25 changes an operator's status, whether the system is high-risk/GPAI, or which obligations ultimately apply.

### Applicability-state reversal

Threat: a human marks a framework reference applicable, but a later crosswalk entry silently changes it to not applicable, or vice versa.

Controls: `AssuranceCrosswalkEntry` binds the exact applicability-assertion digest. An applicable assertion cannot use `NOT_APPLICABLE` coverage; a not-applicable assertion must use `NOT_APPLICABLE` and cannot carry evidence.

### Evidence-free support claim

Threat: a crosswalk claims support without any exact evidence.

Controls: `SUPPORTED` and `PARTIAL` coverage require at least one evidence-reference digest in both Python validation and JSON Schema. `GAP` and `NOT_APPLICABLE` forbid evidence references.

### Cross-scope evidence substitution

Threat: evidence from another AI system, deployment or context is reused to support the current assurance scope.

Controls: scopes, applicability assertions, evidence references and crosswalk entries all bind the exact `scope_digest`. Registry entry registration rejects evidence belonging to a different scope. Package verification rejects cross-scope assertions/evidence.

### Crosswalk assertion substitution

Threat: evidence for one framework reference is attached to a different applicability assertion/reference.

Controls: entry registration requires exact equality of scope, framework, pinned version and `reference_id` between the entry and the referenced human applicability assertion. The assertion digest is then bound into the crosswalk entry.

### Assurance-package set substitution

Threat: a package retains valid entry digests but modifies the advertised assertion/evidence/framework sets.

Controls: `verify_package()` resolves the exact registered crosswalk entries and recomputes the expected assertion, evidence and framework sets. Any mismatch fails closed.

### Certification or legal-compliance overclaim

Threat: mapped evidence is presented as a certification, ISO conformity statement or legal compliance determination.

Controls: `AssuranceEvidencePackage` structurally requires `certification_claimed = false`, `conformity_claimed = false`, `legal_compliance_determined = false` and `requires_human_review = true`. Opposite values cannot construct a valid Python object and violate the JSON contract.

Residual boundary: downstream users can still misdescribe or misuse an artifact outside RegAgentOps. Documentation, process governance and contractual controls remain necessary.

### Evidence-reference fabrication

Threat: a caller registers a digest/reference for an artifact that does not exist, is incomplete or is not authoritative.

Controls: v0.7 makes the exact declared subject digest and metadata immutable within the evidence-reference artifact and package mapping; substitution changes the digest.

Residual boundary: RegAgentOps does not fetch, independently verify or immutably anchor the external artifact in v0.7. Source-system integrity and evidence retention remain external; immutable/external anchoring is a v0.8 milestone.

### Evidence sufficiency overclaim

Threat: one or more valid artifacts are assumed to fully satisfy a framework requirement merely because they are mapped.

Controls: coverage states are evidence terms (`SUPPORTED`, `PARTIAL`, `GAP`, `NOT_APPLICABLE`), not pass/fail compliance states. Mapping rationale and mapper human identity are mandatory. The system does not calculate a compliance score or automatically upgrade `PARTIAL` to `SUPPORTED`.

### Assurance-to-execution privilege escalation

Threat: an assurance package or framework mapping is used to override a policy/data denial, approval requirement, emergency stop or stale execution state.

Controls: v0.7 assurance classes are not accepted by the policy engine, approval gate, MCP PEP or execution gate. The flow is one-way from existing governance artifacts into assurance references. Assurance mappings cannot issue leases or alter authorization decisions.

### Sensitive-category under-reporting

Controls from v0.6 remain: `DataUseDeclaration.observed_data_categories` must exactly equal the current `DataResourceProfile.data_categories`. RegAgentOps still does not scan live payload bytes.

### Purpose laundering, output downgrade and retention expansion

Controls from v0.6 remain: exact purpose/profile matching, explicit compatible-secondary use, sensitive-output constraints and retention ceilings fail closed and are bound into authenticated authorization evidence.

### Data-governance drift

Controls from v0.6 remain: exact data-governance decision/profile/snapshot evidence is authorization-bound and currentness is revalidated before lease issuance/redemption.

### Authorization-to-execution substitution and replay

Controls from v0.5 remain: leases bind exact request/authentication/policy/MCP/approval/emergency-stop/executor evidence; authorization freshness and lease lifetime are bounded; redemption is atomic and one-time; receipt construction requires recorded consumption.

### MCP governance drift and server/tool substitution

Controls from v0.4/v0.5 remain: institution-owned server IDs and identity pins, bounded snapshots, exact current descriptor bindings, conflicting-latest failure and execution-time revalidation.

### Human approval override

Controls from v0.3 remain: approval cannot create continuation from identity, policy or data-governance `DENY`. Requester separation, bounded delegated authority, signatures and one-time approval redemption remain active.

### Identity substitution and JWT key confusion

Controls from v0.2 remain: registered owner/provider/subject binding, pinned issuer/client/audience/algorithm policy, nonce/time checks, remote key-selection header rejection, signed workload identity and signed authenticated context.

### Capability creep

Threat: assurance code quietly becomes a framework scraper, online legal rules engine, certification scorer or execution capability.

Controls: generic CI and the dedicated Assurance Evidence Boundary reject network/process imports, invocation markers and automatic compliance-classification markers in `assurance.py`. The module consumes explicit human/digest artifacts only.

## Residual risks

Applicability, EU operator roles, framework reference identifiers, evidence coverage and mapping rationale remain human/institution assertions. RegAgentOps enforces exact linkage and non-claim semantics but cannot establish that those judgments are legally or auditorily correct.

Evidence references are digest records, not external immutable storage. v0.7 does not prove that the referenced artifact is available, complete, truthful, generated by a trusted system or retained for a legally sufficient period.

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