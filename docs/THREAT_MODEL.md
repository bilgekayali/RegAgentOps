# Threat Model — v0.6

## Protected assets

- authorization policy integrity and governance-evidence binding;
- institution, human-owner, agent, model and workload identity bindings;
- data-resource classification/category integrity;
- primary-purpose and compatible-secondary-purpose configuration;
- sensitive-data minimization and output-handling requirements;
- retention ceilings and request-bound retention intent;
- data-governance registry/profile currentness;
- approval authority, signature and replay integrity;
- MCP server approval, identity-pin, snapshot and binding integrity;
- execution-lease integrity, executor binding and one-time consumption state;
- emergency-stop state integrity;
- executor signing-key trust and signed execution-receipt integrity;
- result-digest, policy-decision and authenticated-authorization linkage;
- separation between governance evidence and external execution capability.

## Trust boundaries

1. **Caller → identity/policy plane**: action, identity and request inputs are untrusted until verified.
2. **Institution data configuration → data-governance registry**: classification, categories, purposes, output modes, redaction requirements and retention ceilings are privileged governance input.
3. **Caller → `DataUseDeclaration`**: declared categories, purpose, output handling and retention are untrusted until exact request/profile validation succeeds.
4. **Data-governance registry → authenticated authorization**: only exact current profile/decision evidence may constrain or deny the existing policy result.
5. **Institution MCP configuration → MCP registry**: server approvals, identity pins and tool bindings remain privileged administrative input.
6. **MCP registry → authenticated PDP**: only current explicit bindings become governed tool actions; MCP annotations remain evidence only.
7. **Authenticated authorization → approval gate**: human approval binds exact authorization and cannot override identity, policy or data-governance denial.
8. **MCP/data/approval evidence → execution gate**: currentness is revalidated before lease issuance/redemption.
9. **Emergency-stop configuration → execution gate**: append-only institution stop state is privileged runtime-governance input.
10. **Execution lease ledger → external executor**: atomic one-time consumption is the final RegAgentOps pre-dispatch boundary.
11. **External executor → receipt builder**: executor-reported result digest/outcome is represented evidence, not independently observed truth.
12. **Executor signer → receipt verifier**: private executor keys remain outside RegAgentOps.

## Primary threats and controls

### Sensitive-category under-reporting

Threat: a caller omits `personal`, `financial`, `health`, credential or other sensitive categories to obtain weaker output or retention controls.

Control: `DataUseDeclaration.observed_data_categories` must exactly equal the current `DataResourceProfile.data_categories`. Subset matching is deliberately rejected. A mismatch produces `data_category_profile_mismatch` and terminates authorization.

Residual boundary: RegAgentOps does not scan live payload bytes. Correct resource categorization remains an institution/integration responsibility.

### Purpose laundering

Threat: an action authorized for one business purpose is reused against a resource for an unrelated purpose.

Controls: the request purpose is already bound into `AgentActionEnvelope` and policy matching. v0.6 independently requires the same purpose to be a resource primary purpose or an explicitly configured compatible secondary purpose. Secondary use is emitted as an explicit constraint. No prompt, tool description, model output or MCP annotation can create purpose compatibility.

Residual boundary: v0.6 does not determine legal basis or semantic purpose truthfulness; it enforces configured identifiers.

### Output-handling downgrade

Threat: raw sensitive output is requested even though the governed resource requires redaction or aggregation.

Controls: profiles explicitly declare categories requiring redaction and permitted output modes. Raw requests over such categories are deterministically constrained to a permitted safer mode—redacted, then aggregated, then metadata-only—or denied if no safe permitted mode exists. The chosen requirement is bound into authorization constraints.

Residual boundary: the core does not redact bytes. The surrounding executor must enforce the represented constraint.

### Retention expansion

Threat: a request asks to persist governed data beyond the institution-approved period.

Controls: each `DataUseDeclaration` contains explicit `retention_seconds`. Values above the current profile ceiling fail closed. Positive decisions bind either `retention:no-persist` or an exact retention-seconds constraint.

Residual boundary: v0.6 does not schedule deletion or independently prove downstream deletion occurred.

### Data-governance profile substitution

Threat: a decision produced under one resource profile is presented as if it were evaluated under another or newer profile.

Controls: `DataGovernanceDecision` binds exact request, declaration, profile and whole institution registry-snapshot digests. Its artifact digest is included in `AuthorizationDecision.governance_evidence_digests`. `DataGovernedExecutionGate` checks snapshot and exact profile currentness before lease issuance and redemption.

### Stale authorization after data-governance change

Threat: purpose compatibility, classification, redaction or retention configuration changes after authorization but before execution.

Control: any data-governance registry snapshot change invalidates the v0.6 decision for execution. Fresh data-purpose authorization is required before a new lease can proceed.

### Data-governance bypass through legacy MCP path

Threat: a caller invokes the v0.4 MCP adapter directly and represents that result as v0.6-governed authorization.

Controls: v0.6 exposes a distinct `DataPurposeMcpPolicyEnforcementOutcome` and `DataGovernedExecutionGate`. Positive v0.6 execution requires a bound `DataGovernanceDecision`; missing data-use context becomes `DENY`. `AuthorizationDecision.governance_evidence_digests` provides an explicit evidence hook for downstream inspection.

Residual boundary: v0.6 is a reference architecture, not a deployment policy. Production integration must route governed resources through the v0.6 boundary rather than exposing an ungoverned legacy entry point.

### Data-governance decision tampering

Threat: constraints, purpose, categories or profile linkage are modified after evaluation.

Control: canonical SHA-256 artifact digests bind the complete `DataGovernanceDecision`; that digest is part of authenticated authorization evidence. Any modified decision has a different digest and no longer matches the authorization chain.

### Authorization-to-execution substitution

Controls from v0.5 remain: the execution lease binds exact request, authenticated authorization, nested policy decision, MCP result, MCP snapshot, intended executor, emergency-stop state and approval evidence when required. Authorization freshness and lease lifetime are bounded to 120 seconds.

### Forged lease consumption or replay

Controls from v0.5 remain: lease redemption is atomic and append-only; receipt construction requires the exact consumption artifact to exist in the ledger; executor identity is bound through lease, consumption and receipt.

### MCP governance drift and server/tool substitution

Controls from v0.4/v0.5 remain: institution-owned server IDs and identity pins, bounded snapshots, exact current descriptor bindings, conflicting-latest failure and revalidation before execution.

### Human approval override

Controls from v0.3 remain: approval cannot create continuation from identity, base-policy or v0.6 data-governance `DENY`. Requester separation, bounded delegated authority, signatures and one-time approval redemption remain active.

### Identity substitution and JWT key confusion

Controls from v0.2 remain: registered owner/provider/subject binding, pinned issuer/client/audience/algorithm policy, nonce/time checks, remote key-selection header rejection, signed workload identity and signed authenticated context.

### Result substitution and executor-key substitution

Controls from v0.5 remain: signed execution receipts bind result, request, authorization, lease and consumption digests with domain-separated Ed25519 signatures and institution/executor/key trust binding.

### Capability creep

Threat: v0.6 quietly gains data-discovery, DLP, network, process or execution capability.

Controls: generic CI and the dedicated Data and Purpose Governance Boundary reject network/process imports and invocation markers in `data_governance.py`. The module consumes explicit caller/institution artifacts only. It has no scanner, client, discovery session or tool-execution interface.

## Residual risks

Resource categories, purpose relationships, redaction requirements and retention ceilings are institution-owned assertions. RegAgentOps does not independently determine whether those assertions are legally or factually correct.

Data-use declarations are exact signed/digest-bound governance inputs but are not generated by a trusted DLP scanner in this milestone. A surrounding integration that supplies incorrect observed categories can undermine policy unless institutional resource profiles remain accurate and authoritative.

The data-governance, MCP and emergency-stop registries are reference in-memory state. Configuration is not yet protected by signed change control, tenant-isolated durable storage, KMS/HSM keys or external immutable anchoring.

SQLite approval/execution ledgers remain local serialization boundaries rather than distributed consensus or physical WORM storage.

The core records output/retention constraints but does not transform output bytes, schedule deletion, prove downstream retention enforcement or inspect post-execution data flows.

A signed receipt proves integrity of represented evidence, not that an external executor actually performed the action exactly as represented or complied with every output/retention constraint.

## Explicit non-claims

v0.6 does not provide or claim:

- automatic PII/sensitive-data discovery or DLP scanning;
- legal data classification or legal-basis determination;
- consent-management functionality;
- semantic purpose inference or legal purpose-compatibility determination;
- byte-level redaction, tokenization or anonymization;
- retention scheduling, deletion enforcement or proof of deletion;
- autonomous MCP server/tool discovery or live MCP connectivity;
- production credential brokerage or tool invocation by the RegAgentOps core;
- distributed exactly-once execution guarantees across multiple executor nodes;
- independent proof that represented result bytes are truthful or complete;
- runtime sandboxing or external immutable audit storage;
- independent timestamp authority;
- regulatory or standards certification;
- production fitness.