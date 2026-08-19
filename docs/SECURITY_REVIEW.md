# v1 Independent Security Review Checklist

The v1 stable-tag gate requires a completed `IndependentSecurityReviewChecklist`. This document defines what the twelve required checklist items are intended to cover; it does **not** assert that an independent review has already occurred.

Every item in the machine-readable review must be either:

- `closed`: the reviewer considers the item adequately addressed and binds exact review evidence plus rationale; or
- `risk_accepted`: the item remains accepted as residual risk and binds both review evidence and an accountable-human risk-acceptance identity/evidence digest.

No `open`, `pass-by-default`, empty or inferred status is valid for stable tag eligibility.

## Required items

### approval-replay-and-delegation

Review direct/delegated authority, requester/approver separation, expiry, replay prevention, denial finality and non-expanding delegation.

### assurance-non-claims

Review human-confirmed applicability, evidence mappings, chronology and structural prevention of certification/conformity/legal-compliance claims.

### authenticated-identity-binding

Review offline OIDC/JWKS validation, workload identity, registered owner/provider/subject binding, signing-key lifecycle and authenticated-context tamper resistance.

### authorization-default-deny

Review deterministic policy precedence, no-match deny behavior, evidence binding and absence of alternate authorization bypass paths.

### capability-creep

Review that governance/stability modules have not acquired hidden networking, shell/process, autonomous MCP discovery, deployment or tool-invocation capability outside declared adapters.

### data-purpose-and-retention

Review exact request/data-use binding, category under-reporting rejection, purpose compatibility, minimization/output handling, retention ceilings and currentness revalidation.

### execution-lease-and-receipts

Review authorization freshness, executor binding, one-time lease consumption, emergency-stop/MCP/data currentness and signed receipt evidence linkage.

### mcp-server-tool-binding

Review approved server identity, bounded snapshots, untrusted metadata treatment, explicit tool binding and stale/changed tool rejection.

### production-egress-tool-worker

Review exact default-deny egress, canonical endpoint identity, tool→executor allowlist, worker hardening, current tenant-isolation dependency and release currentness.

### release-provenance-and-reproducibility

Review CodeQL gate, reproducible two-build wheel check, SHA256SUMS, tag/version matching, artifact attestation and stable-tag review blocker.

### tenant-isolation-and-crypto-lifecycle

Review RLS reference semantics, exact tenant profile binding, KMS/HSM reference-only custody, one-way key lifecycle, configuration-change chain, AES-GCM nonce/AAD behavior and external anchor linkage.

### upgrade-rollback-and-recovery

Review exact 0.9.x source/1.0 target linkage, backup requirement, rollback evidence, current-release preconditions and recovery/restore evidence boundaries.

## Independence

`reviewer_independence_confirmed=true` is an explicit assertion by the party producing the review artifact. The repository does not infer independence from a username, employer, tool, CI result or the fact that a different file was created.

An implementation author should not fabricate this field on behalf of an independent reviewer.

## Risk acceptance

Risk acceptance is not equivalent to technical closure. If an item is `risk_accepted`, the review artifact must identify the accountable human and bind the exact risk-acceptance record digest. A generic project approval or PR merge approval should not be silently reinterpreted as acceptance of an unrelated security risk.

## Stable-tag workflow

The v1.0.0 tagged-release workflow expects the completed artifact at:

`security-review/v1.0-review.json`

The file is intentionally absent until a real review or explicit risk-acceptance process supplies it.
