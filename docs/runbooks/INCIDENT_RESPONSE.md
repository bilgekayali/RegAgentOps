# Incident Response Runbook

## Scope

This runbook covers security or integrity incidents affecting a RegAgentOps production-reference deployment, including suspected credential compromise, policy/configuration tampering, tenant-isolation failure, unauthorized egress, executor misuse, evidence-chain breakage or release-provenance concerns.

## Immediate containment

1. Use the existing institution emergency-stop control to halt new execution leases where continued execution could increase impact.
2. Disable affected external credentials and network routes through the institution's IAM/network controls. RegAgentOps itself does not perform these privileged actions.
3. For suspected KMS/HSM key compromise, append a v0.8 lifecycle transition to `DISABLED`; do not reactivate the same key reference later.
4. Remove or deny the affected executor/tool/egress path in the external enforcement layer and create new versioned RegAgentOps policy artefacts rather than editing historical records.
5. Preserve the current release manifest, signed configuration changes, lease/consumption/receipt evidence, encrypted governance evidence and external audit-anchor records before remediation.

## Triage

Determine institution, tenant, affected release, worker-profile digest, egress-policy version, tool-allowlist version, configuration digest, source commit and key references. Establish the first known-bad and last known-good timestamps using application evidence plus independent infrastructure/SIEM timestamps where available.

Check whether the incident is limited to the policy-enforcement worker or extends to executor credentials, MCP configuration, data-purpose profiles, approval authority, tenant storage, KMS/HSM custody, release supply chain or the external audit anchor.

Do not treat a valid signed RegAgentOps artifact as proof that the underlying external system behaved correctly. Signatures protect represented evidence integrity; they do not independently attest runtime truth.

## Recovery decision

If a release or configuration is suspect, prefer the exact registered `RollbackPlan` when its trigger and window remain valid. If the rollback target or its dependencies are no longer current, do not widen policies to force rollback; create a separately approved recovery change based on a known-good release and current tenant/egress/tool controls.

If cryptographic material is affected, follow the key-rotation runbook. If data or state integrity is affected, follow the disaster-recovery runbook and restore only from a checkpoint whose encrypted-backup and external-anchor evidence are independently validated.

## Re-entry criteria

Normal execution may resume only after the emergency-stop owner approves re-entry under institutional procedure, affected key/credential state is remediated, current tenant/egress/tool policies are restored, a known-good release passes deployment verification, and new monitoring confirms no recurrence.

Create new evidence for containment, analysis, remediation, recovery and re-entry. Anchor the resulting incident evidence externally. Historical artefacts must remain immutable even when they document compromised state.

## Post-incident review

Record root cause, control failures, blast radius, tenant impact, key and credential exposure, rollback/recovery outcomes, detection gaps and corrective actions. Update threat model, deployment controls and runbooks where the incident exposed a missing invariant. Compliance, regulatory notification and customer-communication decisions remain accountable legal/risk decisions outside the RegAgentOps core.
