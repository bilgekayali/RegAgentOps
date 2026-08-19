# Disaster Recovery Runbook

## Scope

Use this runbook when restoring a RegAgentOps production-reference deployment after infrastructure loss, corruption, destructive operator error, regional failure or another event requiring state restoration. The RegAgentOps core does not perform restore operations; the accountable infrastructure/data platform executes them under institutional DR controls.

## Recovery source selection

Select a `RecoveryCheckpoint` for the exact institution and tenant. Verify that the checkpoint binds the intended release digest, configuration digest, encrypted-backup digest, external audit-anchor record and restore-verification procedure/result digest. Do not use a checkpoint that predates the release it claims to represent.

Independently verify backup-object hashes, encryption-key availability and external anchor evidence using the institution's storage/KMS/audit systems. A digest recorded by RegAgentOps is not proof that the external backup still exists or is restorable.

## Isolated restore test

1. Restore into an isolated recovery environment before production cutover whenever operationally possible.
2. Re-establish PostgreSQL tenant isolation and verify RLS is enabled and forced with institution+tenant predicates. Do not infer deployment correctness from the v0.8 RLS artefact alone.
3. Restore KMS/HSM references and lifecycle state without reactivating retired or disabled keys.
4. Load the release artifact only after checksum and provenance verification.
5. Reapply the exact default-deny egress and tool allowlist policies required by the release's current worker profile.
6. Confirm worker isolation: non-root, read-only root filesystem, no-new-privileges, all capabilities dropped, `RuntimeDefault` seccomp, no privileged/host namespaces and no direct tool invocation.
7. Run identity, authorization, approval, MCP, data-purpose, emergency-stop, execution-receipt, tenant-hardening and deployment regression checks.
8. Execute the restore-verification procedure represented by the checkpoint and create new evidence for its outcome.

## Production cutover

Cut over only after the recovered release passes `assert_release_current()` against current egress/tool/worker policy and after institutional DR authority approves service restoration. If policies have changed since the checkpoint, create new versioned policies/worker profile/release evidence rather than weakening current controls to fit the historical checkpoint.

Re-enable normal execution progressively and retain emergency-stop readiness. Observe authentication failures, policy denials, executor activity, data-governance decisions and external dependencies for signs of incomplete restore.

## Post-recovery evidence

Create a new recovery checkpoint after the restored environment is stable and a new verified backup exists. Preserve the old checkpoint and incident evidence. Anchor recovery evidence externally, including source checkpoint, restored release/configuration, backup verification, key-state evidence, RLS/egress/tool enforcement checks, recovery test results and cutover approval.

## RTO/RPO boundary

This reference runbook does not define or prove RTO/RPO. Required objectives, backup frequency, geographic redundancy, storage immutability, database replication and recovery staffing are institution-specific production controls outside the RegAgentOps core.
