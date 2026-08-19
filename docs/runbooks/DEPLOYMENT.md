# Deployment Runbook

## Purpose

Use this runbook when promoting a RegAgentOps release into a production-reference environment. The runbook assumes infrastructure automation exists outside the RegAgentOps core. It does not authorize operators to bypass institutional change management, segregation of duties or production-access controls.

## Preconditions

Before promotion, confirm that the target `DeploymentReleaseManifest` resolves to the expected institution and tenant and that `ProductionDeploymentRegistry.assert_release_current()` succeeds. Confirm the release artifact SHA-256 against the published `SHA256SUMS` file, retain the CodeQL evidence reference, and verify the GitHub artifact attestation under the repository/release policy used by the institution.

Confirm the referenced worker profile is the approved profile for the tenant. Runtime deployment must enforce non-root execution, read-only root filesystem, no-new-privileges, all capabilities dropped, `RuntimeDefault` seccomp, isolated network namespace, no host PID/IPC/network namespace, no privileged mode and no direct tool invocation.

Confirm that the exact egress and tool allowlist policy versions in the worker profile are still current. A policy or allowlist change after release registration requires a new worker/release binding rather than an exception.

## Promotion sequence

1. Freeze the exact source commit, release artifact hash, configuration digest and worker-profile digest in the production change record.
2. Validate the `UpgradePlan`. The from-release must match the currently deployed release under the external deployment inventory. The to-release must match the intended release.
3. Validate that the referenced `RollbackPlan` exactly reverses the upgrade and that its rollback window, trigger conditions and verification procedure are operationally available.
4. Verify the v0.8 signed configuration-change digest and ensure its effective time has been reached.
5. Apply infrastructure changes only through the approved deployment platform. Do not grant the policy worker direct tool credentials or unrestricted egress.
6. Apply the exact tenant-specific egress and tool allowlist controls. Default deny must remain the baseline.
7. Start the isolated worker and run the preflight/post-deploy checks represented by the upgrade plan.
8. Confirm identity, policy, approval, MCP, data-purpose, emergency-stop and execution-receipt regressions are healthy before opening normal production traffic.
9. Produce a new deployment evidence record outside the core and include it in the next audit-anchor batch.
10. Create or refresh a `RecoveryCheckpoint` only after backup and restore-verification evidence exists.

## Abort and rollback criteria

Abort promotion if artifact checksums, provenance, CodeQL evidence, worker profile, signed configuration change, tenant isolation, egress policy, tool allowlist or preflight checks do not match the approved change. Do not improvise a wider egress policy or temporary direct tool invocation to complete the deployment.

Trigger the registered rollback plan when an approved trigger condition occurs within its rollback window. Rollback must target the exact older release named in that plan; choosing an unregistered alternative release requires a new controlled change.

## Evidence to retain

Retain release manifest digest, source commit, artifact SHA-256, checksum manifest, provenance verification output, CodeQL review evidence, worker-profile digest, egress/tool-policy digests, signed configuration-change digest, upgrade and rollback plan digests, deployment-system event IDs, post-deploy verification evidence and the resulting audit-anchor record.
