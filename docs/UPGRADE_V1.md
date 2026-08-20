# Supported Upgrade Path: final v0.9.x → 1.0.0

RegAgentOps v1 defines one supported major-boundary upgrade source series: **final 0.9.x to 1.0.0**.

`SupportedUpgradePath` does not merely name the series. It binds the exact source `DeploymentReleaseManifest` digest and exact 1.0 target `DeploymentReleaseManifest` digest.

## Preconditions

Before applying a production integration upgrade:

1. identify the exact registered 0.9.x source release;
2. confirm the production registry still considers that source release current;
3. retain a verified backup/recovery checkpoint appropriate to the deployment;
4. bind the migration-plan, preflight-check, post-upgrade-check and rollback-plan evidence digests;
5. construct the exact 1.0 target release manifest with CodeQL, provenance and checksum evidence;
6. verify the 1.0 release against current worker, egress, tool-allowlist and tenant-isolation state; and
7. do not proceed when the stable compatibility/review/responsibility baseline is incomplete.

`backup_required` and `current_source_release_required` are structural `true` values in the v1 contract.

## Compatibility posture

The supported 0.9.x → 1.0.0 path declares no unbounded breaking migration in the represented governance data. The principal v1 change is the addition of a stable façade, compatibility baseline and release-readiness contracts.

Existing v0.1-v0.9 schema discriminators are preserved in the v1 JSON baseline. Existing authorization, identity, approval, MCP, execution, data-purpose, assurance, tenant/crypto and production-reference boundaries remain in force.

## Rollback

A real deployment rollback remains an accountable platform operation. The v1 `SupportedUpgradePath` binds an exact rollback-plan evidence digest, while the v0.9 `RollbackPlan`/`UpgradePlan` contracts remain the production-reference model for direction, checks and reverse-transition validation.

Rollback must not bypass current tenant isolation, egress, tool, emergency-stop, key lifecycle or other fail-closed controls merely to restore an older release.

## Unsupported sources

Direct upgrade from a pre-0.9 line is not represented as a supported v1 path. Such a deployment should first reach a final 0.9.x production-reference baseline through its own reviewed process, or define a separately reviewed migration rather than relabeling an untested path as supported.

## Non-claim

This document is a reference upgrade contract. It does not perform database migration, Kubernetes rollout, backup restoration, key rotation, network-policy application or tool invocation.
