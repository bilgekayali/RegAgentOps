# Threat Model — v0.9

## Protected assets

- authorization policy integrity and governance-evidence binding;
- authenticated human/agent/model/workload identity;
- approval authority, replay protection and execution-lease integrity;
- MCP, data-purpose and emergency-stop currentness;
- signed execution-receipt integrity;
- assurance-scope/crosswalk/package integrity;
- tenant identity, PostgreSQL RLS profile and KMS/HSM key-reference integrity;
- signed configuration-change and encrypted-evidence integrity;
- external audit-anchor chain integrity;
- production egress and tool-dispatch allowlists;
- exact current v0.8 tenant-isolation binding in the production worker;
- isolated policy-worker profile integrity;
- release source/artifact/configuration and security/provenance evidence bindings;
- rollback/upgrade transition integrity;
- recovery-checkpoint evidence; and
- separation between production-reference metadata and privileged deployment/execution capability.

## Trust boundaries

1. **Caller → identity/policy plane**: action and identity inputs are untrusted until verified.
2. **Institution governance → policy/MCP/data/approval state**: privileged configuration determines governance evidence.
3. **Authenticated authorization → external executor**: exact current authorization plus one-time lease remains execution authority.
4. **Database/KMS/HSM/external anchor → v0.8 reference artefacts**: actual enforcement/custody remains external.
5. **v0.8 tenant-isolation registry → deployment registry**: current RLS/tenant profile becomes a mandatory production-worker dependency.
6. **Network-security platform → egress policy**: the platform must translate and enforce exact tenant endpoint/trust rules.
7. **Dispatch platform → tool allowlist**: the external dispatcher must enforce exact governed-tool→executor bindings.
8. **Container/orchestrator → worker profile**: runtime isolation controls are external facts represented by the profile.
9. **GitHub security/build pipeline → release manifest**: CodeQL, artifact/checksum and provenance evidence is imported by digest.
10. **Change process → upgrade/rollback plan**: signed configuration and exact transition evidence constrain promotion.
11. **Backup/DR platform → recovery checkpoint**: backup existence, integrity and restorability remain external facts.

## Primary v0.9 threats and controls

### Wildcard, plaintext or aliased-IP egress expansion

Threat: a deployment policy permits broad domains, paths, arbitrary schemes, plaintext endpoints or multiple textual encodings of the same IP, turning the policy worker into an uncontrolled network pivot or bypassing endpoint uniqueness.

Controls: `EgressPolicy` is structurally default deny, `allow_wildcards=false`, `allow_plaintext=false`, and accepts only governed `https`/`tls` protocol values. Hosts must be canonical exact lowercase hostname/IP values with no wildcard, URL path or scheme. IP values must equal the canonical textual representation produced by the IP parser. Each exact protocol/host/port endpoint can appear only once and carries a trust-policy digest.

Residual boundary: RegAgentOps does not resolve DNS, pin live addresses/certificates or install firewall/CNI/mesh rules. External enforcement can still be misconfigured.

### Cross-tenant egress or tenant-isolation substitution

Threat: a worker for tenant A binds egress policy or v0.8 tenant-isolation evidence belonging to tenant B, or simply supplies a syntactically valid but unknown tenant-isolation digest.

Controls: `ProductionDeploymentRegistry.register_worker_profile()` resolves egress/tool state only within the same institution+tenant and receives the actual v0.8 `TenantIsolationRegistry`. It resolves the current tenant profile and requires the worker's `tenant_isolation_profile_digest` to equal that exact artifact digest. Unknown, cross-tenant or superseded profile evidence fails closed.

### Tool allowlist ambiguity

Threat: one governed tool maps to multiple executors or an empty/default rule silently becomes allow-by-default.

Controls: `ToolAllowlistPolicy` requires `default_deny=true` and `direct_tool_invocation_allowed=false`. A governed tool ID may appear once per policy version and therefore binds to one exact executor plus one exact governance-binding digest.

### Policy-worker privilege escalation

Threat: the policy worker gains host namespaces, root/privileged mode, writable root filesystem, Linux capabilities or direct tool credentials and becomes an execution pivot.

Controls: `IsolatedPolicyWorkerProfile` requires network namespace isolation, non-root, read-only root filesystem, no-new-privileges, all capabilities dropped and `RuntimeDefault` seccomp while requiring privileged/host-network/host-PID/host-IPC/direct-tool-invocation flags to be false. JSON Schema pins the same values.

Residual boundary: the core does not inspect a live container. Orchestrator admission controls and runtime monitoring must prove/enforce the profile.

### Stale policy or RLS worker registration

Threat: a newly registered worker profile intentionally binds superseded egress, tool or tenant-isolation state.

Controls: worker registration resolves exact current egress/tool policies and current v0.8 tenant-isolation profile. The worker timestamp must be at or after all three dependencies. Egress/tool/worker histories are append-only and v0.8 tenant isolation remains append-only/versioned.

### Backdated worker or release evidence

Threat: a worker or release claims to have existed before the policies/profile it depends on, creating misleading historical evidence.

Controls: worker `registered_at` cannot predate bound current egress, tool or tenant-isolation profile time. Release `created_at` cannot predate its worker profile. Rollback, upgrade and recovery chronology is also dependency checked.

Residual boundary: these are application timestamps, not an independent timestamp authority.

### Release evidence substitution

Threat: a release manifest points to one source commit while binding a different artifact, worker, configuration, CodeQL result, provenance record or checksum set.

Controls: `DeploymentReleaseManifest` digest-binds strict source Git SHA, semantic release version, artifact SHA-256, worker/configuration digest and exact CodeQL/provenance/checksum evidence digests. Release identities are immutable and versions increase monotonically per tenant.

Residual boundary: the offline core does not independently fetch GitHub/Sigstore evidence or decide whether CodeQL alert state satisfies institutional acceptance policy.

### Stale release deployment after policy or tenant drift

Threat: a previously valid release is redeployed after egress/tool policy, worker hardening or v0.8 tenant-isolation/RLS state has changed.

Control: `assert_release_current()` resolves the exact registered release and requires the same current worker profile, egress policy, tool allowlist and tenant-isolation profile. Any superseded dependency fails closed.

### Version rollback disguised as upgrade

Threat: an `UpgradePlan` points to an older or equal release while being represented as forward promotion.

Control: registered upgrade target semantic version must be strictly greater than the from-release version.

### Fake rollback path

Threat: an upgrade package references a rollback plan that does not actually reverse the proposed transition.

Control: the rollback source must equal the upgrade target and rollback target must equal the upgrade source. `register_upgrade()` rejects any other relationship.

### Unsafe rollback target

Threat: a rollback points laterally/forward or to an unregistered release.

Controls: both releases must resolve in the same institution+tenant and the rollback target version must be strictly older. Trigger-condition digests, verification-procedure digest and bounded rollback window are mandatory.

### Recovery checkpoint substitution

Threat: a checkpoint claims one release/configuration but points to an unrelated backup, anchor or restore verification.

Control: checkpoint digest binds exact tenant release, configuration, encrypted-backup, external-audit-anchor and restore-verification digests. Registration resolves the release in the same tenant and rejects a checkpoint timestamp that predates it.

Residual boundary: a digest does not prove the backup exists or restores successfully. DR requires independent restore testing.

### Supply-chain provenance overclaim

Threat: the existence of CodeQL or artifact attestation is represented as proof the release is secure.

Controls: release evidence fields are documented as evidence bindings rather than safety verdicts. CI separates CodeQL analysis, release provenance and functional boundary tests. Tag-scoped provenance does not substitute for security review.

Residual boundary: institutions must define acceptable CodeQL alert thresholds, provenance verification policy and release approval.

### Test-build attestation noise

Threat: frequent PR/test builds are attested and later confused with actual release provenance.

Control: `Release Provenance Gate` builds/checks the release contract on PRs, but the actual `actions/attest@v4` job is restricted to `v*` tags and requires the tag to exactly match `pyproject.toml` version.

### Deployment metadata becomes execution authority

Threat: a valid release/worker/rollback/checkpoint artefact is treated as permission to execute an agent action.

Control: v0.9 deployment types are not inputs to authorization, approval or execution-lease policy effects. `deployment.py` has no network, deployment or tool-invocation interface.

## Earlier threats retained

v0.8 PostgreSQL RLS, tenant substitution, KMS/HSM custody, key lifecycle, configuration-chain, AES-GCM and audit-anchor controls remain active. v0.2-v0.7 authenticated identity, approval separation/replay, MCP governance, data-purpose control, execution freshness/one-time leases, emergency stop, signed receipt and human-reviewed assurance controls remain active.

## Capability creep

Threat: the production-reference module quietly becomes a Kubernetes/cloud/database/network client or a direct tool executor.

Controls: generic CI and the dedicated Production Reference Deployment Boundary parse `deployment.py` and reject network/process imports plus deployment/connection/tool-invocation markers. The module only creates/validates deterministic metadata and consumes the existing in-memory v0.8 tenant-isolation registry.

## CI/supply-chain configuration risk

CodeQL and GitHub Actions workflows are themselves privileged build configuration. A malicious workflow change could weaken queries, attest an unintended artifact or broaden permissions.

Controls: workflow files are version controlled, covered by the dedicated production-reference gate, and checked for CodeQL v4/security-extended, tag-only attestation, required OIDC/attestation permissions and checksum generation. Branch protection/review policy is still required outside this codebase.

## Residual risks

Actual worker isolation depends on orchestrator/runtime configuration, admission policy, kernel/container security and monitoring. The worker profile is evidence, not remote attestation.

Actual RLS and egress enforcement depends on PostgreSQL roles/session context plus firewall/CNI/service-mesh/proxy and DNS/TLS trust controls. A privileged platform/database operator may still bypass external controls.

Actual tool dispatch depends on executor IAM/credentials and the external dispatcher honoring the allowlist and v0.5 one-time lease boundary.

CodeQL can miss vulnerabilities; provenance can faithfully attest a malicious or vulnerable build. Neither is a substitute for secure development, review, dependency governance or runtime defense.

Backups, replicas, restore tooling, RTO/RPO, regional failover and production state reconciliation remain external operational controls.

In-memory deployment/hardening registries and local SQLite approval/execution ledgers remain reference state, not a distributed highly available production datastore.

## Explicit non-claims

v0.9 does not provide or claim:

- Kubernetes/VM/container deployment or admission enforcement;
- live firewall/CNI/service-mesh/proxy configuration;
- DNS/TLS endpoint verification by the offline core;
- production executor credential management or direct tool invocation;
- proof that worker isolation flags or PostgreSQL RLS are active in a live runtime;
- CodeQL zero-vulnerability assurance or automatic alert-acceptance policy;
- in-core GitHub/Sigstore attestation verification;
- proof that a backup is restorable or that RTO/RPO was achieved;
- KMS/HSM hardware custody proof;
- compliance, certification, regulatory approval, supervisory acceptance; or
- production fitness.
