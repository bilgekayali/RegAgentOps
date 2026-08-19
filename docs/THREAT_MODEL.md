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
5. **Network-security platform → egress policy**: the platform must translate and enforce exact tenant endpoint/trust rules.
6. **Dispatch platform → tool allowlist**: the external dispatcher must enforce exact governed-tool→executor bindings.
7. **Container/orchestrator → worker profile**: runtime isolation controls are external facts represented by the profile.
8. **GitHub security/build pipeline → release manifest**: CodeQL, artifact/checksum and provenance evidence is imported by digest.
9. **Change process → upgrade/rollback plan**: signed configuration and exact transition evidence constrain promotion.
10. **Backup/DR platform → recovery checkpoint**: backup existence, integrity and restorability remain external facts.

## Primary v0.9 threats and controls

### Wildcard or plaintext egress expansion

Threat: a deployment policy permits broad domains, paths, arbitrary schemes or plaintext endpoints, turning the policy worker into an uncontrolled network pivot.

Controls: `EgressPolicy` is structurally default deny, `allow_wildcards=false`, `allow_plaintext=false`, and accepts only governed `https`/`tls` protocol values. Hosts must be canonical exact lowercase hostname/IP values with no wildcard, URL path or scheme. Each exact protocol/host/port endpoint can appear only once and carries a trust-policy digest.

Residual boundary: RegAgentOps does not resolve DNS, pin live addresses/certificates or install firewall/CNI/mesh rules. External enforcement can still be misconfigured.

### Cross-tenant egress policy substitution

Threat: a worker for tenant A binds an egress policy from tenant B.

Control: `ProductionDeploymentRegistry.register_worker_profile()` resolves the egress-policy digest only within the same institution+tenant. Cross-tenant lookup fails closed.

### Tool allowlist ambiguity

Threat: one governed tool maps to multiple executors or an empty/default rule silently becomes allow-by-default.

Controls: `ToolAllowlistPolicy` requires `default_deny=true` and `direct_tool_invocation_allowed=false`. A governed tool ID may appear once per policy version and therefore binds to one exact executor plus one exact governance-binding digest.

### Policy-worker privilege escalation

Threat: the policy worker gains host namespaces, root/privileged mode, writable root filesystem, Linux capabilities or direct tool credentials and becomes an execution pivot.

Controls: `IsolatedPolicyWorkerProfile` requires network namespace isolation, non-root, read-only root filesystem, no-new-privileges, all capabilities dropped and `RuntimeDefault` seccomp while requiring privileged/host-network/host-PID/host-IPC/direct-tool-invocation flags to be false. JSON Schema pins the same values.

Residual boundary: the core does not inspect a live container. Orchestrator admission controls and runtime monitoring must prove/enforce the profile.

### Stale policy worker registration

Threat: a newly registered worker profile intentionally binds superseded egress or tool policy evidence.

Control: worker registration resolves exact policy digests and requires both to be current at registration time. Egress/tool/worker versions are append-only and contiguous.

### Release evidence substitution

Threat: a release manifest points to one source commit while binding a different artifact, worker, configuration, CodeQL result, provenance record or checksum set.

Controls: `DeploymentReleaseManifest` digest-binds every field: strict source Git SHA, semantic release version, artifact SHA-256, worker/configuration digest and exact CodeQL/provenance/checksum evidence digests. Release identities are immutable and versions increase monotonically per tenant.

Residual boundary: the offline core does not independently fetch GitHub/Sigstore evidence or decide whether CodeQL alert state satisfies institutional acceptance policy.

### Stale release deployment after policy drift

Threat: a previously valid release is redeployed after egress/tool policy or worker hardening has changed.

Control: `assert_release_current()` resolves the exact registered release, worker profile and current egress/tool policy. Superseded worker, egress or tool state fails closed.

### Version rollback disguised as upgrade

Threat: an `UpgradePlan` points to an older or equal release while being represented as forward promotion.

Control: registered upgrade target semantic version must be strictly greater than the from-release version.

### Fake rollback path

Threat: an upgrade package references a rollback plan that does not actually reverse the proposed transition.

Control: the rollback source must equal the upgrade target and rollback target must equal the upgrade source. `register_upgrade()` rejects any other relationship.

### Unsafe rollback target

Threat: a rollback points laterally/forward or to an unregistered release.

Controls: both releases must resolve in the same institution+tenant and the rollback target version must be strictly older. Trigger-condition digests, verification-procedure digest and bounded rollback window are mandatory.

### Backdated change planning

Threat: rollback, upgrade or recovery evidence claims to predate the release/change evidence it depends on.

Controls: rollback cannot predate either referenced release; upgrade cannot predate its target release or rollback plan; recovery checkpoint cannot predate its release.

Residual boundary: application timestamps are not an independent trusted timestamp authority; infrastructure/SIEM/external anchor timestamps remain important evidence.

### Recovery checkpoint substitution

Threat: a checkpoint claims one release/configuration but points to an unrelated backup, anchor or restore verification.

Control: checkpoint digest binds exact tenant release, configuration, encrypted-backup, external-audit-anchor and restore-verification digests. Registration resolves the release in the same tenant.

Residual boundary: a digest does not prove the backup exists or restores successfully. DR requires independent restore testing.

### Supply-chain provenance overclaim

Threat: the existence of CodeQL or artifact attestation is represented as proof the release is secure.

Controls: release evidence fields are named and documented as evidence bindings rather than safety verdicts. CI separates CodeQL analysis, release provenance and functional boundary tests. Tag-scoped provenance does not run as a substitute for security review on every PR.

Residual boundary: institutions must define acceptable CodeQL alert thresholds, provenance verification policy and release approval.

### Test-build attestation noise

Threat: frequent PR/test builds are attested and later confused with actual release provenance.

Control: `Release Provenance Gate` builds/checks the release contract on PRs, but the actual `actions/attest@v4` job is restricted to `v*` tags and requires the tag to exactly match `pyproject.toml` version.

### Deployment metadata becomes execution authority

Threat: a valid release/worker/rollback/checkpoint artefact is treated as permission to execute an agent action.

Control: v0.9 deployment types are not inputs to the authorization, approval or execution-lease policy effects. The production-reference registry has no network, deploy or tool-invocation interface.

## v0.8 threats retained

PostgreSQL RLS injection/partial-policy, cross-tenant RLS substitution, KMS/HSM custody laundering, cross-tenant key substitution, key-rotation ambiguity, configuration-chain fork/stale overwrite, AES-GCM AAD/ciphertext substitution and external-anchor fork/backdating controls remain active.

## v0.2-v0.7 threats retained

Authenticated identity/key-confusion defenses; requester/approver separation and replay control; bounded explicit MCP governance; exact data-purpose classification/purpose/output/retention controls; authorization freshness; executor-bound one-time leases; emergency-stop currentness; signed receipt integrity; and human-reviewed assurance non-certification semantics remain active.

## Capability creep

Threat: the production-reference module quietly becomes a Kubernetes/cloud/database/network client or a direct tool executor.

Controls: generic CI and the dedicated Production Reference Deployment Boundary parse `deployment.py` and reject network/process imports plus deployment/connection/tool-invocation markers. The module only creates/validates deterministic metadata.

## CI/supply-chain configuration risk

CodeQL and GitHub Actions workflows are themselves privileged build configuration. A malicious workflow change could weaken queries, attest an unintended artifact or broaden permissions.

Controls: workflow files are version controlled, covered by the dedicated production-reference gate, and checked for CodeQL v4/security-extended, tag-only attestation, required OIDC/attestation permissions and checksum generation. Branch protection/review policy is still required outside this codebase.

## Residual risks

Actual worker isolation depends on orchestrator/runtime configuration, admission policy, kernel/container security and monitoring. The worker profile is evidence, not remote attestation.

Actual egress enforcement depends on firewall/CNI/service-mesh/proxy and DNS/TLS trust controls. The reference cannot prevent a privileged platform operator from bypassing external network policy.

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
- proof that worker isolation flags are active in a live runtime;
- CodeQL zero-vulnerability assurance;
- automatic CodeQL alert acceptance policy;
- in-core GitHub/Sigstore attestation verification;
- proof that a backup is restorable or that RTO/RPO was achieved;
- deployed PostgreSQL RLS non-bypassability or KMS/HSM hardware custody proof;
- compliance, certification, regulatory approval, supervisory acceptance; or
- production fitness.
