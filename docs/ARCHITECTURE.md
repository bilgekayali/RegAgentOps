# RegAgentOps Architecture

## v0.9 boundary

RegAgentOps v0.9 is an **offline authorization, approval, MCP-governance, execution-evidence, data/purpose, assurance, tenant/cryptographic-hardening and production-reference control plane**.

The v0.9 deployment layer remains non-deploying. It defines exact worker-isolation, egress/tool-allowlist, release, rollback, upgrade and recovery artefacts plus CI/supply-chain gates. It does not open sockets, deploy workloads, install firewall/RLS rules or invoke tools.

```text
                    EXECUTION CONTROL PLANE

OIDC + pinned trust             Institution workload signer
        \                               /
         +---- Signed authenticated agent ----+
                          |
AgentActionEnvelope ------+------ PolicyBundle
        |                 |
        |        current governed MCP binding
        |                 |
        +------ DataUseDeclaration
                          |
                  DataResourceProfile
                          |
                          v
                 DataGovernanceDecision
                          |
               governance evidence digest
                          v
               AuthenticatedAuthorizationDecision
                          |
                    MCP policy result
                          |
                  if approval required
                          v
                     ApprovalGate
                          |
                          v
                  ApprovalResolution
                          |
      current MCP + data profile + emergency stop
                          |
                          v
                 one-time ExecutionLease
                          |
                  atomic consumption
                          |
                          v
                  external executor
                          |
                          v
             SignedToolExecutionReceipt

                    ASSURANCE / HARDENING

existing signed evidence --> human assurance crosswalk/package

PostgresRlsPolicy --> TenantIsolationProfile
InstitutionCryptoKeyReference --> signed config / AES-GCM evidence
                                        |
                                external audit anchor

                    PRODUCTION REFERENCE

EgressPolicy --------+
                     |
ToolAllowlistPolicy --+--> IsolatedPolicyWorkerProfile
                              |
                              v
                   DeploymentReleaseManifest
               source SHA + artifact SHA-256
               worker/configuration digest
               CodeQL/provenance/checksum evidence
                              |
                    +---------+---------+
                    |                   |
                    v                   v
                UpgradePlan <----> RollbackPlan
                    |
                    v
             RecoveryCheckpoint
```

## Production worker isolation

`IsolatedPolicyWorkerProfile` represents the minimum isolation posture expected from an external runtime adapter. A valid profile requires:

- isolated network namespace;
- non-root execution;
- read-only root filesystem;
- no-new-privileges;
- all Linux capabilities dropped;
- `RuntimeDefault` seccomp;
- no privileged mode;
- no host network/PID/IPC namespaces; and
- no direct tool invocation.

The profile binds exact tenant-scoped egress/tool policy digests plus the v0.8 tenant-isolation profile digest and an exact worker-image SHA-256.

These fields are declarative reference requirements. The core does not create a container or independently attest that a container runtime enforced them.

## Egress boundary

`EgressPolicy` is append-only/versioned per institution+tenant. It is structurally default deny, forbids wildcard destinations and plaintext transport, and permits only exact `https` or generic `tls` endpoint tuples.

Each `EgressDestination` binds exact protocol, canonical host, port, purpose and external `trust_policy_digest`. A host cannot contain wildcard/path/scheme material. One endpoint can appear only once in a policy.

The core does not resolve DNS, validate a live certificate or install network rules. A production CNI/firewall/proxy/service mesh must implement the policy and its trust-resolution rules.

## Tool dispatch boundary

`ToolAllowlistPolicy` is also append-only/versioned and default deny. One governed tool ID maps to at most one exact external executor per policy version, together with its existing governance-binding digest.

The policy worker itself is intentionally non-invoking. Actual dispatch remains behind the v0.5 lease/consumption/executor boundary. The v0.9 allowlist therefore narrows where an already-governed action may be dispatched; it does not create new authorization authority.

## Worker/profile currentness

`ProductionDeploymentRegistry.register_worker_profile()` resolves the exact egress/tool policies in the same tenant and requires them to be current at registration.

Policies and worker profiles are immutable and contiguously versioned. If egress or tool policy changes, an old worker profile remains historical evidence but is stale for current release use.

## Release manifest

`DeploymentReleaseManifest` binds one tenant release to:

- strict `MAJOR.MINOR.PATCH` version;
- exact 40-character source Git commit SHA;
- safe artifact name and SHA-256;
- exact worker-profile and production-configuration digests;
- CodeQL evidence digest;
- provenance-attestation evidence digest; and
- checksum-manifest digest.

Release versions must increase monotonically for a tenant and each release identity is immutable.

`assert_release_current()` resolves the registered release and fails closed when the release's worker profile, egress policy or tool allowlist is no longer current. This gives a surrounding deployment controller an explicit drift precondition without RegAgentOps performing the deployment itself.

## Upgrade and rollback integrity

`RollbackPlan` references exact registered releases. The target must have an older semantic version than the source. Trigger-condition digests, verification-procedure digest and bounded rollback window are mandatory.

`UpgradePlan` references exact from/to releases, migration/preflight/post-deploy evidence, a v0.8 signed configuration-change digest and an exact rollback plan. The to-release must be newer, and the registered rollback plan must **exactly reverse** the upgrade transition.

This prevents a release package from advertising a rollback artefact whose real source/target does not match the proposed change.

## Recovery checkpoint

`RecoveryCheckpoint` binds exact tenant release/configuration to encrypted-backup evidence, external audit-anchor record and restore-verification evidence. It cannot predate the release.

A checkpoint is not proof that a backup is restorable. The DR runbook requires independent backup/hash/key/anchor checks and an isolated restore-verification process.

## Supply-chain gates

v0.9 separates three CI concerns:

1. **CI / boundary tests**: Python regression, schemas and capability separation.
2. **CodeQL**: advanced Python CodeQL analysis with `security-extended` queries.
3. **Release Provenance Gate**: PR-time release build/checksum contract, plus tag-only GitHub artifact attestation for actual version-matching release builds.

`DeploymentReleaseManifest` stores evidence digests from those external controls; the offline core does not call GitHub APIs or decide that a CodeQL result/attestation is acceptable.

## Operational runbooks

Deployment, incident-response, KMS/HSM key-rotation and disaster-recovery runbooks define accountable operational preconditions and retained evidence. They intentionally do not contain an embedded privileged automation client.

## Relationship to earlier boundaries

v0.9 does not change authorization precedence:

`DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`

v0.2 authenticated identity remains mandatory. v0.3 approval cannot override denial. v0.4 MCP governance remains explicit. v0.5 leases remain short-lived, one-time and executor-bound. v0.6 data-purpose controls remain currentness checked. v0.7 assurance remains human-reviewed/non-certifying. v0.8 tenant/crypto hardening remains append-only and adapter-oriented.

Deployment artefacts cannot create an `ALLOW`, satisfy human approval, issue a lease or bypass emergency stop.

## Trust boundaries

1. **Caller → identity/policy plane**: request and identity input is untrusted until verified.
2. **Institution governance → MCP/data/approval registries**: privileged configuration establishes policy evidence.
3. **Authenticated authorization → execution**: exact current authorization/approval/data/MCP state remains execution authority.
4. **Database/KMS/HSM/external anchor → v0.8 references**: production custody/enforcement remains external.
5. **Network/security platform → `EgressPolicy`**: external platform must enforce exact endpoint/trust rules represented by the artefact.
6. **Executor platform → `ToolAllowlistPolicy`**: external dispatcher must reject unlisted tool/executor combinations.
7. **Container/orchestrator → worker profile**: runtime must enforce the isolation flags represented by the profile.
8. **Build/security pipeline → release manifest**: source/artifact/CodeQL/provenance/checksum evidence crosses into deployment evidence by digest.
9. **Change operator → upgrade/rollback**: signed configuration and exact reverse-transition evidence constrain change planning.
10. **Backup/DR platform → recovery checkpoint**: backup existence/restorability remains an external fact represented by digest evidence.

## Historical evidence versus current deployment eligibility

Policies, profiles, releases, rollback/upgrade plans and checkpoints are immutable historical artefacts. Historical evidence is not automatically destroyed when a newer version appears.

Current deployment eligibility is stricter: release currentness requires its exact worker profile and the worker's exact egress/tool policies to still be current. Historical evidence therefore remains reviewable without allowing stale deployment controls to masquerade as current.

## Capability separation

`deployment.py` imports no networking/process/deployment SDK and contains no connection, deploy or tool-invocation interface. CI rejects those capability markers.

The actual production adapter—Kubernetes/VM/container runtime, database, CNI/firewall/proxy, KMS/HSM, executor, backup platform and external immutable log—remains outside the governed core and must be independently secured and monitored.

## Standards and platform posture

CodeQL and GitHub artifact attestations are CI/supply-chain controls used by this repository. Their presence is not a claim that software is vulnerability-free, that a release is safe, or that a particular deployment satisfies a regulatory framework. Operational and regulatory acceptance remains external.
