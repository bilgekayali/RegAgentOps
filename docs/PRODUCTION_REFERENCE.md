# Production Reference Deployment

RegAgentOps v0.9 defines a production-reference deployment boundary without turning the governance core into a deployment orchestrator, network client or tool executor. It describes exact deployment artefacts that a production integration must bind and enforce around the v0.1-v0.8 control plane.

## Boundary

The v0.9 core remains deterministic and offline. `deployment.py` creates and validates metadata for:

- exact default-deny TLS/HTTPS egress allowlists;
- exact governed-tool to external-executor allowlists;
- isolated policy-enforcement worker profiles bound to the **current v0.8 tenant-isolation profile**;
- release manifests bound to source commit, artifact hash, configuration, CodeQL evidence, provenance-attestation evidence and checksum evidence;
- exact rollback and upgrade plans; and
- recovery checkpoints bound to encrypted backup, external audit anchor and restore-verification evidence.

The module does not open sockets, create Kubernetes resources, start containers, install firewall rules, invoke tools or mutate production infrastructure.

## Isolated policy worker

`IsolatedPolicyWorkerProfile` is deliberately restrictive. A valid profile requires:

- isolated network namespace;
- non-root execution;
- read-only root filesystem;
- no-new-privileges semantics;
- all Linux capabilities dropped;
- `RuntimeDefault` seccomp;
- no privileged mode;
- no host network, PID or IPC namespace;
- no direct tool invocation; and
- exact current tenant-scoped egress, tool-allowlist and v0.8 tenant-isolation evidence.

`ProductionDeploymentRegistry` receives the actual v0.8 `TenantIsolationRegistry` as a dependency. Worker registration resolves the exact current tenant profile rather than accepting an unverified digest string. A cross-tenant, unknown or superseded tenant-isolation profile fails closed.

Worker chronology is also constrained: `registered_at` cannot predate the bound egress policy, tool allowlist or tenant-isolation profile. These fields are deployment requirements, not proof that a particular runtime has applied them.

## Strict egress

`EgressPolicy` is tenant-scoped, append-only and versioned. It is always default deny, forbids wildcard destinations and forbids plaintext transport. Every allowed destination is an exact `https` or generic `tls` host/port pair with a human/institution-defined purpose and a `trust_policy_digest` for the external DNS/TLS identity policy.

Hostname values must use a bounded canonical lowercase form. IP addresses must use the canonical textual representation returned by the IP parser; alternate textual forms of the same IP are rejected so exact endpoint uniqueness cannot be bypassed through address aliases.

RegAgentOps does not resolve DNS or open a connection. Production enforcement belongs to the selected CNI, service mesh, firewall, proxy or equivalent platform control. Wildcard/FQDN expansion or DNS trust cannot be introduced by the RegAgentOps core.

## Tool dispatch allowlist

`ToolAllowlistPolicy` is also default deny. One governed tool ID can bind to one exact executor in a policy version, together with the exact governance-binding digest from the earlier MCP/execution control plane. The policy worker itself remains non-invoking; the external executor boundary introduced in v0.5 remains responsible for actual dispatch.

## Release manifest and supply-chain evidence

`DeploymentReleaseManifest` binds one tenant release to:

- strict semantic version;
- exact 40-character source Git commit SHA;
- exact release artifact name and SHA-256;
- exact policy-worker profile;
- exact production configuration digest;
- CodeQL evidence digest;
- build-provenance attestation digest; and
- checksum-manifest digest.

A release cannot claim to predate its worker profile. Release versions are immutable and increase monotonically for the tenant.

The digests are evidence bindings. RegAgentOps does not itself fetch or validate GitHub code-scanning alerts or Sigstore/GitHub attestation bundles.

The repository adds two separate GitHub Actions controls:

1. `CodeQL` performs Python CodeQL advanced analysis with the `security-extended` query suite.
2. `Release Provenance Gate` builds and checks the wheel/checksum contract on pull requests. For a `v*` tag whose version exactly matches `pyproject.toml`, it rebuilds the wheel and uses GitHub artifact attestations for the release wheel and checksum manifest.

Artifact provenance does not prove that software is vulnerability-free or production-safe; it establishes cryptographic build provenance that consumers can verify under their own acceptance policy.

Primary GitHub references used by this milestone:

- https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations
- https://docs.github.com/en/actions/concepts/security/artifact-attestations

## Drift and currentness

A release may remain historical evidence, but `ProductionDeploymentRegistry.assert_release_current()` rejects it for current deployment use when any of these dependencies has been superseded:

- worker profile;
- egress policy;
- tool allowlist; or
- v0.8 tenant-isolation profile.

A policy or RLS/tenant-isolation change therefore requires a new worker/release binding instead of silently reusing a stale release manifest. The function does not deploy or undeploy anything; it is a fail-closed precondition for a surrounding production controller.

## Upgrade and rollback

A `RollbackPlan` must point from a newer registered tenant release to an older registered release, bind exact trigger-condition digests and an exact verification procedure, and set a bounded rollback window.

An `UpgradePlan` binds exact from/to releases, migration/preflight/post-deploy evidence, a signed v0.8 configuration-change digest and an exact rollback-plan digest. Registration succeeds only when that rollback plan exactly reverses the proposed upgrade transition.

This prevents an upgrade package from claiming a rollback path that actually points somewhere else.

## Recovery checkpoint

`RecoveryCheckpoint` binds the exact release and configuration to:

- encrypted backup evidence;
- an external audit-anchor record; and
- a restore-verification procedure/result digest.

The checkpoint must not predate its release. It does not prove that a backup is restorable; the disaster-recovery runbook requires an isolated restore test and new verification evidence.

## Chronological provenance

v0.9 prevents downstream deployment artefacts from claiming to exist before their dependencies. In addition to version-history monotonicity:

- worker profile time must be at or after current egress/tool/tenant-isolation policy times;
- release time must be at or after the bound worker profile;
- rollback time must be at or after both referenced releases;
- upgrade time must be at or after its target release and rollback plan; and
- recovery checkpoint time must be at or after its release.

These are application evidence timestamps, not an independent trusted timestamp authority.

## Operational runbooks

v0.9 includes reference runbooks under `docs/runbooks/` for:

- deployment;
- incident response;
- KMS/HSM key rotation; and
- disaster recovery.

They are control checklists for an accountable operator. They do not automate privileged operations.

## Explicit non-claims

v0.9 does not by itself:

- provision or configure Kubernetes, VMs, containers, databases, KMS/HSMs, firewalls, proxies or service meshes;
- prove that runtime isolation flags or PostgreSQL RLS were applied;
- verify CodeQL has zero alerts or define an institution's alert-severity acceptance threshold;
- verify a GitHub/Sigstore attestation bundle inside the offline core;
- guarantee DNS resolution, TLS certificate validation or egress enforcement performed by an external platform;
- execute upgrade, rollback, restore or key-rotation operations;
- prove backup restorability, RTO/RPO attainment or external audit-log immutability;
- replace production IAM, secrets management, change approval, incident response or DR governance; or
- claim compliance, certification, supervisory acceptance or production fitness.
