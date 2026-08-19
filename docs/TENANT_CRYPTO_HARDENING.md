# Tenant and Cryptographic Hardening

RegAgentOps v0.8 adds an offline tenant-isolation and cryptographic-hardening reference boundary over the governance, execution and assurance artifacts produced by earlier milestones. It defines exact artifacts and fail-closed bindings that production adapters can enforce with PostgreSQL, institution-controlled KMS/HSM services and an external immutable audit service. The core itself connects to none of those systems.

## PostgreSQL RLS reference boundary

`PostgresRlsPolicy` represents one immutable version of a PostgreSQL row-level-security policy. Identifiers are restricted to safe lowercase PostgreSQL identifiers, and session-setting names must remain in the `regagentops.*` namespace.

The renderer always emits:

- `ENABLE ROW LEVEL SECURITY`;
- `FORCE ROW LEVEL SECURITY`;
- a `USING` predicate binding both institution and tenant session settings; and
- the same exact predicate in `WITH CHECK` so writes cannot cross the reference tenant boundary.

`TenantIsolationProfile` binds one institution/tenant/environment/database-role tuple to exact RLS policy digests. Policy and profile histories are append-only and contiguously versioned.

This is reference DDL, not a database migration engine. v0.8 does not prove that a target PostgreSQL cluster installed the rendered policy, that application roles cannot bypass it, or that database superuser/BYPASSRLS privileges are correctly controlled.

## Institution-owned KMS/HSM key references and lifecycle

`InstitutionCryptoKeyReference` stores only governance metadata and, for Ed25519 signing keys, the public verification key. The key reference is institution-, tenant- and purpose-scoped. Custody is restricted to `kms` or `hsm`.

Supported purposes are:

- `config_signing` using Ed25519; and
- `evidence_encryption` using AES-256-GCM.

Symmetric key bytes and private signing key bytes are never represented in RegAgentOps artifacts.

Key references are append-only and contiguously versioned per institution, tenant and purpose. Rotation requires a distinct `key_id`.

A key reference also seeds an immutable `CryptoKeyLifecycleState` version 1 from its initial status. Later status changes are separate append-only lifecycle artifacts. Allowed transitions are deliberately one-way:

```text
ACTIVE -> RETIRED -> DISABLED
ACTIVE ------------> DISABLED
DISABLED -X-> any state
RETIRED  -X-> ACTIVE
```

Lifecycle versions are contiguous and effective times cannot move backward. This prevents immutable key metadata from hiding later retirement or compromise state.

New signing/encryption operations require the exact key to be `ACTIVE` at the represented operation time and at the caller-supplied current operation time. Historical signature verification and evidence decryption may use a key that has become `RETIRED`, provided it was active and valid when the original artifact was produced. A key whose lifecycle is `DISABLED` at verification/decryption time fails closed.

The KMS/HSM adapter remains responsible for actual private/symmetric-key custody, authorization, audit logging, key-generation quality, hardware/service protection and compromise response.

## Signed configuration change control

`ConfigurationChangeRequest` binds the exact tenant, object identity, previous configuration digest, proposed digest, reason digest, requester identity, sequence and requested/effective times.

`SignedConfigurationChange` uses domain-separated Ed25519 signing with purpose:

`regagentops.configuration-change.v1`

The signing document additionally binds the exact KMS/HSM key-reference digest and the previous signed-change digest. New signatures require an active lifecycle state and a key valid at signing time.

`ConfigurationChangeRegistry` verifies the exact signature before a new append, enforces one contiguous tenant change chain, rejects chain forks, rejects stale object-state overwrites and prevents chronology from moving backwards. **A signed change cannot become current in the registry before its own `effective_at`.** Exact retries of an already-recorded artifact are idempotent.

The signing interface is a protocol. A production adapter may call an HSM or KMS signing API while the RegAgentOps core never receives the private signing key.

## Tenant-scoped encrypted governance evidence

`EncryptedGovernanceEvidence` wraps exact governance evidence bytes under AES-256-GCM using an institution/tenant-scoped encryption-key reference. Encryption/decryption interfaces are adapter protocols; key bytes remain external to RegAgentOps artifacts.

Authenticated additional data is domain separated with purpose:

`regagentops.tenant-encrypted-governance-evidence.v1`

AAD binds:

- envelope id;
- institution id;
- tenant id;
- exact encryption-key-reference digest; and
- exact subject-artifact digest.

The envelope also records the SHA-256 digest of plaintext bytes and the AAD digest. Cross-tenant providers, wrong key versions, modified AAD and modified plaintext/ciphertext therefore fail the reference verification path.

For every new envelope, the core itself creates a fresh 96-bit nonce with `secrets.token_bytes(12)`. The public encryption path no longer accepts a caller-selected nonce; this removes an avoidable integration path to AES-GCM nonce reuse. Production adapters still remain responsible for preserving the generated nonce with the ciphertext and for not performing independent unsafe encryption outside this boundary.

Authenticated-decryption failures from an adapter are normalized to a fail-closed `ValueError`, followed by explicit plaintext-digest verification when decryption succeeds.

## External immutable audit anchoring

`AuditAnchorBatch` groups exact evidence-artifact digests into a tenant-scoped, monotonically sequenced hash chain. Every batch after the first binds the exact previous `AuditAnchorRecord` digest.

An external service returns evidence represented by `ExternalAuditAnchorReceipt`, which binds the exact batch digest, external provider id, external anchor id, opaque provider-receipt digest and anchor time.

`AuditAnchorRegistry` accepts a new record only when tenant/institution scope matches, the receipt binds the exact batch digest, sequence/previous-record digest extend the exact chain, and assembly → external anchoring → local recording chronology is monotonic. Exact retries of an already-recorded record are idempotent; conflicting reuse of the same sequence fails closed.

The provider receipt is deliberately opaque. RegAgentOps does not claim that its digest alone proves a provider is truly immutable, independently timestamped or regulator-approved. A production deployment must choose and validate the external anchoring service.

## Capability boundary

The v0.8 module contains no PostgreSQL driver, cloud SDK, KMS/HSM network client, external-log client or tool-execution interface. Generic and dedicated CI reject network/process capability imports and known database/cloud-client markers.

Production database sessions, RLS deployment, KMS/HSM calls, external immutable storage, secrets authorization, lifecycle administration and operational monitoring remain integration responsibilities and are completed as part of the v0.9 production-reference deployment boundary.

## Explicit non-claims

v0.8 does not independently prove:

- deployed PostgreSQL RLS correctness or non-bypassability;
- actual KMS/HSM hardware custody or provider attestation;
- secure administrative access to KMS/HSM or PostgreSQL;
- that all external encryption callers use this core-controlled nonce path;
- external anchor immutability, independent timestamp accuracy or legal evidentiary sufficiency;
- database backup encryption or tenant isolation in backups/replicas;
- production secrets rotation or incident-response execution;
- regulatory compliance, certification, supervisory acceptance or production fitness.
