# Tenant and Cryptographic Hardening

RegAgentOps v0.8 adds a tenant-isolation and cryptographic-hardening reference boundary over the governance, execution and assurance artifacts produced by earlier milestones.

The boundary remains deliberately adapter-oriented. It defines exact artifacts, cryptographic bindings and fail-closed invariants that a production deployment can enforce with PostgreSQL, an institution-controlled KMS/HSM and an external immutable audit service. The core itself does not connect to any of those systems.

## PostgreSQL RLS reference boundary

`PostgresRlsPolicy` represents one immutable version of a PostgreSQL row-level-security policy. Identifiers are restricted to safe lowercase PostgreSQL identifiers, and session-setting names must remain in the `regagentops.*` namespace.

The renderer always emits all four required elements:

- `ENABLE ROW LEVEL SECURITY`;
- `FORCE ROW LEVEL SECURITY`;
- a `USING` predicate binding both institution and tenant session settings; and
- the same exact predicate in `WITH CHECK` so writes cannot cross the tenant boundary.

`TenantIsolationProfile` binds one institution/tenant/environment/database-role tuple to exact RLS policy digests. Policy and profile histories are append-only and contiguously versioned.

This is reference DDL, not a database migration engine. v0.8 does not prove that a target PostgreSQL cluster installed the rendered policy, that application roles cannot bypass it, or that database superuser privileges are correctly controlled.

## Institution-owned KMS/HSM key references

`InstitutionCryptoKeyReference` stores only governance metadata and, for Ed25519 signing keys, the public verification key. The key reference is tenant scoped and purpose scoped.

Supported purposes are:

- `config_signing` using Ed25519; and
- `evidence_encryption` using AES-256-GCM.

Custody is restricted to `kms` or `hsm`. Symmetric key bytes and private signing key bytes are never represented in RegAgentOps artifacts.

Key references are append-only and contiguously versioned per institution, tenant and purpose. Rotation requires a distinct `key_id`. New cryptographic operations require an `ACTIVE` key. Historical signature verification and evidence decryption may use a key that has become `RETIRED`, provided it was valid when the original artifact was produced. `DISABLED` keys fail closed.

A KMS/HSM adapter is responsible for real private/symmetric-key custody, authorization, audit logging, key-generation quality, hardware protection and compromise response.

## Signed configuration change control

`ConfigurationChangeRequest` binds the exact tenant, object identity, previous configuration digest, proposed digest, reason digest, requester identity, sequence and requested/effective times.

`SignedConfigurationChange` uses domain-separated Ed25519 signing with purpose:

`regagentops.configuration-change.v1`

The signing document additionally binds the exact KMS/HSM key-reference digest and the previous signed-change digest. `ConfigurationChangeRegistry` verifies the signature before append, enforces one contiguous tenant change chain, rejects chain forks, rejects stale object-state overwrites and prevents chronology from moving backwards.

The signing interface is a protocol. A production adapter may call an HSM or KMS signing API, while the RegAgentOps core remains offline and never receives the private signing key.

## Tenant-scoped encrypted governance evidence

`EncryptedGovernanceEvidence` wraps exact governance evidence bytes under AES-256-GCM using an institution/tenant-scoped encryption-key reference. The encryption/decryption interfaces are adapter protocols; key bytes remain external to RegAgentOps artifacts.

Authenticated additional data is domain separated with purpose:

`regagentops.tenant-encrypted-governance-evidence.v1`

AAD binds:

- envelope id;
- institution id;
- tenant id;
- exact encryption-key-reference digest; and
- exact subject-artifact digest.

The envelope also records the SHA-256 digest of plaintext bytes and the AAD digest. Cross-tenant providers, wrong key versions, modified AAD and modified plaintext/ciphertext therefore fail the reference verification path.

AES-GCM nonce generation defaults to a fresh 96-bit random nonce. Callers may supply a nonce only for deterministic testing; production adapters remain responsible for ensuring nonce uniqueness for a given key.

## External immutable audit anchoring

`AuditAnchorBatch` groups exact evidence-artifact digests into a tenant-scoped, monotonically sequenced hash chain. Every batch after the first binds the exact previous `AuditAnchorRecord` digest.

An external service returns evidence represented by `ExternalAuditAnchorReceipt`, which binds the exact batch digest, external provider id, external anchor id, opaque provider-receipt digest and anchor time.

`AuditAnchorRegistry` accepts a record only when:

- tenant/institution scope matches;
- the receipt binds the exact batch digest;
- sequence and previous-record digest extend the exact local chain; and
- assembly → external anchoring → local recording chronology is monotonic.

The provider receipt is deliberately opaque. RegAgentOps does not claim that its digest alone proves a provider is truly immutable, independently timestamped or regulator-approved. A production deployment must choose and validate the external anchoring service.

## Capability boundary

The v0.8 module contains no PostgreSQL driver, cloud SDK, KMS/HSM network client, external-log client or tool-execution interface. Generic and dedicated CI reject network/process capability imports and known database/cloud-client markers.

Production database sessions, RLS deployment, KMS/HSM calls, external immutable storage, secrets authorization and operational monitoring remain integration responsibilities and are completed as part of the v0.9 production-reference deployment boundary.

## Explicit non-claims

v0.8 does not independently prove:

- deployed PostgreSQL RLS correctness or non-bypassability;
- actual KMS/HSM hardware custody or provider attestation;
- secure administrative access to KMS/HSM or PostgreSQL;
- nonce uniqueness across every external encryption caller;
- external anchor immutability, independent timestamp accuracy or legal evidentiary sufficiency;
- database backup encryption or tenant isolation in backups/replicas;
- production secrets rotation or incident response execution;
- regulatory compliance, certification, supervisory acceptance or production fitness.
