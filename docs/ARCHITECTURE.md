# RegAgentOps Architecture

## v0.8 boundary

RegAgentOps v0.8 is an **offline authenticated authorization, data/purpose governance, human-approval, MCP-governance, signed execution-evidence, human-reviewed assurance-evidence, tenant-isolation and cryptographic-hardening control plane**.

The v0.8 hardening layer is adapter-oriented. It defines exact PostgreSQL RLS, KMS/HSM key-reference, signed configuration-change, encrypted-evidence and external-anchor artifacts without opening database, cloud, network or production-execution capability inside the core.

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

                    ASSURANCE EVIDENCE PLANE

Signed/governed artifacts --> AssuranceEvidenceReference
                                  |
                         human applicability/mapping
                                  |
                                  v
                       AssuranceEvidencePackage

                    HARDENING REFERENCE PLANE

PostgresRlsPolicy ----> TenantIsolationProfile
        |
        +---- safe reference DDL: ENABLE + FORCE RLS
              exact institution+tenant USING/WITH CHECK

InstitutionCryptoKeyReference (KMS/HSM only)
        |                         |
        | Ed25519                 | AES-256-GCM
        v                         v
SignedConfigurationChange   EncryptedGovernanceEvidence
        |                         |
        +------ exact tenant -----+
                  bindings
                         |
                         v
                  AuditAnchorBatch
                         |
            external immutable service
                         |
                         v
             ExternalAuditAnchorReceipt
                         |
                         v
                 AuditAnchorRecord
```

## PostgreSQL RLS reference boundary

`PostgresRlsPolicy` is immutable/versioned policy metadata. Table, policy and column names must match a bounded lowercase PostgreSQL identifier grammar, preventing the reference renderer from accepting arbitrary SQL fragments. Session settings are restricted to the `regagentops.*` namespace.

`render_postgres_rls_sql()` always emits `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and the same exact institution+tenant predicate in both `USING` and `WITH CHECK`. The reference therefore covers row visibility and attempted writes.

`TenantIsolationProfile` is institution/tenant/environment scoped and binds a database role to exact RLS-policy digests. `TenantIsolationRegistry` keeps policy/profile versions append-only and contiguous and exposes a digest snapshot for integration evidence.

The core does not apply SQL. A production adapter must set transaction/session context safely and prove the expected role/policies exist in the target PostgreSQL deployment.

## Institution-owned KMS/HSM key-reference boundary

`InstitutionCryptoKeyReference` is scoped by institution, tenant, purpose and key version. Custody is restricted to `kms` or `hsm`.

Two v0.8 key purposes are recognized:

- configuration signing: Ed25519, with only the public verification key represented;
- governance-evidence encryption: AES-256-GCM, with no symmetric key bytes represented.

`InstitutionCryptoKeyRegistry` is append-only per institution/tenant/purpose. Versions are contiguous and rotation requires distinct key IDs. `ACTIVE` keys may create new cryptographic artifacts. Historical verification/decryption accepts keys that are still `ACTIVE` or have become `RETIRED`, provided they were valid at artifact creation. `DISABLED` fails closed.

The registry does not prove hardware custody. The external adapter remains responsible for actual KMS/HSM authorization, generation, key policy, audit, rotation and compromise response.

## Signed configuration change control

`ConfigurationChangeRequest` binds exact tenant, sequence, object identity, previous/proposed configuration digests, reason digest, requester and chronology.

`SignedConfigurationChange` uses a domain-separated signing document with purpose `regagentops.configuration-change.v1`. The signature binds:

- exact request digest;
- exact previous signed-change digest;
- exact institution/tenant;
- exact KMS/HSM key-reference digest;
- key id/version and Ed25519 algorithm; and
- signing time.

`ConfigurationChangeRegistry.append()` verifies the signature internally before storing the artifact. It then enforces one contiguous tenant-wide chain, exact previous-change linkage, non-decreasing chronology, and exact prior object state for previously changed objects. A stale configuration writer therefore cannot silently overwrite a newer represented object state.

The signer is a protocol. Production signing can be performed behind KMS/HSM adapters without exposing the private key to RegAgentOps.

## Tenant-scoped encrypted governance evidence

`EncryptedGovernanceEvidence` is an AES-256-GCM envelope around governance evidence bytes. The encryption/decryption providers are protocols whose institution, tenant, key id/version and algorithm must match the exact registered encryption-key reference.

AAD is domain separated with purpose `regagentops.tenant-encrypted-governance-evidence.v1` and binds envelope id, institution, tenant, exact key-reference digest and subject-artifact digest. The envelope also records raw plaintext SHA-256 and AAD SHA-256 digests.

New encryption requires an `ACTIVE` key valid at `encrypted_at`. Historical decryption can use an `ACTIVE` or `RETIRED` key that was valid at encryption time; `DISABLED` keys fail closed. The default nonce is a fresh 96-bit random value, while deterministic nonce injection exists only to support controlled tests.

## External audit anchoring

`AuditAnchorBatch` groups exact evidence-artifact digests in a tenant-scoped contiguous chain. Each batch after the first binds the exact previous `AuditAnchorRecord` digest.

`ExternalAuditAnchorReceipt` represents the opaque result of an external immutable/timestamping service: provider id, anchor id, exact batch digest, provider-receipt digest and anchor time.

`AuditAnchorRegistry.register()` verifies tenant scope, exact batch binding, contiguous sequence, exact previous record and monotonic assembly → anchoring → recording chronology before creating `AuditAnchorRecord`.

This proves exact local linkage to a declared external receipt digest; it does not independently prove the provider is immutable or that its timestamp has a specific legal evidentiary status.

## Relationship to authorization and assurance

v0.8 does not change policy precedence or add new authorization effects. The flow remains one-way:

```text
policy/data/MCP/approval/execution artifacts
           |                     |
           |                     +--> assurance crosswalk/package
           |
           +--> tenant encryption / audit anchoring

hardening artifact -X-> policy ALLOW
hardening artifact -X-> approval continuation
hardening artifact -X-> execution lease creation
```

Hardening artifacts can protect/configure a production adapter, but the offline core does not treat the existence of an RLS policy, encryption envelope or anchor receipt as authority to execute an action.

## Existing boundaries retained

v0.1 policy precedence remains `DENY > REQUIRE_HUMAN_APPROVAL > ALLOW_WITH_CONSTRAINTS > ALLOW`. v0.2 authenticated identity remains mandatory. v0.3 approval cannot override denial. v0.4 MCP governance remains explicit/non-executing. v0.5 leases remain short-lived, one-time and executor-bound. v0.6 data-purpose governance remains exact/currentness checked. v0.7 assurance remains human-reviewed and non-certifying.

## Trust boundaries

1. **Caller → identity/policy plane**: request and identity inputs remain untrusted until verified.
2. **Institution governance → data/MCP registries**: policy-supporting configuration remains privileged administrative input.
3. **Authenticated authorization → approval/execution**: exact current authorization artifacts remain execution authority.
4. **Institution → RLS reference artifacts**: policy metadata is privileged; rendered DDL becomes effective only when a production database adapter installs it.
5. **Application/database session → PostgreSQL RLS**: session institution/tenant settings and database role become a critical production boundary outside the offline core.
6. **Institution KMS/HSM → crypto-key reference**: only public/reference metadata crosses into RegAgentOps; private/symmetric key custody remains external.
7. **KMS/HSM signing adapter → signed configuration registry**: externally produced signature bytes cross the boundary and are locally verified before append.
8. **KMS/HSM encryption adapter → encrypted evidence**: plaintext/AAD are provided to the adapter and authenticated ciphertext returns; key bytes do not cross.
9. **Evidence store → external anchor service**: exact batch digest is anchored externally; an opaque receipt digest returns.
10. **Assurance/hardening evidence → auditor/operations**: sufficiency, deployed-state correctness and compliance conclusions remain external.

## Historical evidence versus current state

RLS policies, tenant profiles, crypto-key references, signed changes, encrypted envelopes and anchor records are immutable historical artifacts. New policy/profile/key versions create new exact digests rather than rewriting old records.

Historical cryptographic evidence remains verifiable/decryptable across ordinary key retirement when the adapter retains access and the key was valid at artifact creation. A key marked `DISABLED` is treated as unsafe and rejected.

## Capability separation

`hardening.py` contains no PostgreSQL driver, cloud SDK, KMS/HSM client, external-log client, shell/process invocation or tool-execution interface. CI statically rejects those capability markers.

The production realization of PostgreSQL RLS, KMS/HSM network calls, secrets authorization, immutable external storage, backup/replica isolation and operations monitoring is explicitly deferred to the v0.9 deployment boundary.

## Standards posture

The RLS renderer uses PostgreSQL row-level-security concepts as a deployment reference. Ed25519 and AES-256-GCM are cryptographic algorithm choices for the defined artifact boundaries. These choices are not a FIPS, HSM, cloud-provider, regulatory or certification claim.
