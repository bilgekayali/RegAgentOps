# Threat Model — v0.8

## Protected assets

- authorization policy integrity and governance-evidence binding;
- institution, human-owner, agent, model and workload identity bindings;
- data-resource classification/category, purpose, output and retention governance;
- approval authority, signature and replay integrity;
- MCP server approval, identity-pin, snapshot and binding integrity;
- execution-lease integrity, executor binding and one-time consumption state;
- emergency-stop state and signed execution-receipt integrity;
- assurance-scope/applicability/crosswalk/package integrity;
- tenant identity and PostgreSQL RLS policy/profile integrity;
- institution-owned KMS/HSM key-reference integrity and tenant/purpose separation;
- signed configuration-change chain integrity;
- encrypted-governance-evidence tenant/key/AAD integrity;
- external audit-anchor batch/receipt/chain integrity; and
- separation between hardening evidence and execution authority.

## Trust boundaries

1. **Caller → identity/policy plane**: action, identity and request inputs are untrusted until verified.
2. **Institution data/MCP configuration → governance registries**: classification, purpose, tool/server and related configuration are privileged input.
3. **Authenticated authorization → approval/execution**: exact current policy/governance artifacts remain execution authority.
4. **Institution database configuration → RLS artifacts**: policy/profile artifacts are trusted administrative references; actual PostgreSQL deployment is external.
5. **Application/database session → PostgreSQL RLS**: production session settings and role selection can enforce or defeat tenant isolation and remain outside the offline core.
6. **Institution KMS/HSM → key references**: only reference/public material crosses into RegAgentOps; private/symmetric keys remain external.
7. **KMS/HSM signer → configuration registry**: signature bytes cross the boundary and are locally verified before append.
8. **KMS/HSM encryptor/decryptor → encrypted evidence**: authenticated ciphertext/plaintext crosses the adapter boundary; raw key material does not.
9. **Evidence batch → external immutable anchor**: exact batch digest is sent externally and an opaque provider receipt is represented locally.
10. **Assurance/hardening evidence → auditor/operations**: deployed-state correctness, evidence sufficiency and compliance conclusions remain external.
11. **Execution lease ledger → external executor**: one-time consumption remains the final RegAgentOps pre-dispatch boundary.

## Primary v0.8 threats and controls

### PostgreSQL RLS injection or partial policy

Threat: a policy renderer accepts arbitrary SQL identifiers/fragments, fails to force RLS, protects reads without protecting writes, or scopes only by tenant without institution.

Controls: table/policy/column identifiers use a bounded lowercase identifier grammar; session settings must use `regagentops.*`; the renderer always emits `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and the same exact institution+tenant predicate in both `USING` and `WITH CHECK`.

Residual boundary: v0.8 does not connect to PostgreSQL or prove that the rendered DDL is installed, enabled on every relevant table, resistant to privileged-role bypass, or consistently applied to replicas/backups.

### Cross-tenant RLS profile substitution

Threat: a tenant profile references unknown or institution-foreign RLS policy evidence.

Control: `TenantIsolationRegistry` resolves every policy digest in the same institution before registering a tenant profile. Policy/profile versions are immutable and contiguous.

### KMS/HSM custody laundering

Threat: software-held keys are represented as institution-controlled hardware/cloud custody, or symmetric/private key bytes leak into governance artifacts.

Controls: key-reference custody is structurally restricted to `kms` or `hsm`; configuration signing references expose only an Ed25519 public key; evidence-encryption references forbid public/raw symmetric material. No private/symmetric key field exists in the v0.8 contracts.

Residual boundary: the label is a governance assertion. v0.8 does not obtain provider attestation or prove the external system is genuinely hardware-backed or correctly administered.

### Cross-tenant key substitution

Threat: a signer/encryptor/decryptor for one tenant or key version is used for another tenant's artifact.

Controls: key references bind institution, tenant, purpose, key id and version. Sign/encrypt/decrypt adapters must expose matching metadata and mismatch fails closed. Signed/encrypted artifacts also bind the exact key-reference digest.

### Key-rotation ambiguity

Threat: multiple versions reuse a key identity or non-contiguous versions obscure which key was intended.

Controls: versions are contiguous per institution/tenant/purpose and rotated versions require distinct `key_id` values. New operations require an `ACTIVE` key. Historical verification/decryption can accept ordinary retirement but rejects `DISABLED` keys.

Residual boundary: the immutable reference model does not itself execute provider-side disable/delete/rotation operations; v0.9 runbooks and adapters must implement those lifecycle actions.

### Configuration-change signature substitution

Threat: a signed configuration change is modified, signed under another tenant/key, or detached from the exact previous change.

Controls: domain-separated Ed25519 signing binds institution, tenant, sequence, request digest, exact key-reference digest, previous signed-change digest and signing time. Verification resolves the exact registered key reference and checks signature/key validity at signing time.

### Configuration-chain fork or replay

Threat: two competing changes extend the same tenant chain, a sequence is skipped, or an old chain head is reused.

Controls: `ConfigurationChangeRegistry` requires one contiguous tenant sequence and exact previous `SignedConfigurationChange` digest. Chain chronology cannot move backwards.

### Stale-object overwrite

Threat: a validly signed writer changes an object from an obsolete prior state and overwrites a newer represented configuration.

Control: the registry tracks the latest represented digest per tenant/object identity. Subsequent changes to that object must bind the exact current digest as `previous_configuration_digest`.

Residual boundary: the registry represents configuration state; it does not independently verify that every external system applied the represented change.

### AES-GCM tenant/AAD substitution

Threat: ciphertext from another tenant, key, envelope or subject is relabeled as current evidence.

Controls: domain-separated AAD binds envelope id, institution, tenant, exact key-reference digest and subject-artifact digest. The envelope also records AAD and plaintext SHA-256 digests. Adapter metadata must match the exact key reference.

### Ciphertext tampering

Threat: encrypted governance evidence is modified while retaining metadata.

Controls: AES-256-GCM authenticated decryption is required by the adapter contract, and plaintext digest verification runs after decryption. Modified AAD changes the recorded AAD digest; modified ciphertext must fail provider authentication or plaintext-digest verification.

Residual boundary: v0.8 cannot prove nonce uniqueness across every independent external caller. The core generates a fresh 96-bit nonce by default; production integration must maintain the same uniqueness property.

### External-anchor receipt substitution

Threat: a receipt for another tenant or batch is attached to the current audit chain.

Controls: `ExternalAuditAnchorReceipt` binds exact institution, tenant and `AuditAnchorBatch` digest. Registration rejects scope or batch mismatch.

### Audit-anchor chain fork or backdating

Threat: batches skip/fork sequence, reference the wrong previous record, or claim an external anchor predating the local batch.

Controls: batches are tenant-scoped, contiguous and bind the exact previous `AuditAnchorRecord` digest. Registry chronology enforces batch assembly <= external anchor <= local recording and non-decreasing recorded time.

Residual boundary: provider receipt authenticity, true external immutability and independent timestamp accuracy are not proven by the opaque receipt digest alone.

### Hardening-to-execution privilege escalation

Threat: possession of an RLS policy, encrypted evidence or anchor receipt is treated as permission to execute an agent action.

Control: v0.8 hardening types are not accepted as policy effects, approval continuation or execution-lease authority. Existing authorization and execution boundaries remain unchanged.

## Existing v0.2-v0.7 threats retained

Prior controls remain active: authenticated identity and key-confusion defenses; requester/approver separation and replay controls; bounded explicit MCP governance; exact data-purpose classification/purpose/output/retention controls; authorization freshness; executor-bound one-time leases; emergency-stop currentness; signed execution receipts; human-reviewed assurance applicability/crosswalk/package integrity; and non-certification semantics.

## Capability creep

Threat: hardening code quietly becomes a PostgreSQL migration client, cloud KMS SDK integration, external-log client or production executor.

Controls: generic CI and the dedicated Tenant and Cryptographic Hardening Boundary reject network/process imports plus PostgreSQL/cloud-SDK/client markers in `hardening.py`. The module renders SQL text and consumes adapter protocols only.

## Residual risks

Actual PostgreSQL RLS effectiveness depends on production role architecture, session-setting integrity, migration completeness, superuser/BYPASSRLS control, backup/replica isolation and operational monitoring.

Actual KMS/HSM security depends on provider IAM, key policies, hardware/service guarantees, entropy, quorum/approval configuration, audit logging, rotation and compromise response. v0.8 stores references and verifies cryptographic outputs; it is not the custody system.

Configuration-change artifacts prove the represented signature/chain, not that every downstream component applied the intended configuration or that unauthorized out-of-band changes are impossible.

Encrypted envelopes protect represented bytes under the adapter's AES-GCM operation but do not independently guarantee secure plaintext handling before encryption or after decryption.

External anchor records prove exact linkage to a declared provider receipt digest but do not establish legal admissibility, provider independence or physical WORM guarantees.

SQLite approval/execution ledgers remain local serialization boundaries rather than distributed consensus. In-memory governance/hardening registries are reference state rather than tenant-isolated durable production stores.

## Explicit non-claims

v0.8 does not provide or claim:

- deployed PostgreSQL RLS verification or absolute non-bypassability;
- automatic PostgreSQL migration/session-role management;
- KMS/HSM provider attestation, FIPS validation or proof of hardware custody;
- secure cloud/database IAM administration;
- raw private/symmetric-key custody in the RegAgentOps core;
- guaranteed nonce uniqueness across every external integration;
- proof that external audit anchors are immutable, independently timestamped or legally sufficient;
- backup/replica tenant isolation or database encryption-at-rest proof;
- production key rotation, incident response or disaster-recovery execution;
- automatic framework/legal compliance determination;
- autonomous MCP connectivity or production tool invocation by the core;
- distributed exactly-once execution across multiple executor nodes;
- regulatory or standards certification; or
- production fitness.
