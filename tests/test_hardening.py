from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from regagentops.hardening import (
    AuditAnchorBatch,
    AuditAnchorRegistry,
    ConfigurationChangeRegistry,
    ConfigurationChangeRequest,
    CryptoAlgorithm,
    CryptoKeyCustody,
    CryptoKeyPurpose,
    CryptoKeyStatus,
    EncryptedGovernanceEvidence,
    ExternalAuditAnchorReceipt,
    InstitutionCryptoKeyReference,
    InstitutionCryptoKeyRegistry,
    PostgresRlsPolicy,
    TenantIsolationProfile,
    TenantIsolationRegistry,
    decrypt_and_verify_governance_evidence,
    encrypt_governance_evidence,
    render_postgres_rls_sql,
    sign_configuration_change,
    verify_signed_configuration_change,
)
from regagentops.models import Environment, digest_artifact

NOW = "2026-08-19T11:50:00Z"


def b64url(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Ed25519Signer:
    algorithm = "Ed25519"

    def __init__(self, private_key, *, institution_id="bank-demo", tenant_id="tenant-a", key_id="cfg-key-1", key_version=1):
        self.private_key = private_key
        self.institution_id = institution_id
        self.tenant_id = tenant_id
        self.key_id = key_id
        self.key_version = key_version

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)


class AesProvider:
    algorithm = "AES-256-GCM"

    def __init__(self, key: bytes, *, institution_id="bank-demo", tenant_id="tenant-a", key_id="enc-key-1", key_version=1):
        self.aes = AESGCM(key)
        self.institution_id = institution_id
        self.tenant_id = tenant_id
        self.key_id = key_id
        self.key_version = key_version

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self.aes.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self.aes.decrypt(nonce, ciphertext, aad)


class TenantCryptoHardeningTests(unittest.TestCase):
    def rls_policy(self, **changes):
        values = dict(
            institution_id="bank-demo",
            policy_id="governance_evidence_rls",
            policy_version=1,
            table_name="governance_evidence",
            policy_name="tenant_isolation",
            institution_column="institution_id",
            tenant_column="tenant_id",
            institution_setting="regagentops.institution_id",
            tenant_setting="regagentops.tenant_id",
            force_row_level_security=True,
            registered_at=NOW,
        )
        values.update(changes)
        return PostgresRlsPolicy(**values)

    def signing_material(self, *, status=CryptoKeyStatus.ACTIVE, tenant_id="tenant-a"):
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        reference = InstitutionCryptoKeyReference(
            institution_id="bank-demo",
            tenant_id=tenant_id,
            purpose=CryptoKeyPurpose.CONFIG_SIGNING,
            key_version=1,
            key_id="cfg-key-1",
            custody=CryptoKeyCustody.HSM,
            algorithm=CryptoAlgorithm.ED25519,
            public_key_base64url=b64url(public),
            status=status,
            not_before="2026-08-19T00:00:00Z",
            not_after="2027-08-19T00:00:00Z",
            registered_at="2026-08-18T00:00:00Z",
        )
        signer = Ed25519Signer(private, tenant_id=tenant_id)
        return reference, signer

    def encryption_material(self, *, status=CryptoKeyStatus.ACTIVE, tenant_id="tenant-a"):
        key = bytes(range(32))
        reference = InstitutionCryptoKeyReference(
            institution_id="bank-demo",
            tenant_id=tenant_id,
            purpose=CryptoKeyPurpose.EVIDENCE_ENCRYPTION,
            key_version=1,
            key_id="enc-key-1",
            custody=CryptoKeyCustody.KMS,
            algorithm=CryptoAlgorithm.AES_256_GCM,
            public_key_base64url=None,
            status=status,
            not_before="2026-08-19T00:00:00Z",
            not_after="2027-08-19T00:00:00Z",
            registered_at="2026-08-18T00:00:00Z",
        )
        return reference, AesProvider(key, tenant_id=tenant_id)

    def config_request(self, *, sequence=1, previous=None, proposed="b" * 64, object_id="policy-1"):
        return ConfigurationChangeRequest(
            change_id=f"change-{sequence}",
            institution_id="bank-demo",
            tenant_id="tenant-a",
            sequence=sequence,
            object_type="policy_bundle",
            object_id=object_id,
            previous_configuration_digest=previous,
            proposed_configuration_digest=proposed,
            change_reason_digest="c" * 64,
            requested_by_human_id="owner-1",
            requested_at="2026-08-19T11:49:00Z",
            effective_at="2026-08-19T11:55:00Z",
        )

    def test_postgres_rls_reference_forces_using_and_with_check_for_both_scopes(self):
        policy = self.rls_policy()
        sql = render_postgres_rls_sql(policy)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("USING (institution_id = current_setting('regagentops.institution_id', true) AND tenant_id = current_setting('regagentops.tenant_id', true))", sql)
        self.assertIn("WITH CHECK (institution_id = current_setting('regagentops.institution_id', true) AND tenant_id = current_setting('regagentops.tenant_id', true))", sql)

    def test_rls_identifier_injection_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "safe lowercase PostgreSQL identifier"):
            self.rls_policy(table_name="governance_evidence; DROP TABLE users")
        with self.assertRaisesRegex(ValueError, "regagentops"):
            self.rls_policy(tenant_setting="app.tenant_id")
        with self.assertRaisesRegex(ValueError, "force row level security"):
            self.rls_policy(force_row_level_security=False)

    def test_tenant_profile_binds_registered_rls_policy_digest(self):
        registry = TenantIsolationRegistry()
        policy = self.rls_policy()
        registry.register_policy(policy)
        profile = TenantIsolationProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=Environment.PRODUCTION,
            database_role="regagentops_runtime",
            rls_policy_digests=(policy.artifact_digest,),
            registered_at=NOW,
        )
        registry.register_profile(profile)
        self.assertEqual(registry.current_profile("bank-demo", "tenant-a").artifact_digest, profile.artifact_digest)
        self.assertEqual(len(registry.snapshot_digest("bank-demo", "tenant-a")), 64)
        with self.assertRaisesRegex(ValueError, "unknown PostgreSQL RLS policy digest"):
            registry.register_profile(replace(profile, tenant_id="tenant-b", rls_policy_digests=("d" * 64,)))

    def test_crypto_key_references_never_embed_symmetric_key_material(self):
        encryption, _ = self.encryption_material()
        self.assertIsNone(encryption.public_key_base64url)
        with self.assertRaisesRegex(ValueError, "must not be embedded"):
            replace(encryption, public_key_base64url=b64url(bytes(range(32))))
        signing, _ = self.signing_material()
        self.assertEqual(signing.custody, CryptoKeyCustody.HSM)
        self.assertEqual(len(signing.public_key_base64url), 43)

    def test_key_versions_are_tenant_scoped_contiguous_and_distinct(self):
        registry = InstitutionCryptoKeyRegistry()
        first, _ = self.signing_material()
        registry.register(first)
        with self.assertRaisesRegex(ValueError, "contiguous"):
            registry.register(replace(first, key_version=3, key_id="cfg-key-3"))
        with self.assertRaisesRegex(ValueError, "distinct key_id"):
            registry.register(replace(first, key_version=2, registered_at=NOW))
        second = replace(first, key_version=2, key_id="cfg-key-2", registered_at=NOW)
        registry.register(second)
        self.assertEqual(registry.current_active("bank-demo", "tenant-a", CryptoKeyPurpose.CONFIG_SIGNING, at=NOW), second)

    def test_signed_configuration_change_roundtrip_and_historical_key_expiry(self):
        key_registry = InstitutionCryptoKeyRegistry()
        key, signer = self.signing_material()
        key_registry.register(key)
        request = self.config_request()
        signed = sign_configuration_change(
            request,
            previous_change_digest=None,
            key_reference=key,
            signer=signer,
            signed_at=NOW,
        )
        verified = verify_signed_configuration_change(signed, key_registry=key_registry, now="2028-08-19T00:00:00Z")
        self.assertEqual(verified.artifact_digest, request.artifact_digest)
        registry = ConfigurationChangeRegistry()
        registry.append(signed, key_registry=key_registry, now=NOW)
        self.assertEqual(registry.history("bank-demo", "tenant-a")[0].artifact_digest, signed.artifact_digest)

    def test_configuration_change_rejects_tenant_signer_substitution_and_tampering(self):
        key_registry = InstitutionCryptoKeyRegistry()
        key, signer = self.signing_material()
        key_registry.register(key)
        request = self.config_request()
        foreign_signer = Ed25519Signer(signer.private_key, tenant_id="tenant-b")
        with self.assertRaisesRegex(ValueError, "tenant scope mismatch"):
            sign_configuration_change(
                request,
                previous_change_digest=None,
                key_reference=key,
                signer=foreign_signer,
                signed_at=NOW,
            )
        signed = sign_configuration_change(request, previous_change_digest=None, key_reference=key, signer=signer, signed_at=NOW)
        tampered = replace(signed, request=replace(request, proposed_configuration_digest="e" * 64))
        with self.assertRaisesRegex(ValueError, "signing document digest mismatch"):
            verify_signed_configuration_change(tampered, key_registry=key_registry, now=NOW)

    def test_configuration_change_chain_rejects_fork_and_stale_object_state(self):
        key_registry = InstitutionCryptoKeyRegistry()
        key, signer = self.signing_material()
        key_registry.register(key)
        registry = ConfigurationChangeRegistry()
        first_request = self.config_request(proposed="1" * 64)
        first = sign_configuration_change(first_request, previous_change_digest=None, key_reference=key, signer=signer, signed_at=NOW)
        registry.append(first, key_registry=key_registry, now=NOW)

        second_request = self.config_request(sequence=2, previous="0" * 64, proposed="2" * 64)
        second = sign_configuration_change(
            second_request,
            previous_change_digest=first.artifact_digest,
            key_reference=key,
            signer=signer,
            signed_at=NOW,
        )
        with self.assertRaisesRegex(ValueError, "previous digest does not match current object state"):
            registry.append(second, key_registry=key_registry, now=NOW)

        correct_request = self.config_request(sequence=2, previous="1" * 64, proposed="2" * 64)
        forked = sign_configuration_change(
            correct_request,
            previous_change_digest="f" * 64,
            key_reference=key,
            signer=signer,
            signed_at=NOW,
        )
        with self.assertRaisesRegex(ValueError, "exact tenant change chain"):
            registry.append(forked, key_registry=key_registry, now=NOW)

    def test_tenant_scoped_aes_gcm_evidence_roundtrip_and_aad_tamper_rejection(self):
        key_registry = InstitutionCryptoKeyRegistry()
        key, provider = self.encryption_material()
        key_registry.register(key)
        plaintext = b'{"decision":"ALLOW_WITH_CONSTRAINTS"}'
        envelope = encrypt_governance_evidence(
            plaintext,
            envelope_id="evidence-envelope-1",
            institution_id="bank-demo",
            tenant_id="tenant-a",
            subject_artifact_digest="a" * 64,
            key_reference=key,
            encryptor=provider,
            encrypted_at=NOW,
            nonce=b"\x01" * 12,
        )
        self.assertNotIn(plaintext.decode(), envelope.ciphertext_base64url)
        recovered = decrypt_and_verify_governance_evidence(envelope, key_registry=key_registry, decryptor=provider, now=NOW)
        self.assertEqual(recovered, plaintext)
        tampered = replace(envelope, subject_artifact_digest="b" * 64)
        with self.assertRaisesRegex(ValueError, "AAD digest mismatch"):
            decrypt_and_verify_governance_evidence(tampered, key_registry=key_registry, decryptor=provider, now=NOW)

    def test_encryption_rejects_cross_tenant_provider_and_retired_key_for_new_ciphertext(self):
        key, provider = self.encryption_material()
        foreign = AesProvider(bytes(range(32)), tenant_id="tenant-b")
        with self.assertRaisesRegex(ValueError, "does not match exact tenant key reference"):
            encrypt_governance_evidence(
                b"evidence",
                envelope_id="e-1",
                institution_id="bank-demo",
                tenant_id="tenant-a",
                subject_artifact_digest="a" * 64,
                key_reference=key,
                encryptor=foreign,
                encrypted_at=NOW,
                nonce=b"\x02" * 12,
            )
        with self.assertRaisesRegex(ValueError, "requires an active key"):
            encrypt_governance_evidence(
                b"evidence",
                envelope_id="e-2",
                institution_id="bank-demo",
                tenant_id="tenant-a",
                subject_artifact_digest="a" * 64,
                key_reference=replace(key, status=CryptoKeyStatus.RETIRED),
                encryptor=provider,
                encrypted_at=NOW,
                nonce=b"\x03" * 12,
            )

    def test_external_audit_anchor_chain_binds_exact_batch_and_tenant(self):
        registry = AuditAnchorRegistry()
        batch = AuditAnchorBatch(
            batch_id="batch-1",
            institution_id="bank-demo",
            tenant_id="tenant-a",
            sequence=1,
            previous_anchor_record_digest=None,
            evidence_artifact_digests=("a" * 64, "b" * 64),
            assembled_at=NOW,
        )
        receipt = ExternalAuditAnchorReceipt(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            batch_digest=batch.artifact_digest,
            provider_id="immutable-log-1",
            anchor_id="anchor-0001",
            provider_receipt_digest="c" * 64,
            anchored_at="2026-08-19T11:51:00Z",
        )
        record = registry.register(batch, receipt, recorded_at="2026-08-19T11:52:00Z")
        self.assertEqual(record.batch_digest, batch.artifact_digest)
        second_batch = AuditAnchorBatch(
            batch_id="batch-2",
            institution_id="bank-demo",
            tenant_id="tenant-a",
            sequence=2,
            previous_anchor_record_digest=record.artifact_digest,
            evidence_artifact_digests=("d" * 64,),
            assembled_at="2026-08-19T11:53:00Z",
        )
        bad_receipt = replace(receipt, batch_digest=second_batch.artifact_digest, tenant_id="tenant-b", anchor_id="anchor-0002", anchored_at="2026-08-19T11:54:00Z")
        with self.assertRaisesRegex(ValueError, "tenant scope mismatch"):
            registry.register(second_batch, bad_receipt, recorded_at="2026-08-19T11:55:00Z")

    def test_external_anchor_rejects_wrong_batch_and_backdated_receipt(self):
        registry = AuditAnchorRegistry()
        batch = AuditAnchorBatch(
            batch_id="batch-1",
            institution_id="bank-demo",
            tenant_id="tenant-a",
            sequence=1,
            previous_anchor_record_digest=None,
            evidence_artifact_digests=("a" * 64,),
            assembled_at=NOW,
        )
        wrong = ExternalAuditAnchorReceipt(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            batch_digest="f" * 64,
            provider_id="immutable-log-1",
            anchor_id="anchor-x",
            provider_receipt_digest="c" * 64,
            anchored_at="2026-08-19T11:51:00Z",
        )
        with self.assertRaisesRegex(ValueError, "exact audit batch"):
            registry.register(batch, wrong, recorded_at="2026-08-19T11:52:00Z")
        backdated = replace(wrong, batch_digest=batch.artifact_digest, anchored_at="2026-08-19T11:49:00Z")
        with self.assertRaisesRegex(ValueError, "cannot predate batch assembly"):
            registry.register(batch, backdated, recorded_at="2026-08-19T11:52:00Z")


if __name__ == "__main__":
    unittest.main()
