import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from regagentops.hardening import (
    CryptoAlgorithm,
    CryptoKeyCustody,
    CryptoKeyPurpose,
    CryptoKeyStatus,
    InstitutionCryptoKeyReference,
    InstitutionCryptoKeyRegistry,
    encrypt_governance_evidence,
)


class AesProvider:
    institution_id = "bank-demo"
    tenant_id = "tenant-a"
    key_id = "enc-key-1"
    key_version = 1
    algorithm = "AES-256-GCM"

    def __init__(self) -> None:
        self._aes = AESGCM(bytes(range(32)))

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._aes.encrypt(nonce, plaintext, aad)


class CryptographicOperationTimeTests(unittest.TestCase):
    def test_new_encryption_cannot_be_backdated_relative_to_operation_time(self):
        key = InstitutionCryptoKeyReference(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            purpose=CryptoKeyPurpose.EVIDENCE_ENCRYPTION,
            key_version=1,
            key_id="enc-key-1",
            custody=CryptoKeyCustody.KMS,
            algorithm=CryptoAlgorithm.AES_256_GCM,
            public_key_base64url=None,
            status=CryptoKeyStatus.ACTIVE,
            not_before="2026-08-19T00:00:00Z",
            not_after="2027-08-19T00:00:00Z",
            registered_at="2026-08-18T00:00:00Z",
        )
        registry = InstitutionCryptoKeyRegistry()
        registry.register(key)
        with self.assertRaisesRegex(ValueError, "must equal current operation time"):
            encrypt_governance_evidence(
                b"evidence",
                envelope_id="envelope-1",
                institution_id="bank-demo",
                tenant_id="tenant-a",
                subject_artifact_digest="a" * 64,
                key_reference=key,
                key_registry=registry,
                encryptor=AesProvider(),
                encrypted_at="2026-08-19T11:50:00Z",
                now="2026-08-19T11:51:00Z",
            )


if __name__ == "__main__":
    unittest.main()
