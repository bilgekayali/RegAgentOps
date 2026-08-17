from __future__ import annotations

import base64
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regagentops.identity_binding import HumanIdentityRegistration, HumanIdentityRegistry
from regagentops.identity_models import OidcVerifierConfig
from regagentops.oidc import OidcIdentityError
from regagentops.registered_identity import verify_registered_oidc_identity

NOW = 1767225900


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class RegisteredIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.jwks = {
            "keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(public), "kid": "k1", "alg": "EdDSA"}]
        }
        self.config = OidcVerifierConfig(
            institution_id="bank-demo",
            provider_id="corp-oidc",
            issuer="https://idp.example.test",
            client_id="regagentops-client",
            allowed_algorithms=("EdDSA",),
        )
        self.registry = HumanIdentityRegistry((
            HumanIdentityRegistration(
                institution_id="bank-demo",
                human_owner_id="owner-123",
                provider_id="corp-oidc",
                subject="subject-123",
            ),
        ))

    def _token(self) -> str:
        return jwt.encode(
            {
                "iss": self.config.issuer,
                "sub": "subject-123",
                "aud": self.config.client_id,
                "iat": NOW - 30,
                "exp": NOW + 120,
                "nonce": "nonce-123",
            },
            self.private_key,
            algorithm="EdDSA",
            headers={"kid": "k1"},
        )

    def test_registered_subject_is_source_of_truth(self) -> None:
        assertion = verify_registered_oidc_identity(
            self._token(),
            config=self.config,
            jwks=self.jwks,
            registry=self.registry,
            human_owner_id="owner-123",
            expected_nonce="nonce-123",
            now_epoch=NOW,
        )
        self.assertEqual(assertion.subject, "subject-123")
        self.assertEqual(assertion.human_owner_id, "owner-123")

    def test_unregistered_owner_fails_closed(self) -> None:
        with self.assertRaises(OidcIdentityError):
            verify_registered_oidc_identity(
                self._token(),
                config=self.config,
                jwks=self.jwks,
                registry=self.registry,
                human_owner_id="owner-999",
                expected_nonce="nonce-123",
                now_epoch=NOW,
            )

    def test_provider_mismatch_fails_closed(self) -> None:
        registry = HumanIdentityRegistry((
            HumanIdentityRegistration(
                institution_id="bank-demo",
                human_owner_id="owner-123",
                provider_id="other-provider",
                subject="subject-123",
            ),
        ))
        with self.assertRaises(OidcIdentityError):
            verify_registered_oidc_identity(
                self._token(),
                config=self.config,
                jwks=self.jwks,
                registry=registry,
                human_owner_id="owner-123",
                expected_nonce="nonce-123",
                now_epoch=NOW,
            )


if __name__ == "__main__":
    unittest.main()
