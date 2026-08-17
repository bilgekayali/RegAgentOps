from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regagentops.authenticated_identity_signature import sign_authenticated_agent_identity
from regagentops.authenticated_policy import AuthenticatedPolicyEngine
from regagentops.identity_binding import IdentityBindingError, establish_authenticated_agent_identity
from regagentops.identity_models import OidcVerifierConfig, WorkloadIdentityStatement, WorkloadIdentityTrustBundle, WorkloadIdentityTrustKey
from regagentops.models import AgentActionEnvelope, AgentDescriptor, DataClassification, Decision, Environment, RiskTier, ToolActionDescriptor, canonical_json
from regagentops.oidc import OidcIdentityError, verify_oidc_identity
from regagentops.policy import PolicyBundle, PolicyRule
from regagentops.registry import AgentRegistry, ToolRegistry
from regagentops.workload_identity import WorkloadIdentityError, sign_workload_identity, verify_workload_identity

NOW = 1767225900
NOW_TEXT = "2026-01-01T00:05:00Z"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class _Signer:
    institution_id = "bank-demo"
    key_id = "workload-key-1"
    algorithm = "Ed25519"

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oidc_key = Ed25519PrivateKey.generate()
        oidc_public = self.oidc_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": _b64url(oidc_public), "kid": "oidc-key-1", "alg": "EdDSA", "use": "sig", "key_ops": ["verify"]}]}
        self.config = OidcVerifierConfig(
            institution_id="bank-demo", provider_id="corp-oidc", issuer="https://idp.example.test",
            client_id="regagentops-client", allowed_algorithms=("EdDSA",), max_token_age_seconds=300,
            required_acr_values=("urn:example:loa:2",),
        )
        self.agent = AgentDescriptor("bank-demo", "ops-assistant", "owner-123", "example-provider", "example-model")
        self.tool = ToolActionDescriptor("bank-demo", "customer-records", "read-summary", (DataClassification.CONFIDENTIAL,))
        self.workload_key = Ed25519PrivateKey.generate()
        workload_public = self.workload_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.trust = WorkloadIdentityTrustBundle("bank-demo", (WorkloadIdentityTrustKey(
            "bank-demo", "workload-key-1", _b64url(workload_public), "2025-12-31T00:00:00Z", "2026-12-31T00:00:00Z"
        ),))
        self.signer = _Signer(self.workload_key)

    def token(self, **changes: object) -> str:
        claims: dict[str, object] = {
            "iss": self.config.issuer, "sub": "oidc-subject-123", "aud": self.config.client_id,
            "iat": NOW - 30, "exp": NOW + 300, "auth_time": NOW - 60, "nonce": "nonce-123",
            "acr": "urn:example:loa:2",
        }
        claims.update(changes)
        return jwt.encode(claims, self.oidc_key, algorithm="EdDSA", headers={"kid": "oidc-key-1"})

    def human(self):
        return verify_oidc_identity(
            self.token(), config=self.config, jwks=self.jwks, human_owner_id="owner-123",
            expected_subject="oidc-subject-123", expected_nonce="nonce-123", now_epoch=NOW,
        )

    def workload(self, **changes: object):
        data: dict[str, object] = {
            "institution_id": "bank-demo", "agent_id": "ops-assistant", "human_owner_id": "owner-123",
            "model_provider": "example-provider", "model_id": "example-model",
            "workload_id": "workload://bank-demo/ops-assistant",
            "challenge_digest": hashlib.sha256(b"challenge").hexdigest(),
            "issued_at": "2026-01-01T00:04:30Z", "expires_at": "2026-01-01T00:10:00Z",
        }
        data.update(changes)
        return sign_workload_identity(WorkloadIdentityStatement(**data), signer=self.signer)

    def identity(self):
        return establish_authenticated_agent_identity(
            self.agent, human_identity=self.human(), workload_identity=self.workload(),
            workload_trust_bundle=self.trust, established_at=NOW_TEXT,
        )

    def signed_identity(self):
        return sign_authenticated_agent_identity(self.identity(), signer=self.signer)

    def request(self):
        return AgentActionEnvelope(
            "req-1", "bank-demo", "ops-assistant", "owner-123", "example-provider", "example-model",
            "customer-records", "read-summary", "customer/summary", DataClassification.CONFIDENTIAL,
            "customer-support", Environment.TEST, RiskTier.MODERATE, "0" * 64, NOW_TEXT,
        )

    def policy(self):
        return PolicyBundle("bank-demo", (PolicyRule(
            "allow-read", "bank-demo", "ops-assistant", "customer-records", "read-summary",
            ("customer-support",), (Environment.TEST,), (DataClassification.CONFIDENTIAL,),
            (RiskTier.MODERATE,), Decision.ALLOW,
        ),))

    def engine(self):
        return AuthenticatedPolicyEngine(AgentRegistry((self.agent,)), ToolRegistry((self.tool,)))

    def test_oidc_verifies_and_does_not_persist_raw_bearer_material(self) -> None:
        raw = self.token()
        assertion = verify_oidc_identity(
            raw, config=self.config, jwks=self.jwks, human_owner_id="owner-123",
            expected_subject="oidc-subject-123", expected_nonce="nonce-123", now_epoch=NOW,
        )
        rendered = canonical_json(assertion)
        self.assertNotIn(raw, rendered)
        self.assertNotIn("nonce-123", rendered)

    def test_oidc_rejects_wrong_subject_expiry_and_remote_key_header(self) -> None:
        for token, subject in ((self.token(), "wrong-subject"), (self.token(exp=NOW), "oidc-subject-123")):
            with self.assertRaises(OidcIdentityError):
                verify_oidc_identity(token, config=self.config, jwks=self.jwks, human_owner_id="owner-123", expected_subject=subject, expected_nonce="nonce-123", now_epoch=NOW)
        remote = jwt.encode(
            {"iss": self.config.issuer, "sub": "oidc-subject-123", "aud": self.config.client_id, "iat": NOW - 30, "exp": NOW + 300, "nonce": "nonce-123", "acr": "urn:example:loa:2"},
            self.oidc_key, algorithm="EdDSA", headers={"kid": "oidc-key-1", "jku": "https://attacker.invalid"},
        )
        with self.assertRaises(OidcIdentityError):
            verify_oidc_identity(remote, config=self.config, jwks=self.jwks, human_owner_id="owner-123", expected_subject="oidc-subject-123", expected_nonce="nonce-123", now_epoch=NOW)

    def test_workload_signature_and_tamper_detection(self) -> None:
        signed = self.workload()
        self.assertEqual(verify_workload_identity(signed, trust_bundle=self.trust, now=NOW_TEXT).agent_id, "ops-assistant")
        with self.assertRaises(WorkloadIdentityError):
            verify_workload_identity(replace(signed, statement=replace(signed.statement, workload_id="forged")), trust_bundle=self.trust, now=NOW_TEXT)

    def test_binding_rejects_model_mismatch(self) -> None:
        with self.assertRaises(IdentityBindingError):
            establish_authenticated_agent_identity(
                self.agent, human_identity=self.human(), workload_identity=self.workload(model_id="wrong-model"),
                workload_trust_bundle=self.trust, established_at=NOW_TEXT,
            )

    def test_policy_rejects_unsigned_context(self) -> None:
        decision = self.engine().evaluate(self.request(), self.policy(), self.identity(), identity_trust_bundle=self.trust, evaluated_at=NOW_TEXT)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertIn("authenticated_identity_context_unsigned", decision.authorization.reason_codes)

    def test_policy_allows_valid_signed_context(self) -> None:
        decision = self.engine().evaluate(self.request(), self.policy(), self.signed_identity(), identity_trust_bundle=self.trust, evaluated_at=NOW_TEXT)
        self.assertTrue(decision.identity_verified)
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_policy_rejects_tampered_or_expired_signed_context(self) -> None:
        signed = self.signed_identity()
        tampered = replace(signed, identity=replace(signed.identity, workload_id="forged"))
        for candidate, at in ((tampered, NOW_TEXT), (signed, "2026-01-01T00:10:00Z")):
            decision = self.engine().evaluate(self.request(), self.policy(), candidate, identity_trust_bundle=self.trust, evaluated_at=at)
            self.assertEqual(decision.decision, Decision.DENY)
            self.assertIn("authenticated_identity_context_untrusted_or_expired", decision.authorization.reason_codes)

    def test_policy_rejects_agent_registration_drift(self) -> None:
        changed = replace(self.agent, model_id="rotated-model")
        engine = AuthenticatedPolicyEngine(AgentRegistry((changed,)), ToolRegistry((self.tool,)))
        decision = engine.evaluate(self.request(), self.policy(), self.signed_identity(), identity_trust_bundle=self.trust, evaluated_at=NOW_TEXT)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertIn("authenticated_identity_agent_registration_changed", decision.authorization.reason_codes)


if __name__ == "__main__":
    unittest.main()
