from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regagentops.authenticated_policy import AuthenticatedPolicyEngine
from regagentops.identity_binding import IdentityBindingError, establish_authenticated_agent_identity
from regagentops.identity_models import (
    OidcVerifierConfig,
    TrustKeyStatus,
    WorkloadIdentityStatement,
    WorkloadIdentityTrustBundle,
    WorkloadIdentityTrustKey,
)
from regagentops.models import (
    AgentActionEnvelope,
    AgentDescriptor,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    ToolActionDescriptor,
    canonical_json,
)
from regagentops.oidc import OidcIdentityError, verify_oidc_identity
from regagentops.policy import PolicyBundle, PolicyRule
from regagentops.registry import AgentRegistry, ToolRegistry
from regagentops.workload_identity import WorkloadIdentityError, sign_workload_identity, verify_workload_identity

NOW = 1767225900  # 2026-01-01T00:05:00Z
NOW_TEXT = "2026-01-01T00:05:00Z"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class _Signer:
    institution_id = "bank-demo"
    key_id = "workload-key-1"
    algorithm = "Ed25519"

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oidc_private = Ed25519PrivateKey.generate()
        oidc_public = self.oidc_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.jwks = {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(oidc_public),
                    "kid": "oidc-key-1",
                    "alg": "EdDSA",
                    "use": "sig",
                    "key_ops": ["verify"],
                }
            ]
        }
        self.config = OidcVerifierConfig(
            institution_id="bank-demo",
            provider_id="corp-oidc",
            issuer="https://idp.example.test",
            client_id="regagentops-client",
            allowed_algorithms=("EdDSA",),
            max_token_age_seconds=300,
            required_acr_values=("urn:example:loa:2",),
        )
        self.agent = AgentDescriptor(
            institution_id="bank-demo",
            agent_id="ops-assistant",
            human_owner_id="owner-123",
            model_provider="example-provider",
            model_id="example-model",
        )
        self.tool = ToolActionDescriptor(
            institution_id="bank-demo",
            tool_id="customer-records",
            action="read-summary",
            allowed_data_classifications=(DataClassification.CONFIDENTIAL,),
        )
        self.workload_private = Ed25519PrivateKey.generate()
        workload_public = self.workload_private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.trust_bundle = WorkloadIdentityTrustBundle(
            institution_id="bank-demo",
            keys=(
                WorkloadIdentityTrustKey(
                    institution_id="bank-demo",
                    key_id="workload-key-1",
                    public_key_base64url=_b64url(workload_public),
                    not_before="2025-12-31T00:00:00Z",
                    not_after="2026-12-31T00:00:00Z",
                ),
            ),
        )

    def _token(self, **overrides: object) -> str:
        claims: dict[str, object] = {
            "iss": self.config.issuer,
            "sub": "oidc-subject-123",
            "aud": self.config.client_id,
            "iat": NOW - 30,
            "exp": NOW + 300,
            "auth_time": NOW - 60,
            "nonce": "nonce-123",
            "acr": "urn:example:loa:2",
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            self.oidc_private,
            algorithm="EdDSA",
            headers={"kid": "oidc-key-1", "typ": "JWT"},
        )

    def _human(self):
        return verify_oidc_identity(
            self._token(),
            config=self.config,
            jwks=self.jwks,
            human_owner_id="owner-123",
            expected_subject="oidc-subject-123",
            expected_nonce="nonce-123",
            now_epoch=NOW,
        )

    def _signed_workload(self, **statement_overrides: object):
        values: dict[str, object] = {
            "institution_id": "bank-demo",
            "agent_id": "ops-assistant",
            "human_owner_id": "owner-123",
            "model_provider": "example-provider",
            "model_id": "example-model",
            "workload_id": "spiffe-like://bank-demo/agent/ops-assistant",
            "challenge_digest": hashlib.sha256(b"challenge-123").hexdigest(),
            "issued_at": "2026-01-01T00:04:30Z",
            "expires_at": "2026-01-01T00:10:00Z",
        }
        values.update(statement_overrides)
        statement = WorkloadIdentityStatement(**values)
        return sign_workload_identity(statement, signer=_Signer(self.workload_private))

    def _identity(self):
        return establish_authenticated_agent_identity(
            self.agent,
            human_identity=self._human(),
            workload_identity=self._signed_workload(),
            workload_trust_bundle=self.trust_bundle,
            established_at=NOW_TEXT,
        )

    def _request(self) -> AgentActionEnvelope:
        return AgentActionEnvelope(
            request_id="req-identity-1",
            institution_id="bank-demo",
            agent_id="ops-assistant",
            human_owner_id="owner-123",
            model_provider="example-provider",
            model_id="example-model",
            tool_id="customer-records",
            action="read-summary",
            resource="customer/summary",
            data_classification=DataClassification.CONFIDENTIAL,
            business_purpose="customer-support",
            environment=Environment.TEST,
            risk_tier=RiskTier.MODERATE,
            input_digest="0" * 64,
            requested_at=NOW_TEXT,
        )

    def _policy(self) -> PolicyBundle:
        return PolicyBundle(
            institution_id="bank-demo",
            rules=(
                PolicyRule(
                    rule_id="allow-read",
                    institution_id="bank-demo",
                    agent_id="ops-assistant",
                    tool_id="customer-records",
                    action="read-summary",
                    business_purposes=("customer-support",),
                    environments=(Environment.TEST,),
                    data_classifications=(DataClassification.CONFIDENTIAL,),
                    risk_tiers=(RiskTier.MODERATE,),
                    effect=Decision.ALLOW,
                ),
            ),
        )

    def test_oidc_verification_is_offline_and_redacts_bearer_material(self) -> None:
        raw = self._token()
        assertion = verify_oidc_identity(
            raw,
            config=self.config,
            jwks=self.jwks,
            human_owner_id="owner-123",
            expected_subject="oidc-subject-123",
            expected_nonce="nonce-123",
            now_epoch=NOW,
        )
        rendered = canonical_json(assertion)
        self.assertNotIn(raw, rendered)
        self.assertNotIn("nonce-123", rendered)
        self.assertEqual(assertion.algorithm, "EdDSA")
        self.assertEqual(assertion.subject, "oidc-subject-123")

    def test_oidc_rejects_wrong_subject(self) -> None:
        with self.assertRaises(OidcIdentityError):
            verify_oidc_identity(
                self._token(),
                config=self.config,
                jwks=self.jwks,
                human_owner_id="owner-123",
                expected_subject="different-subject",
                expected_nonce="nonce-123",
                now_epoch=NOW,
            )

    def test_oidc_rejects_expired_token(self) -> None:
        with self.assertRaises(OidcIdentityError):
            verify_oidc_identity(
                self._token(exp=NOW),
                config=self.config,
                jwks=self.jwks,
                human_owner_id="owner-123",
                expected_subject="oidc-subject-123",
                expected_nonce="nonce-123",
                now_epoch=NOW,
            )

    def test_oidc_rejects_remote_key_selection_header(self) -> None:
        token = jwt.encode(
            {
                "iss": self.config.issuer,
                "sub": "oidc-subject-123",
                "aud": self.config.client_id,
                "iat": NOW - 30,
                "exp": NOW + 300,
                "nonce": "nonce-123",
                "acr": "urn:example:loa:2",
            },
            self.oidc_private,
            algorithm="EdDSA",
            headers={"kid": "oidc-key-1", "jku": "https://attacker.invalid/jwks"},
        )
        with self.assertRaises(OidcIdentityError):
            verify_oidc_identity(
                token,
                config=self.config,
                jwks=self.jwks,
                human_owner_id="owner-123",
                expected_subject="oidc-subject-123",
                expected_nonce="nonce-123",
                now_epoch=NOW,
            )

    def test_workload_identity_signature_verifies(self) -> None:
        signed = self._signed_workload()
        statement = verify_workload_identity(signed, trust_bundle=self.trust_bundle, now=NOW_TEXT)
        self.assertEqual(statement.agent_id, "ops-assistant")

    def test_workload_identity_rejects_disabled_key(self) -> None:
        disabled = WorkloadIdentityTrustBundle(
            institution_id="bank-demo",
            keys=(replace(self.trust_bundle.keys[0], status=TrustKeyStatus.DISABLED),),
        )
        with self.assertRaises(ValueError):
            # A bundle with no active key is invalid before verification.
            verify_workload_identity(self._signed_workload(), trust_bundle=disabled, now=NOW_TEXT)

    def test_workload_identity_rejects_tampered_statement(self) -> None:
        signed = self._signed_workload()
        tampered = replace(signed, statement=replace(signed.statement, workload_id="different-workload"))
        with self.assertRaises(WorkloadIdentityError):
            verify_workload_identity(tampered, trust_bundle=self.trust_bundle, now=NOW_TEXT)

    def test_binding_rejects_model_identity_mismatch(self) -> None:
        with self.assertRaises(IdentityBindingError):
            establish_authenticated_agent_identity(
                self.agent,
                human_identity=self._human(),
                workload_identity=self._signed_workload(model_id="different-model"),
                workload_trust_bundle=self.trust_bundle,
                established_at=NOW_TEXT,
            )

    def test_authenticated_policy_allows_only_with_current_bound_identity(self) -> None:
        engine = AuthenticatedPolicyEngine(AgentRegistry((self.agent,)), ToolRegistry((self.tool,)))
        decision = engine.evaluate(self._request(), self._policy(), self._identity(), evaluated_at=NOW_TEXT)
        self.assertTrue(decision.identity_verified)
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_authenticated_policy_denies_expired_identity(self) -> None:
        engine = AuthenticatedPolicyEngine(AgentRegistry((self.agent,)), ToolRegistry((self.tool,)))
        decision = engine.evaluate(
            self._request(),
            self._policy(),
            self._identity(),
            evaluated_at="2026-01-01T00:10:00Z",
        )
        self.assertFalse(decision.identity_verified)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertIn("authenticated_identity_expired_or_not_yet_valid", decision.authorization.reason_codes)

    def test_authenticated_policy_denies_after_agent_registration_changes(self) -> None:
        identity = self._identity()
        changed_agent = replace(self.agent, model_id="rotated-model")
        engine = AuthenticatedPolicyEngine(AgentRegistry((changed_agent,)), ToolRegistry((self.tool,)))
        decision = engine.evaluate(self._request(), self._policy(), identity, evaluated_at=NOW_TEXT)
        self.assertFalse(decision.identity_verified)
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertIn("authenticated_identity_agent_registration_changed", decision.authorization.reason_codes)


if __name__ == "__main__":
    unittest.main()
