from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from regagentops.approval_authority import ApprovalAuthorityError, ApprovalAuthorityRegistry
from regagentops.approval_engine import ApprovalGate, ApprovalGateError, SignedApprovalPackage
from regagentops.approval_models import (
    ApprovalAuthorityBundle,
    ApprovalAuthorityGrant,
    ApprovalEscalationPolicy,
    ApprovalStatement,
    ApprovalVote,
    GrantType,
)
from regagentops.approval_replay import ApprovalReplayLedger
from regagentops.approval_signature import (
    ApprovalSigner,
    ApprovalTrustBundle,
    ApprovalTrustKey,
    sign_approval_statement,
)
from regagentops.authenticated_policy import AuthenticatedAuthorizationDecision
from regagentops.models import (
    AgentActionEnvelope,
    AuthorizationDecision,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
)

NOW = "2026-08-17T11:30:00Z"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class _Signer(ApprovalSigner):
    institution_id = "bank-demo"
    algorithm = "Ed25519"

    def __init__(self, principal_id: str, key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.principal_id = principal_id
        self.key_id = key_id
        self._key = private_key

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = AgentActionEnvelope(
            request_id="req-approval-1",
            institution_id="bank-demo",
            agent_id="ops-agent",
            human_owner_id="requester-1",
            model_provider="provider",
            model_id="model",
            tool_id="payments",
            action="release",
            resource="payment/123",
            data_classification=DataClassification.CONFIDENTIAL,
            business_purpose="payment-operations",
            environment=Environment.PRODUCTION,
            risk_tier=RiskTier.HIGH,
            input_digest="1" * 64,
            requested_at=NOW,
        )
        self.policy = ApprovalEscalationPolicy(institution_id="bank-demo")
        self.authz = self._authorization(Decision.ALLOW)

        self.root_grant = ApprovalAuthorityGrant(
            grant_id="grant-root",
            institution_id="bank-demo",
            issuer_principal_id="governance-root",
            subject_principal_id="manager-1",
            role_id="senior-approver",
            grant_type=GrantType.DIRECT,
            allowed_tool_ids=("payments", "customers"),
            allowed_actions=("release", "read"),
            allowed_environments=(Environment.TEST, Environment.PRODUCTION),
            max_risk_tier=RiskTier.CRITICAL,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            can_delegate=True,
        )
        self.delegated_grant = ApprovalAuthorityGrant(
            grant_id="grant-delegated",
            institution_id="bank-demo",
            issuer_principal_id="manager-1",
            subject_principal_id="approver-1",
            role_id="payment-approver",
            grant_type=GrantType.DELEGATED,
            allowed_tool_ids=("payments",),
            allowed_actions=("release",),
            allowed_environments=(Environment.PRODUCTION,),
            max_risk_tier=RiskTier.HIGH,
            valid_from="2026-06-01T00:00:00Z",
            valid_until="2026-12-31T00:00:00Z",
            parent_grant_digest=self.root_grant.artifact_digest,
        )
        self.approver2_grant = ApprovalAuthorityGrant(
            grant_id="grant-approver-2",
            institution_id="bank-demo",
            issuer_principal_id="governance-root",
            subject_principal_id="approver-2",
            role_id="senior-approver",
            grant_type=GrantType.DIRECT,
            allowed_tool_ids=("payments",),
            allowed_actions=("release",),
            allowed_environments=(Environment.PRODUCTION,),
            max_risk_tier=RiskTier.CRITICAL,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
        )
        self.authority = ApprovalAuthorityRegistry(
            ApprovalAuthorityBundle(
                institution_id="bank-demo",
                grants=(self.root_grant, self.delegated_grant, self.approver2_grant),
            )
        )

        self.keys: dict[str, Ed25519PrivateKey] = {
            "approver-1": Ed25519PrivateKey.generate(),
            "approver-2": Ed25519PrivateKey.generate(),
            "requester-1": Ed25519PrivateKey.generate(),
        }
        trust_keys = []
        for principal, private in self.keys.items():
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            trust_keys.append(
                ApprovalTrustKey(
                    institution_id="bank-demo",
                    principal_id=principal,
                    key_id=f"key-{principal}",
                    public_key_base64url=_b64url(public),
                    not_before="2026-01-01T00:00:00Z",
                    not_after="2027-01-01T00:00:00Z",
                )
            )
        self.trust = ApprovalTrustBundle(institution_id="bank-demo", keys=tuple(trust_keys))
        self.ledger = ApprovalReplayLedger()
        self.gate = ApprovalGate(authority_registry=self.authority, trust_bundle=self.trust, replay_ledger=self.ledger)

    def tearDown(self) -> None:
        self.ledger.close()

    def _authorization(self, decision: Decision) -> AuthenticatedAuthorizationDecision:
        nested = AuthorizationDecision(
            request_digest=self.request.artifact_digest,
            policy_bundle_digest="2" * 64,
            decision=decision,
            matched_rule_ids=("rule-1",),
            constraints=(),
            reason_codes=("test",),
            human_approval_required=decision is Decision.REQUIRE_HUMAN_APPROVAL,
            policy_permits_execution=decision is Decision.ALLOW,
            evaluated_at=NOW,
        )
        return AuthenticatedAuthorizationDecision(
            request_digest=self.request.artifact_digest,
            identity_context_digest="3" * 64,
            authorization=nested,
            identity_verified=True,
            evaluated_at=NOW,
        )

    def _requirement(self, request=None, authz=None):
        value = ApprovalGate.build_requirement(
            request or self.request,
            authz or self.authz,
            escalation_policy=self.policy,
            issued_at=NOW,
        )
        self.assertIsNotNone(value)
        return value

    def _signed_vote(self, requirement, principal: str, grant, vote=ApprovalVote.APPROVE):
        statement = ApprovalStatement(
            approval_id=f"approval-{principal}-{vote.value.lower()}",
            institution_id="bank-demo",
            requirement_digest=requirement.artifact_digest,
            request_digest=requirement.request_digest,
            approver_id=principal,
            authority_grant_digest=grant.artifact_digest,
            vote=vote,
            issued_at=NOW,
            expires_at="2026-08-17T11:40:00Z",
            rationale_digest=hashlib.sha256(b"reviewed").hexdigest(),
        )
        signer = _Signer(principal, f"key-{principal}", self.keys[principal])
        return sign_approval_statement(statement, signer=signer)

    def test_high_risk_allow_is_escalated_to_human_approval(self) -> None:
        requirement = self._requirement()
        self.assertEqual(requirement.min_approvals, 1)
        self.assertTrue(requirement.requester_separation_required)

    def test_critical_risk_requires_two_distinct_approvers(self) -> None:
        critical = replace(self.request, request_id="critical", risk_tier=RiskTier.CRITICAL)
        authz = replace(
            self.authz,
            request_digest=critical.artifact_digest,
            authorization=replace(self.authz.authorization, request_digest=critical.artifact_digest),
        )
        requirement = self._requirement(critical, authz)
        self.assertEqual(requirement.min_approvals, 2)

    def test_policy_human_approval_is_enforced_even_at_low_risk(self) -> None:
        low = replace(self.request, request_id="low", risk_tier=RiskTier.LOW, environment=Environment.TEST)
        authz = self._authorization(Decision.REQUIRE_HUMAN_APPROVAL)
        authz = replace(
            authz,
            request_digest=low.artifact_digest,
            authorization=replace(authz.authorization, request_digest=low.artifact_digest),
        )
        requirement = self._requirement(low, authz)
        self.assertEqual(requirement.min_approvals, 1)

    def test_deny_cannot_be_overridden_by_approval(self) -> None:
        with self.assertRaises(ApprovalGateError):
            self._requirement(authz=self._authorization(Decision.DENY))

    def test_delegation_cannot_widen_parent_scope(self) -> None:
        widened = replace(
            self.delegated_grant,
            grant_id="widened",
            allowed_tool_ids=("payments", "admin-console"),
        )
        with self.assertRaises(ApprovalAuthorityError):
            ApprovalAuthorityRegistry(
                ApprovalAuthorityBundle(institution_id="bank-demo", grants=(self.root_grant, widened))
            )

    def test_valid_signed_approval_satisfies_high_risk_requirement_once(self) -> None:
        requirement = self._requirement()
        package = SignedApprovalPackage(
            requirement=requirement,
            approvals=(self._signed_vote(requirement, "approver-1", self.delegated_grant),),
        )
        first = self.gate.resolve(self.request, self.authz, package, evaluated_at=NOW)
        self.assertTrue(first.approval_satisfied)
        self.assertTrue(first.authorization_continuation_permitted)
        self.assertEqual(first.approved_by, ("approver-1",))
        second = self.gate.resolve(self.request, self.authz, package, evaluated_at=NOW)
        self.assertFalse(second.approval_satisfied)
        self.assertIn("approval_requirement_already_redeemed", second.reason_codes)

    def test_critical_approval_is_not_consumed_until_threshold_is_met(self) -> None:
        critical = replace(self.request, request_id="critical-2", risk_tier=RiskTier.CRITICAL)
        authz = replace(
            self.authz,
            request_digest=critical.artifact_digest,
            authorization=replace(self.authz.authorization, request_digest=critical.artifact_digest),
        )
        requirement = self._requirement(critical, authz)
        one = SignedApprovalPackage(
            requirement=requirement,
            approvals=(self._signed_vote(requirement, "approver-2", self.approver2_grant),),
        )
        pending = self.gate.resolve(critical, authz, one, evaluated_at=NOW)
        self.assertFalse(pending.approval_satisfied)
        self.assertFalse(pending.replay_consumed)
        self.assertEqual(self.ledger.redemption_count(), 0)

        grant1_critical = replace(self.delegated_grant, grant_id="critical-approver-1", max_risk_tier=RiskTier.CRITICAL)
        authority = ApprovalAuthorityRegistry(
            ApprovalAuthorityBundle(
                institution_id="bank-demo",
                grants=(self.root_grant, grant1_critical, self.approver2_grant),
            )
        )
        gate = ApprovalGate(authority_registry=authority, trust_bundle=self.trust, replay_ledger=self.ledger)
        two = SignedApprovalPackage(
            requirement=requirement,
            approvals=(
                self._signed_vote(requirement, "approver-1", grant1_critical),
                self._signed_vote(requirement, "approver-2", self.approver2_grant),
            ),
        )
        resolved = gate.resolve(critical, authz, two, evaluated_at=NOW)
        self.assertTrue(resolved.approval_satisfied)
        self.assertEqual(resolved.approved_by, ("approver-1", "approver-2"))

    def test_valid_denial_consumes_requirement_and_blocks_alternative_package(self) -> None:
        requirement = self._requirement()
        denial = SignedApprovalPackage(
            requirement=requirement,
            approvals=(self._signed_vote(requirement, "approver-1", self.delegated_grant, ApprovalVote.DENY),),
        )
        denied = self.gate.resolve(self.request, self.authz, denial, evaluated_at=NOW)
        self.assertFalse(denied.approval_satisfied)
        self.assertTrue(denied.replay_consumed)
        self.assertEqual(denied.denied_by, ("approver-1",))

        approval = SignedApprovalPackage(
            requirement=requirement,
            approvals=(self._signed_vote(requirement, "approver-1", self.delegated_grant),),
        )
        replay = self.gate.resolve(self.request, self.authz, approval, evaluated_at=NOW)
        self.assertIn("approval_requirement_already_redeemed", replay.reason_codes)

    def test_requester_cannot_self_approve_high_risk_request(self) -> None:
        self_grant = ApprovalAuthorityGrant(
            grant_id="self-grant",
            institution_id="bank-demo",
            issuer_principal_id="governance-root",
            subject_principal_id="requester-1",
            role_id="approver",
            grant_type=GrantType.DIRECT,
            allowed_tool_ids=("payments",),
            allowed_actions=("release",),
            allowed_environments=(Environment.PRODUCTION,),
            max_risk_tier=RiskTier.HIGH,
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
        )
        authority = ApprovalAuthorityRegistry(
            ApprovalAuthorityBundle(institution_id="bank-demo", grants=(self_grant,))
        )
        gate = ApprovalGate(authority_registry=authority, trust_bundle=self.trust, replay_ledger=self.ledger)
        requirement = self._requirement()
        package = SignedApprovalPackage(
            requirement=requirement,
            approvals=(self._signed_vote(requirement, "requester-1", self_grant),),
        )
        decision = gate.resolve(self.request, self.authz, package, evaluated_at=NOW)
        self.assertFalse(decision.approval_satisfied)
        self.assertIn("approver_outside_delegated_authority", decision.reason_codes)

    def test_tampered_signed_approval_fails_closed(self) -> None:
        requirement = self._requirement()
        signed = self._signed_vote(requirement, "approver-1", self.delegated_grant)
        tampered = replace(signed, statement=replace(signed.statement, rationale_digest="0" * 64))
        decision = self.gate.resolve(
            self.request,
            self.authz,
            SignedApprovalPackage(requirement=requirement, approvals=(tampered,)),
            evaluated_at=NOW,
        )
        self.assertFalse(decision.approval_satisfied)
        self.assertIn("approval_signature_invalid", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
