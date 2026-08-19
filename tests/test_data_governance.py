from __future__ import annotations

from dataclasses import replace
import unittest

import test_mcp as mcp_test_module

from regagentops.approval_models import ApprovalEscalationPolicy
from regagentops.data_governance import (
    DataCategory,
    DataGovernanceRegistry,
    DataGovernedExecutionGate,
    DataPurposeMcpPolicyEnforcementPoint,
    DataResourceProfile,
    DataUseDeclaration,
    OutputHandling,
)
from regagentops.execution import EmergencyStopRegistry, EmergencyStopState, ExecutionGate, ExecutionLeaseLedger
from regagentops.models import DataClassification, Decision, RiskTier

NOW = mcp_test_module.NOW


class DataPurposeGovernanceTests(unittest.TestCase):
    def _stack(self, *, purpose="customer-support", risk=RiskTier.MODERATE, effect=Decision.ALLOW):
        case = mcp_test_module.McpGovernanceTests()
        identity, mcp, server, descriptor, snapshot, binding = case._stack()
        request = case._request(binding, risk=risk)
        if purpose != request.business_purpose:
            request = replace(request, business_purpose=purpose)
        policy = case._policy(binding, effect=effect, risk=risk)
        if purpose != "customer-support":
            policy = replace(policy, rules=(replace(policy.rules[0], business_purposes=(purpose,)),))
        data = DataGovernanceRegistry()
        profile = DataResourceProfile(
            institution_id="bank-demo",
            resource_id=request.resource,
            profile_version=1,
            data_classification=DataClassification.CONFIDENTIAL,
            data_categories=(DataCategory.FINANCIAL, DataCategory.PERSONAL),
            primary_purposes=("customer-support",),
            compatible_secondary_purposes=("fraud-investigation",),
            permitted_output_handling=(OutputHandling.REDACTED,),
            redaction_required_for=(DataCategory.FINANCIAL, DataCategory.PERSONAL),
            max_retention_seconds=3600,
            enabled=True,
            registered_at="2026-01-01T00:04:40Z",
        )
        data.register_profile(profile)
        declaration = DataUseDeclaration(
            institution_id="bank-demo",
            request_digest=request.artifact_digest,
            resource_id=request.resource,
            business_purpose=request.business_purpose,
            observed_data_categories=profile.data_categories,
            requested_output_handling=OutputHandling.RAW,
            retention_seconds=600,
            declared_at=NOW,
        )
        pep = DataPurposeMcpPolicyEnforcementPoint(case._pep(identity, mcp)._agents, mcp, data)
        outcome = pep.evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            data_use=declaration,
            evaluated_at=NOW,
        )
        return case, identity, mcp, binding, request, policy, data, profile, declaration, outcome

    def test_primary_purpose_sensitive_data_is_bound_as_authorization_evidence(self):
        *_, outcome = self._stack()
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.ALLOW_WITH_CONSTRAINTS)
        self.assertIsNotNone(outcome.data_governance)
        decision = outcome.data_governance
        self.assertIn("data:minimize", decision.constraints)
        self.assertIn("output:handling=redacted", decision.constraints)
        self.assertIn("retention:seconds=600", decision.constraints)
        self.assertIn(decision.artifact_digest, outcome.mcp_outcome.authorization.authorization.governance_evidence_digests)
        self.assertEqual(outcome.mcp_outcome.result.authenticated_authorization_digest, outcome.mcp_outcome.authorization.artifact_digest)

    def test_incompatible_purpose_fails_closed(self):
        stack = self._stack(purpose="marketing")
        outcome = stack[-1]
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.DENY)
        self.assertEqual(outcome.data_governance.reason_codes, ("purpose_not_compatible_with_resource",))
        self.assertFalse(outcome.mcp_outcome.result.execution_permitted)

    def test_compatible_secondary_purpose_is_explicitly_constrained(self):
        stack = self._stack(purpose="fraud-investigation")
        decision = stack[-1].data_governance
        self.assertEqual(decision.decision, Decision.ALLOW_WITH_CONSTRAINTS)
        self.assertIn("purpose:compatible-secondary-use", decision.constraints)

    def test_data_category_under_reporting_fails_closed(self):
        stack = self._stack()
        request, policy, data, declaration = stack[4], stack[5], stack[6], stack[8]
        identity, mcp = stack[1], stack[2]
        bad = replace(declaration, observed_data_categories=(DataCategory.FINANCIAL,))
        pep = DataPurposeMcpPolicyEnforcementPoint(stack[0]._pep(identity, mcp)._agents, mcp, data)
        outcome = pep.evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            data_use=bad,
            evaluated_at=NOW,
        )
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.DENY)
        self.assertEqual(outcome.data_governance.reason_codes, ("data_category_profile_mismatch",))

    def test_retention_above_profile_ceiling_fails_closed(self):
        stack = self._stack()
        request, policy, data, declaration = stack[4], stack[5], stack[6], stack[8]
        identity, mcp = stack[1], stack[2]
        excessive = replace(declaration, retention_seconds=3601)
        outcome = DataPurposeMcpPolicyEnforcementPoint(stack[0]._pep(identity, mcp)._agents, mcp, data).evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            data_use=excessive,
            evaluated_at=NOW,
        )
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.DENY)
        self.assertEqual(outcome.data_governance.reason_codes, ("retention_exceeds_resource_policy",))

    def test_missing_data_use_context_denies_positive_base_authorization(self):
        stack = self._stack()
        request, policy, data = stack[4], stack[5], stack[6]
        identity, mcp = stack[1], stack[2]
        outcome = DataPurposeMcpPolicyEnforcementPoint(stack[0]._pep(identity, mcp)._agents, mcp, data).evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            data_use=None,
            evaluated_at=NOW,
        )
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.DENY)
        self.assertEqual(outcome.mcp_outcome.result.reason_codes, ("data_governance_context_missing",))

    def test_policy_required_approval_preserves_data_governance_evidence(self):
        stack = self._stack(risk=RiskTier.HIGH, effect=Decision.REQUIRE_HUMAN_APPROVAL)
        outcome = stack[-1]
        self.assertEqual(outcome.mcp_outcome.result.decision, Decision.REQUIRE_HUMAN_APPROVAL)
        self.assertTrue(outcome.mcp_outcome.result.human_approval_required)
        self.assertEqual(outcome.mcp_outcome.result.constraints, ())
        self.assertIn(outcome.data_governance.artifact_digest, outcome.mcp_outcome.authorization.authorization.governance_evidence_digests)
        requirement = mcp_test_module.ApprovalGate.build_requirement(
            stack[4],
            outcome.mcp_outcome.authorization,
            escalation_policy=ApprovalEscalationPolicy("bank-demo"),
            issued_at=NOW,
        )
        self.assertIsNotNone(requirement)

    def test_data_governance_drift_invalidates_execution_lease_path(self):
        stack = self._stack()
        mcp, request, data, profile, outcome = stack[2], stack[4], stack[6], stack[7], stack[9]
        stops = EmergencyStopRegistry()
        stops.register(EmergencyStopState("bank-demo", 1, False, None, "2026-01-01T00:04:50Z"))
        base_gate = ExecutionGate(mcp, stops, ExecutionLeaseLedger())
        gate = DataGovernedExecutionGate(base_gate, data)
        lease = gate.issue_lease(
            outcome,
            lease_id="data-governed-lease",
            executor_id="executor-1",
            issued_at="2026-01-01T00:05:01Z",
            expires_at="2026-01-01T00:06:01Z",
        )
        data.register_profile(replace(
            profile,
            profile_version=2,
            max_retention_seconds=300,
            registered_at="2026-01-01T00:05:02Z",
        ))
        with self.assertRaisesRegex(ValueError, "data governance state changed"):
            gate.redeem_lease(
                lease,
                outcome,
                executor_id="executor-1",
                consumed_at="2026-01-01T00:05:03Z",
            )
        self.assertEqual(lease.request_digest, request.artifact_digest)


if __name__ == "__main__":
    unittest.main()
