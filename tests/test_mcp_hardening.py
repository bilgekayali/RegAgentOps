from __future__ import annotations

from dataclasses import replace
import unittest

import test_mcp as mcp_test_module

from regagentops.mcp import McpToolBinding
from regagentops.models import DataClassification, Decision, Environment, RiskTier
from regagentops.policy import PolicyBundle, PolicyRule


class McpHardeningTests(unittest.TestCase):
    def test_server_version_cannot_move_backward_in_time(self):
        _, registry, server, _, _, _ = mcp_test_module.McpGovernanceTests()._stack()
        with self.assertRaisesRegex(ValueError, "cannot predate"):
            registry.register_server(
                replace(
                    server,
                    server_version=2,
                    metadata_digest=mcp_test_module._digest("server-v2"),
                    registered_at="2026-01-01T00:03:59Z",
                )
            )

    def test_binding_cannot_predate_snapshot(self):
        _, registry, _, _, snapshot, binding = mcp_test_module.McpGovernanceTests()._stack()
        with self.assertRaisesRegex(ValueError, "cannot predate its governed tool snapshot"):
            registry.register_binding(
                McpToolBinding(
                    institution_id=binding.institution_id,
                    binding_id="predated-binding",
                    binding_version=1,
                    server_id=binding.server_id,
                    server_registration_digest=binding.server_registration_digest,
                    tool_snapshot_digest=binding.tool_snapshot_digest,
                    tool_descriptor_digest=binding.tool_descriptor_digest,
                    governed_tool_id=binding.governed_tool_id,
                    allowed_data_classifications=binding.allowed_data_classifications,
                    production_registered=binding.production_registered,
                    enabled=binding.enabled,
                    registered_at="2026-01-01T00:04:19Z",
                )
            )
        self.assertEqual(snapshot.captured_at, "2026-01-01T00:04:20Z")

    def test_pep_result_preserves_constraints_and_approval_flag(self):
        identity, registry, _, _, _, binding = mcp_test_module.McpGovernanceTests()._stack()
        request = mcp_test_module.McpGovernanceTests()._request(binding)
        constrained = PolicyBundle(
            institution_id="bank-demo",
            rules=(
                PolicyRule(
                    rule_id="mcp-constrained-read",
                    institution_id="bank-demo",
                    agent_id="ops-assistant",
                    tool_id=binding.governed_tool_id,
                    action="invoke",
                    business_purposes=("customer-support",),
                    environments=(Environment.TEST,),
                    data_classifications=(DataClassification.CONFIDENTIAL,),
                    risk_tiers=(RiskTier.MODERATE,),
                    effect=Decision.ALLOW_WITH_CONSTRAINTS,
                    constraints=("read-only",),
                ),
            ),
        )
        outcome = mcp_test_module.McpGovernanceTests()._pep(identity, registry).evaluate(
            request,
            constrained,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=mcp_test_module.NOW,
        )
        self.assertEqual(outcome.result.decision, Decision.ALLOW_WITH_CONSTRAINTS)
        self.assertEqual(outcome.result.constraints, ("read-only",))
        self.assertFalse(outcome.result.human_approval_required)
        self.assertTrue(outcome.result.execution_permitted)
        with self.assertRaisesRegex(ValueError, "continuation"):
            replace(outcome.result, execution_permitted=False)

    def test_high_risk_allow_still_requires_v03_approval_gate(self):
        identity, registry, _, _, _, binding = mcp_test_module.McpGovernanceTests()._stack()
        request = mcp_test_module.McpGovernanceTests()._request(binding, risk=RiskTier.HIGH)
        policy = mcp_test_module.McpGovernanceTests()._policy(
            binding,
            effect=Decision.ALLOW,
            risk=RiskTier.HIGH,
        )
        outcome = mcp_test_module.McpGovernanceTests()._pep(identity, registry).evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=mcp_test_module.NOW,
        )
        self.assertEqual(outcome.result.decision, Decision.ALLOW)
        self.assertTrue(outcome.result.identity_verified)
        self.assertEqual(outcome.result.risk_tier, RiskTier.HIGH)
        self.assertTrue(outcome.result.human_approval_required)
        self.assertFalse(outcome.result.execution_permitted)
        self.assertFalse(outcome.authorization.authorization.human_approval_required)

    def test_policy_required_approval_is_non_executable_before_resolution(self):
        identity, registry, _, _, _, binding = mcp_test_module.McpGovernanceTests()._stack()
        approval_request = mcp_test_module.McpGovernanceTests()._request(binding, risk=RiskTier.HIGH)
        approval_policy = mcp_test_module.McpGovernanceTests()._policy(
            binding,
            effect=Decision.REQUIRE_HUMAN_APPROVAL,
            risk=RiskTier.HIGH,
        )
        approval_outcome = mcp_test_module.McpGovernanceTests()._pep(identity, registry).evaluate(
            approval_request,
            approval_policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=mcp_test_module.NOW,
        )
        self.assertTrue(approval_outcome.result.human_approval_required)
        self.assertFalse(approval_outcome.result.execution_permitted)
        self.assertEqual(approval_outcome.result.constraints, ())


if __name__ == "__main__":
    unittest.main()
