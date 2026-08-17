import unittest

from regagentops.models import (
    AgentActionEnvelope,
    AgentDescriptor,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    ToolActionDescriptor,
)
from regagentops.policy import PolicyBundle, PolicyEngine, PolicyRule
from regagentops.registry import AgentRegistry, ToolRegistry


class PolicyEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = AgentDescriptor(
            institution_id="bank-a",
            agent_id="agent-1",
            human_owner_id="owner-1",
            model_provider="provider-a",
            model_id="model-a",
        )
        self.tool = ToolActionDescriptor(
            institution_id="bank-a",
            tool_id="customer-records",
            action="read-summary",
            allowed_data_classifications=(DataClassification.CONFIDENTIAL,),
            production_registered=False,
        )
        self.engine = PolicyEngine(AgentRegistry((self.agent,)), ToolRegistry((self.tool,)))

    def request(self, **overrides):
        values = dict(
            request_id="req-1",
            institution_id="bank-a",
            agent_id="agent-1",
            human_owner_id="owner-1",
            model_provider="provider-a",
            model_id="model-a",
            tool_id="customer-records",
            action="read-summary",
            resource="customer/summary",
            data_classification=DataClassification.CONFIDENTIAL,
            business_purpose="customer-support",
            environment=Environment.TEST,
            risk_tier=RiskTier.MODERATE,
            input_digest="1" * 64,
            requested_at="2026-01-01T00:00:00Z",
        )
        values.update(overrides)
        return AgentActionEnvelope(**values)

    def rule(self, effect=Decision.ALLOW, **overrides):
        values = dict(
            rule_id="rule-1",
            institution_id="bank-a",
            agent_id="agent-1",
            tool_id="customer-records",
            action="read-summary",
            business_purposes=("customer-support",),
            environments=(Environment.TEST,),
            data_classifications=(DataClassification.CONFIDENTIAL,),
            risk_tiers=(RiskTier.MODERATE,),
            effect=effect,
            constraints=(),
        )
        values.update(overrides)
        return PolicyRule(**values)

    def evaluate(self, request=None, rules=()):
        return self.engine.evaluate(
            request or self.request(),
            PolicyBundle("bank-a", tuple(rules)),
            evaluated_at="2026-01-01T00:00:01Z",
        )

    def test_default_deny_when_no_rule_matches(self):
        decision = self.evaluate(rules=())
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.reason_codes, ("default_deny_no_matching_rule",))
        self.assertFalse(decision.policy_permits_execution)

    def test_explicit_allow(self):
        decision = self.evaluate(rules=(self.rule(),))
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertTrue(decision.policy_permits_execution)

    def test_deny_overrides_allow(self):
        allow = self.rule(rule_id="allow")
        deny = self.rule(effect=Decision.DENY, rule_id="deny")
        decision = self.evaluate(rules=(allow, deny))
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.matched_rule_ids, ("allow", "deny"))

    def test_human_approval_overrides_allow(self):
        allow = self.rule(rule_id="allow")
        approval = self.rule(effect=Decision.REQUIRE_HUMAN_APPROVAL, rule_id="approval")
        decision = self.evaluate(rules=(allow, approval))
        self.assertEqual(decision.decision, Decision.REQUIRE_HUMAN_APPROVAL)
        self.assertTrue(decision.human_approval_required)
        self.assertFalse(decision.policy_permits_execution)

    def test_constraints_are_deterministically_merged(self):
        first = self.rule(
            effect=Decision.ALLOW_WITH_CONSTRAINTS,
            rule_id="b",
            constraints=("read-only",),
        )
        second = self.rule(
            effect=Decision.ALLOW_WITH_CONSTRAINTS,
            rule_id="a",
            constraints=("redact-sensitive-fields",),
        )
        decision = self.evaluate(rules=(first, second))
        self.assertEqual(decision.decision, Decision.ALLOW_WITH_CONSTRAINTS)
        self.assertEqual(decision.matched_rule_ids, ("a", "b"))
        self.assertEqual(decision.constraints, ("read-only", "redact-sensitive-fields"))

    def test_agent_identity_context_mismatch_fails_closed(self):
        request = self.request(model_id="different-model")
        decision = self.evaluate(request=request, rules=(self.rule(),))
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.reason_codes, ("agent_identity_context_mismatch",))

    def test_unregistered_production_use_fails_closed(self):
        request = self.request(environment=Environment.PRODUCTION)
        production_rule = self.rule(environments=(Environment.PRODUCTION,))
        decision = self.evaluate(request=request, rules=(production_rule,))
        self.assertEqual(decision.decision, Decision.DENY)
        self.assertEqual(decision.reason_codes, ("tool_not_registered_for_production",))

    def test_request_digest_is_stable(self):
        first = self.request()
        second = self.request()
        self.assertEqual(first.artifact_digest, second.artifact_digest)
        self.assertEqual(len(first.artifact_digest), 64)

    def test_duplicate_registry_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            AgentRegistry((self.agent, self.agent))

    def test_policy_bundle_rejects_cross_institution_rule(self):
        foreign = self.rule(institution_id="bank-b")
        with self.assertRaises(ValueError):
            PolicyBundle("bank-a", (foreign,))


if __name__ == "__main__":
    unittest.main()
