from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

import test_identity as identity_test_module

from regagentops.approval_engine import ApprovalGate
from regagentops.approval_models import ApprovalEscalationPolicy
from regagentops.mcp import (
    MCP_MAX_TOOLS_PER_SNAPSHOT,
    McpGovernanceRegistry,
    McpPolicyEnforcementPoint,
    McpServerRegistration,
    McpToolBinding,
    McpToolDescriptor,
    McpToolSnapshot,
    McpTransportProfile,
)
from regagentops.models import (
    AgentActionEnvelope,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    digest_artifact,
)
from regagentops.policy import PolicyBundle, PolicyRule
from regagentops.registry import AgentRegistry

NOW = identity_test_module.NOW_TEXT


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class McpGovernanceTests(unittest.TestCase):
    def _stack(self):
        identity = identity_test_module.IdentityTests()
        identity.setUp()
        registry = McpGovernanceRegistry()
        server = McpServerRegistration(
            institution_id="bank-demo",
            server_id="finance-tools",
            server_version=1,
            expected_server_name="finance-mcp",
            transport_profile=McpTransportProfile.STDIO,
            server_identity_digest=_digest("finance-server-pin-v1"),
            metadata_digest=_digest("finance-server-metadata-v1"),
            approved=True,
            registered_at="2026-01-01T00:04:00Z",
        )
        registry.register_server(server)
        descriptor = McpToolDescriptor(
            institution_id="bank-demo",
            server_id=server.server_id,
            server_registration_digest=server.artifact_digest,
            name="customer.read",
            input_schema_digest=_digest("customer-read-input-schema"),
            output_schema_digest=_digest("customer-read-output-schema"),
            description_digest=_digest("read customer summary"),
            annotations_digest=_digest("readOnlyHint=true;destructiveHint=false"),
            raw_metadata_digest=_digest("customer-read-tool-metadata-v1"),
        )
        snapshot = McpToolSnapshot(
            institution_id="bank-demo",
            snapshot_id="finance-tools-snapshot-1",
            server_id=server.server_id,
            server_registration_digest=server.artifact_digest,
            observed_server_name=server.expected_server_name,
            observed_server_identity_digest=server.server_identity_digest,
            tools=(descriptor,),
            captured_at="2026-01-01T00:04:20Z",
        )
        registry.register_snapshot(snapshot)
        binding = McpToolBinding(
            institution_id="bank-demo",
            binding_id="finance-customer-read",
            binding_version=1,
            server_id=server.server_id,
            server_registration_digest=server.artifact_digest,
            tool_snapshot_digest=snapshot.artifact_digest,
            tool_descriptor_digest=descriptor.artifact_digest,
            governed_tool_id=registry.governed_tool_id(server.server_id, descriptor.name),
            allowed_data_classifications=(DataClassification.CONFIDENTIAL,),
            production_registered=False,
            enabled=True,
            registered_at="2026-01-01T00:04:30Z",
        )
        registry.register_binding(binding)
        return identity, registry, server, descriptor, snapshot, binding

    def _request(self, binding: McpToolBinding, *, environment=Environment.TEST, risk=RiskTier.MODERATE):
        return AgentActionEnvelope(
            request_id="mcp-req-1",
            institution_id="bank-demo",
            agent_id="ops-assistant",
            human_owner_id="owner-123",
            model_provider="example-provider",
            model_id="example-model",
            tool_id=binding.governed_tool_id,
            action="invoke",
            resource="customer/summary",
            data_classification=DataClassification.CONFIDENTIAL,
            business_purpose="customer-support",
            environment=environment,
            risk_tier=risk,
            input_digest=_digest("request-input"),
            requested_at=NOW,
        )

    def _policy(self, binding: McpToolBinding, *, environment=Environment.TEST, effect=Decision.ALLOW, risk=RiskTier.MODERATE):
        return PolicyBundle("bank-demo", (PolicyRule(
            rule_id="mcp-customer-read-policy",
            institution_id="bank-demo",
            agent_id="ops-assistant",
            tool_id=binding.governed_tool_id,
            action="invoke",
            business_purposes=("customer-support",),
            environments=(environment,),
            data_classifications=(DataClassification.CONFIDENTIAL,),
            risk_tiers=(risk,),
            effect=effect,
        ),))

    def _pep(self, identity, registry):
        return McpPolicyEnforcementPoint(AgentRegistry((identity.agent,)), registry)

    def test_authenticated_mcp_policy_enforcement_reuses_existing_engine_and_never_executes(self):
        identity, registry, _, _, _, binding = self._stack()
        request = self._request(binding)
        outcome = self._pep(identity, registry).evaluate(
            request,
            self._policy(binding),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertIsNotNone(outcome.authorization)
        self.assertTrue(outcome.result.identity_verified)
        self.assertEqual(outcome.result.decision, Decision.ALLOW)
        self.assertTrue(outcome.result.execution_permitted)
        self.assertFalse(outcome.result.execution_performed)
        self.assertEqual(outcome.result.authenticated_authorization_digest, outcome.authorization.artifact_digest)

    def test_human_approval_decision_continues_into_v03_approval_gate(self):
        identity, registry, _, _, _, binding = self._stack()
        request = self._request(binding, risk=RiskTier.HIGH)
        outcome = self._pep(identity, registry).evaluate(
            request,
            self._policy(binding, effect=Decision.REQUIRE_HUMAN_APPROVAL, risk=RiskTier.HIGH),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertEqual(outcome.result.decision, Decision.REQUIRE_HUMAN_APPROVAL)
        self.assertFalse(outcome.result.execution_permitted)
        self.assertIsNotNone(outcome.authorization)
        requirement = ApprovalGate.build_requirement(
            request,
            outcome.authorization,
            escalation_policy=ApprovalEscalationPolicy("bank-demo"),
            issued_at=NOW,
        )
        self.assertIsNotNone(requirement)
        self.assertEqual(requirement.tool_id, binding.governed_tool_id)
        self.assertEqual(requirement.authenticated_authorization_digest, outcome.authorization.artifact_digest)

    def test_untrusted_annotations_cannot_enable_production_or_override_policy(self):
        identity, registry, _, _, _, binding = self._stack()
        request = self._request(binding, environment=Environment.PRODUCTION)
        outcome = self._pep(identity, registry).evaluate(
            request,
            self._policy(binding, environment=Environment.PRODUCTION),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertEqual(outcome.result.decision, Decision.DENY)
        self.assertFalse(outcome.result.execution_permitted)
        self.assertIn("tool_not_registered_for_production", outcome.result.reason_codes)

    def test_tool_metadata_drift_stales_binding_until_explicit_rebinding(self):
        identity, registry, server, descriptor, _, binding = self._stack()
        changed = replace(
            descriptor,
            annotations_digest=_digest("readOnlyHint=false;destructiveHint=false"),
            raw_metadata_digest=_digest("customer-read-tool-metadata-v2"),
        )
        snapshot2 = McpToolSnapshot(
            institution_id="bank-demo",
            snapshot_id="finance-tools-snapshot-2",
            server_id=server.server_id,
            server_registration_digest=server.artifact_digest,
            observed_server_name=server.expected_server_name,
            observed_server_identity_digest=server.server_identity_digest,
            tools=(changed,),
            captured_at="2026-01-01T00:04:40Z",
        )
        registry.register_snapshot(snapshot2)
        with self.assertRaisesRegex(ValueError, "snapshot is stale"):
            registry.assert_binding_current(binding)

        denied = self._pep(identity, registry).evaluate(
            self._request(binding),
            self._policy(binding),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertEqual(denied.result.decision, Decision.DENY)
        self.assertIsNone(denied.authorization)
        self.assertIn("mcp_governance_precondition_failed", denied.result.reason_codes)

        binding2 = replace(
            binding,
            binding_version=2,
            tool_snapshot_digest=snapshot2.artifact_digest,
            tool_descriptor_digest=changed.artifact_digest,
            registered_at="2026-01-01T00:04:45Z",
        )
        registry.register_binding(binding2)
        allowed = self._pep(identity, registry).evaluate(
            self._request(binding2),
            self._policy(binding2),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertEqual(allowed.result.decision, Decision.ALLOW)

    def test_server_identity_pin_and_approval_state_fail_closed(self):
        identity, registry, server, descriptor, snapshot, binding = self._stack()
        bad_snapshot = replace(
            snapshot,
            snapshot_id="bad-pin",
            observed_server_identity_digest=_digest("attacker-pin"),
            captured_at="2026-01-01T00:04:35Z",
        )
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            registry.register_snapshot(bad_snapshot)

        revoked = replace(
            server,
            server_version=2,
            approved=False,
            metadata_digest=_digest("revoked-server-registration"),
            registered_at="2026-01-01T00:04:50Z",
        )
        registry.register_server(revoked)
        with self.assertRaisesRegex(ValueError, "stale or unapproved"):
            registry.assert_binding_current(binding)
        denied = self._pep(identity, registry).evaluate(
            self._request(binding),
            self._policy(binding),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=NOW,
        )
        self.assertEqual(denied.result.decision, Decision.DENY)
        self.assertIsNone(denied.authorization)

    def test_conflicting_latest_snapshots_and_bounded_ingestion_fail_closed(self):
        _, registry, server, descriptor, snapshot, _ = self._stack()
        first = replace(
            snapshot,
            snapshot_id="same-time-a",
            captured_at="2026-01-01T00:04:40Z",
        )
        second_descriptor = replace(
            descriptor,
            raw_metadata_digest=_digest("same-time-different-metadata"),
        )
        second = replace(
            snapshot,
            snapshot_id="same-time-b",
            tools=(second_descriptor,),
            captured_at="2026-01-01T00:04:40Z",
        )
        registry.register_snapshot(first)
        registry.register_snapshot(second)
        with self.assertRaisesRegex(ValueError, "conflicting latest"):
            registry.latest_snapshot("bank-demo", server.server_id)

        tools = tuple(
            replace(
                descriptor,
                name=f"tool-{index}",
                raw_metadata_digest=_digest(f"tool-{index}"),
            )
            for index in range(MCP_MAX_TOOLS_PER_SNAPSHOT + 1)
        )
        with self.assertRaisesRegex(ValueError, "cannot contain more than"):
            McpToolSnapshot(
                institution_id="bank-demo",
                snapshot_id="too-many-tools",
                server_id=server.server_id,
                server_registration_digest=server.artifact_digest,
                observed_server_name=server.expected_server_name,
                observed_server_identity_digest=server.server_identity_digest,
                tools=tools,
                captured_at="2026-01-01T00:04:55Z",
            )

        with self.assertRaisesRegex(ValueError, "duplicate tool names"):
            replace(snapshot, snapshot_id="duplicates", tools=(descriptor, descriptor))

    def test_tool_identity_is_namespaced_by_governed_server_id(self):
        _, registry, server, descriptor, _, _ = self._stack()
        server2 = replace(
            server,
            server_id="crm-tools",
            expected_server_name="crm-mcp",
            server_identity_digest=_digest("crm-server-pin"),
            metadata_digest=_digest("crm-server-metadata"),
        )
        registry.register_server(server2)
        self.assertNotEqual(
            registry.governed_tool_id(server.server_id, descriptor.name),
            registry.governed_tool_id(server2.server_id, descriptor.name),
        )

    def test_governed_types_reject_raw_enums_and_boolean_as_integer(self):
        with self.assertRaisesRegex(ValueError, "McpTransportProfile"):
            McpServerRegistration(
                "bank-demo", "bad", 1, "bad", "stdio", _digest("a"), _digest("b"), True, "2026-01-01T00:04:00Z"
            )
        identity, registry, server, descriptor, snapshot, binding = self._stack()
        with self.assertRaisesRegex(ValueError, "positive integer"):
            replace(binding, binding_version=True)
        with self.assertRaisesRegex(ValueError, "boolean"):
            replace(binding, production_registered=1)
        self.assertEqual(
            digest_artifact(registry.current_tool_registry("bank-demo")),
            digest_artifact(registry.current_tool_registry("bank-demo")),
        )


if __name__ == "__main__":
    unittest.main()
