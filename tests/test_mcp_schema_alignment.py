from __future__ import annotations

import json
from pathlib import Path
import unittest

import test_mcp as mcp_test_module

from regagentops.models import canonical_json


ROOT = Path(__file__).resolve().parents[1]


class McpSchemaAlignmentTests(unittest.TestCase):
    def _schema(self, filename: str) -> dict:
        return json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    def test_runtime_artifact_shapes_match_required_schema_properties(self):
        identity, registry, server, descriptor, snapshot, binding = mcp_test_module.McpGovernanceTests()._stack()
        outcome = mcp_test_module.McpGovernanceTests()._pep(identity, registry).evaluate(
            mcp_test_module.McpGovernanceTests()._request(binding),
            mcp_test_module.McpGovernanceTests()._policy(binding),
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=mcp_test_module.NOW,
        )
        cases = (
            (server, "mcp-server-registration.schema.json"),
            (descriptor, "mcp-tool-descriptor.schema.json"),
            (snapshot, "mcp-tool-snapshot.schema.json"),
            (binding, "mcp-tool-binding.schema.json"),
            (outcome.result, "mcp-policy-enforcement-result.schema.json"),
        )
        for artifact, filename in cases:
            with self.subTest(filename=filename):
                payload = json.loads(canonical_json(artifact))
                schema = self._schema(filename)
                self.assertEqual(set(payload), set(schema["required"]))
                self.assertTrue(set(payload).issubset(schema["properties"]))
                self.assertFalse(schema["additionalProperties"])

    def test_snapshot_embedded_descriptor_contract_matches_standalone_contract(self):
        snapshot_schema = self._schema("mcp-tool-snapshot.schema.json")
        descriptor_schema = self._schema("mcp-tool-descriptor.schema.json")
        embedded = snapshot_schema["properties"]["tools"]["items"]
        self.assertEqual(set(embedded["required"]), set(descriptor_schema["required"]))
        self.assertEqual(set(embedded["properties"]), set(descriptor_schema["properties"]))
        self.assertFalse(embedded["additionalProperties"])
        self.assertEqual(snapshot_schema["properties"]["tools"]["maxItems"], 128)

    def test_pep_schema_encodes_non_execution_and_decision_consistency(self):
        schema = self._schema("mcp-policy-enforcement-result.schema.json")
        self.assertEqual(schema["properties"]["execution_performed"]["const"], False)
        self.assertIn("constraints", schema["required"])
        self.assertIn("human_approval_required", schema["required"])
        self.assertEqual(len(schema["allOf"]), 4)
        decisions = {
            block["if"]["properties"]["decision"]["const"]
            for block in schema["allOf"]
        }
        self.assertEqual(
            decisions,
            {"ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL", "ALLOW_WITH_CONSTRAINTS"},
        )


if __name__ == "__main__":
    unittest.main()
