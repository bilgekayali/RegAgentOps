import json
from pathlib import Path
import subprocess
import sys
import unittest

import regagentops


ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(regagentops.__version__, "0.8.0")

    def test_json_schemas_are_parseable_and_version_pinned(self):
        expected = {
            "agent-action-envelope.schema.json": "regagentops.agent-action-envelope.v1",
            "authorization-decision.schema.json": "regagentops.authorization-decision.v1",
            "policy-bundle.schema.json": "regagentops.policy-bundle.v1",
            "oidc-verifier-config.schema.json": "regagentops.oidc-verifier-config.v1",
            "human-identity-assertion.schema.json": "regagentops.human-identity-assertion.v1",
            "workload-identity-statement.schema.json": "regagentops.workload-identity-statement.v1",
            "workload-identity-trust-bundle.schema.json": "regagentops.workload-identity-trust-bundle.v1",
            "signed-workload-identity.schema.json": "regagentops.signed-workload-identity.v1",
            "authenticated-agent-identity.schema.json": "regagentops.authenticated-agent-identity.v1",
            "signed-authenticated-agent-identity.schema.json": "regagentops.signed-authenticated-agent-identity.v1",
            "authenticated-authorization-decision.schema.json": "regagentops.authenticated-authorization-decision.v1",
            "approval-authority-grant.schema.json": "regagentops.approval-authority-grant.v1",
            "approval-escalation-policy.schema.json": "regagentops.approval-escalation-policy.v1",
            "approval-requirement.schema.json": "regagentops.approval-requirement.v1",
            "approval-trust-bundle.schema.json": "regagentops.approval-trust-bundle.v1",
            "signed-approval-statement.schema.json": "regagentops.signed-approval-statement.v1",
            "signed-approval-package.schema.json": "regagentops.signed-approval-package.v1",
            "approval-resolution.schema.json": "regagentops.approval-resolution.v1",
            "mcp-server-registration.schema.json": "regagentops.mcp-server-registration.v1",
            "mcp-tool-descriptor.schema.json": "regagentops.mcp-tool-descriptor.v1",
            "mcp-tool-snapshot.schema.json": "regagentops.mcp-tool-snapshot.v1",
            "mcp-tool-binding.schema.json": "regagentops.mcp-tool-binding.v1",
            "mcp-policy-enforcement-result.schema.json": "regagentops.mcp-policy-enforcement-result.v1",
            "emergency-stop-state.schema.json": "regagentops.emergency-stop-state.v1",
            "execution-lease.schema.json": "regagentops.execution-lease.v1",
            "execution-lease-consumption.schema.json": "regagentops.execution-lease-consumption.v1",
            "execution-trust-bundle.schema.json": "regagentops.execution-trust-bundle.v1",
            "tool-execution-receipt.schema.json": "regagentops.tool-execution-receipt.v1",
            "signed-tool-execution-receipt.schema.json": "regagentops.signed-tool-execution-receipt.v1",
            "data-resource-profile.schema.json": "regagentops.data-resource-profile.v1",
            "data-use-declaration.schema.json": "regagentops.data-use-declaration.v1",
            "data-governance-decision.schema.json": "regagentops.data-governance-decision.v1",
            "assurance-scope.schema.json": "regagentops.assurance-scope.v1",
            "assurance-applicability-assertion.schema.json": "regagentops.assurance-applicability-assertion.v1",
            "assurance-evidence-reference.schema.json": "regagentops.assurance-evidence-reference.v1",
            "assurance-crosswalk-entry.schema.json": "regagentops.assurance-crosswalk-entry.v1",
            "assurance-evidence-package.schema.json": "regagentops.assurance-evidence-package.v1",
            "postgres-rls-policy.schema.json": "regagentops.postgres-rls-policy.v1",
            "tenant-isolation-profile.schema.json": "regagentops.tenant-isolation-profile.v1",
            "institution-crypto-key-reference.schema.json": "regagentops.institution-crypto-key-reference.v1",
            "configuration-change-request.schema.json": "regagentops.configuration-change-request.v1",
            "signed-configuration-change.schema.json": "regagentops.signed-configuration-change.v1",
            "encrypted-governance-evidence.schema.json": "regagentops.encrypted-governance-evidence.v1",
            "audit-anchor-batch.schema.json": "regagentops.audit-anchor-batch.v1",
            "external-audit-anchor-receipt.schema.json": "regagentops.external-audit-anchor-receipt.v1",
            "audit-anchor-record.schema.json": "regagentops.audit-anchor-record.v1",
        }
        for filename, discriminator in expected.items():
            payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(payload["properties"]["schema_version"]["const"], discriminator)
            self.assertFalse(payload["additionalProperties"])

    def test_authorization_contract_binds_governance_evidence(self):
        authorization = json.loads((ROOT / "schemas" / "authorization-decision.schema.json").read_text())
        self.assertIn("governance_evidence_digests", authorization["required"])
        authenticated = json.loads((ROOT / "schemas" / "authenticated-authorization-decision.schema.json").read_text())
        self.assertIn("governance_evidence_digests", authenticated["properties"]["authorization"]["required"])

    def test_assurance_package_contract_cannot_claim_certification_or_compliance(self):
        package = json.loads((ROOT / "schemas" / "assurance-evidence-package.schema.json").read_text())
        properties = package["properties"]
        self.assertFalse(properties["certification_claimed"]["const"])
        self.assertFalse(properties["conformity_claimed"]["const"])
        self.assertFalse(properties["legal_compliance_determined"]["const"])
        self.assertTrue(properties["requires_human_review"]["const"])

    def test_hardening_contracts_pin_rls_kms_hsm_and_no_symmetric_key_material(self):
        rls = json.loads((ROOT / "schemas" / "postgres-rls-policy.schema.json").read_text())
        self.assertTrue(rls["properties"]["force_row_level_security"]["const"])
        key = json.loads((ROOT / "schemas" / "institution-crypto-key-reference.schema.json").read_text())
        self.assertEqual(key["properties"]["custody"]["enum"], ["kms", "hsm"])
        self.assertNotIn("private_key", key["properties"])
        self.assertNotIn("symmetric_key", key["properties"])
        encrypted = json.loads((ROOT / "schemas" / "encrypted-governance-evidence.schema.json").read_text())
        self.assertEqual(encrypted["properties"]["algorithm"]["const"], "AES-256-GCM")

    def test_demo_cli_is_offline_and_non_executing(self):
        completed = subprocess.run(
            [sys.executable, "-m", "regagentops.cli", "demo-decision"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        self.assertFalse(payload["execution_performed"])
        self.assertEqual(payload["decision"]["decision"], "ALLOW_WITH_CONSTRAINTS")
        self.assertEqual(payload["decision"]["constraints"], ["read-only", "redact-sensitive-fields"])


if __name__ == "__main__":
    unittest.main()
