import json
from pathlib import Path
import subprocess
import sys
import unittest

import regagentops


ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(regagentops.__version__, "1.0.0")

    def test_json_schemas_are_parseable_and_version_pinned(self):
        expected = json.loads((ROOT / "compatibility" / "v1-schema-baseline.json").read_text(encoding="utf-8"))["schemas"]
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

    def test_hardening_contracts_pin_rls_kms_hsm_lifecycle_and_no_symmetric_key_material(self):
        rls = json.loads((ROOT / "schemas" / "postgres-rls-policy.schema.json").read_text())
        self.assertTrue(rls["properties"]["force_row_level_security"]["const"])
        key = json.loads((ROOT / "schemas" / "institution-crypto-key-reference.schema.json").read_text())
        self.assertEqual(key["properties"]["custody"]["enum"], ["kms", "hsm"])
        self.assertNotIn("private_key", key["properties"])
        self.assertNotIn("symmetric_key", key["properties"])
        lifecycle = json.loads((ROOT / "schemas" / "crypto-key-lifecycle-state.schema.json").read_text())
        self.assertEqual(lifecycle["properties"]["status"]["enum"], ["active", "retired", "disabled"])
        encrypted = json.loads((ROOT / "schemas" / "encrypted-governance-evidence.schema.json").read_text())
        self.assertEqual(encrypted["properties"]["algorithm"]["const"], "AES-256-GCM")

    def test_deployment_contracts_pin_default_deny_worker_isolation_and_release_evidence(self):
        egress = json.loads((ROOT / "schemas" / "egress-policy.schema.json").read_text())
        self.assertTrue(egress["properties"]["default_deny"]["const"])
        self.assertFalse(egress["properties"]["allow_wildcards"]["const"])
        self.assertFalse(egress["properties"]["allow_plaintext"]["const"])
        tools = json.loads((ROOT / "schemas" / "tool-allowlist-policy.schema.json").read_text())
        self.assertTrue(tools["properties"]["default_deny"]["const"])
        self.assertFalse(tools["properties"]["direct_tool_invocation_allowed"]["const"])
        worker = json.loads((ROOT / "schemas" / "isolated-policy-worker-profile.schema.json").read_text())
        self.assertTrue(worker["properties"]["run_as_non_root"]["const"])
        self.assertTrue(worker["properties"]["read_only_root_filesystem"]["const"])
        self.assertTrue(worker["properties"]["drop_all_linux_capabilities"]["const"])
        self.assertEqual(worker["properties"]["seccomp_profile"]["const"], "RuntimeDefault")
        self.assertFalse(worker["properties"]["direct_tool_invocation"]["const"])
        release = json.loads((ROOT / "schemas" / "deployment-release-manifest.schema.json").read_text())
        for field in ("codeql_evidence_digest", "provenance_attestation_digest", "checksum_manifest_digest"):
            self.assertIn(field, release["required"])

    def test_v1_contracts_pin_semver_review_responsibility_and_boundary_evidence(self):
        compatibility = json.loads((ROOT / "schemas" / "stable-compatibility-policy.schema.json").read_text())
        self.assertTrue(compatibility["properties"]["breaking_change_requires_major"]["const"])
        self.assertEqual(compatibility["properties"]["deprecation_min_minor_releases"]["minimum"], 2)

        review = json.loads((ROOT / "schemas" / "independent-security-review-checklist.schema.json").read_text())
        self.assertTrue(review["properties"]["reviewer_independence_confirmed"]["const"])
        self.assertEqual(review["properties"]["items"]["minItems"], 12)
        self.assertEqual(review["properties"]["items"]["maxItems"], 12)

        responsibility = json.loads((ROOT / "schemas" / "legal-accessibility-responsibility-scope.schema.json").read_text())
        self.assertFalse(responsibility["properties"]["legal_advice_provided"]["const"])
        self.assertFalse(responsibility["properties"]["regulatory_compliance_determined"]["const"])
        self.assertFalse(responsibility["properties"]["accessibility_conformance_claimed"]["const"])
        self.assertTrue(responsibility["properties"]["institution_legal_review_required"]["const"])

        stable = json.loads((ROOT / "schemas" / "stable-release-baseline.schema.json").read_text())
        self.assertEqual(stable["properties"]["boundary_evidence"]["minItems"], 9)
        self.assertEqual(stable["properties"]["boundary_evidence"]["maxItems"], 9)

        upgrade = json.loads((ROOT / "schemas" / "supported-upgrade-path.schema.json").read_text())
        self.assertIn("source_release_digest", upgrade["required"])
        self.assertIn("target_release_digest", upgrade["required"])
        self.assertTrue(upgrade["properties"]["backup_required"]["const"])
        self.assertFalse(upgrade["properties"]["breaking_changes_declared"]["const"])

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

    def test_contract_snapshot_cli_is_deterministic_and_non_executing(self):
        completed = subprocess.run(
            [sys.executable, "-m", "regagentops.cli", "contract-snapshot"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        baseline = json.loads((ROOT / "compatibility" / "v1-public-api.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["release_version"], "1.0.0")
        self.assertEqual(payload["stable_python_api_symbols"], baseline["python_api_symbols"])
        self.assertEqual(payload["stable_cli_commands"], baseline["cli_commands"])
        self.assertEqual(payload["json_schema_compatibility_baseline"], "v1")
        self.assertFalse(payload["execution_performed"])


if __name__ == "__main__":
    unittest.main()
