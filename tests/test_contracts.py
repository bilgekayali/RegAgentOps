import json
from pathlib import Path
import subprocess
import sys
import unittest

import regagentops


ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_package_version(self):
        self.assertEqual(regagentops.__version__, "0.2.0")

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
            "authenticated-authorization-decision.schema.json": "regagentops.authenticated-authorization-decision.v1",
        }
        for filename, discriminator in expected.items():
            payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(payload["properties"]["schema_version"]["const"], discriminator)
            self.assertFalse(payload["additionalProperties"])

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
