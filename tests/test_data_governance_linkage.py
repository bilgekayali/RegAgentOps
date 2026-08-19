from __future__ import annotations

from dataclasses import replace
import unittest

import test_data_governance as data_test_module

from regagentops.data_governance import DataPurposeMcpPolicyEnforcementOutcome


class DataGovernanceLinkageTests(unittest.TestCase):
    def test_legacy_mcp_outcome_cannot_be_paired_with_independent_data_decision(self):
        stack = data_test_module.DataPurposeGovernanceTests()._stack()
        case, identity, mcp, request, policy, governed = (
            stack[0], stack[1], stack[2], stack[4], stack[5], stack[9]
        )
        legacy = case._pep(identity, mcp).evaluate(
            request,
            policy,
            identity.signed_identity(),
            identity_trust_bundle=identity.trust,
            evaluated_at=data_test_module.NOW,
        )
        with self.assertRaisesRegex(ValueError, "not bound into authenticated authorization evidence"):
            DataPurposeMcpPolicyEnforcementOutcome(legacy, governed.data_governance)

    def test_tampered_data_decision_cannot_replace_bound_evidence(self):
        governed = data_test_module.DataPurposeGovernanceTests()._stack()[-1]
        tampered = replace(
            governed.data_governance,
            retention_seconds=599,
        )
        with self.assertRaisesRegex(ValueError, "not bound into authenticated authorization evidence"):
            DataPurposeMcpPolicyEnforcementOutcome(governed.mcp_outcome, tampered)


if __name__ == "__main__":
    unittest.main()
