from dataclasses import replace
import unittest

import test_stability as fixtures
from regagentops.deployment import EgressDestination, EgressPolicy, EgressProtocol
from regagentops.stability import StableReleaseRegistry


class StableReleaseLifecycleHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.StableGovernanceReferenceTests(
            "test_stable_baseline_registers_only_with_exact_current_v09_to_v10_chain"
        )
        self.fixture.setUp()

    def test_independent_review_cannot_predate_exact_v1_target_release(self):
        review = replace(self.fixture.security_review, reviewed_at=fixtures.T1)
        baseline = replace(
            self.fixture.baseline,
            security_review_checklist_digest=review.artifact_digest,
        )
        with self.assertRaisesRegex(ValueError, "security review cannot predate"):
            self.fixture.register_baseline(baseline, security_review=review)

    def test_stable_baseline_cannot_predate_bound_readiness_evidence(self):
        baseline = replace(self.fixture.baseline, assembled_at=fixtures.T3)
        with self.assertRaisesRegex(ValueError, "cannot predate its bound readiness evidence"):
            self.fixture.register_baseline(baseline)

    def test_registered_baseline_currentness_binds_exact_upgrade_path_and_fails_after_drift(self):
        registry = StableReleaseRegistry(self.fixture.production)
        registry.register_baseline(
            self.fixture.baseline,
            compatibility_policy=self.fixture.compatibility_policy,
            public_surface=self.fixture.public_surface,
            source_release=self.fixture.source_release,
            production_release=self.fixture.target_release,
            upgrade_path=self.fixture.upgrade_path,
            security_review=self.fixture.security_review,
            responsibility_scope=self.fixture.responsibility_scope,
        )
        registry.assert_baseline_current(
            self.fixture.baseline,
            source_release=self.fixture.source_release,
            production_release=self.fixture.target_release,
            upgrade_path=self.fixture.upgrade_path,
        )

        substituted_path = replace(self.fixture.upgrade_path, migration_plan_digest="f" * 64)
        with self.assertRaisesRegex(ValueError, "currentness upgrade path digest mismatch"):
            registry.assert_baseline_current(
                self.fixture.baseline,
                source_release=self.fixture.source_release,
                production_release=self.fixture.target_release,
                upgrade_path=substituted_path,
            )

        egress_v2 = EgressPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_version=2,
            allowed_destinations=(
                EgressDestination(
                    destination_id="kms-api-v2",
                    protocol=EgressProtocol.HTTPS,
                    host="kms2.bank.example",
                    port=443,
                    purpose="Rotated institution KMS adapter endpoint",
                    trust_policy_digest="d" * 64,
                ),
            ),
            default_deny=True,
            allow_wildcards=False,
            allow_plaintext=False,
            registered_at=fixtures.T4,
        )
        self.fixture.production.register_egress_policy(egress_v2)
        with self.assertRaisesRegex(ValueError, "egress policy is stale"):
            registry.assert_baseline_current(
                self.fixture.baseline,
                source_release=self.fixture.source_release,
                production_release=self.fixture.target_release,
                upgrade_path=self.fixture.upgrade_path,
            )


if __name__ == "__main__":
    unittest.main()
