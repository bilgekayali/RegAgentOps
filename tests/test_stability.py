from dataclasses import replace
import json
from pathlib import Path
import unittest

import regagentops.api as stable_api
from regagentops.deployment import (
    DeploymentReleaseManifest,
    EgressDestination,
    EgressPolicy,
    EgressProtocol,
    IsolatedPolicyWorkerProfile,
    ProductionDeploymentRegistry,
    ToolAllowlistPolicy,
    ToolDispatchBinding,
)
from regagentops.hardening import PostgresRlsPolicy, TenantIsolationProfile, TenantIsolationRegistry
from regagentops.models import Environment, digest_artifact
from regagentops.stability import (
    BoundaryEvidenceReference,
    GovernanceBoundary,
    IndependentSecurityReviewChecklist,
    LegalAccessibilityResponsibilityScope,
    PublicSurfaceManifest,
    REQUIRED_SECURITY_REVIEW_ITEMS,
    REQUIRED_V1_NON_CLAIMS,
    SecurityReviewItem,
    SecurityReviewStatus,
    StableCompatibilityPolicy,
    StableReleaseBaseline,
    StableReleaseRegistry,
    SupportedUpgradePath,
)

ROOT = Path(__file__).resolve().parents[1]
T0 = "2026-08-19T15:10:00Z"
T1 = "2026-08-19T15:11:00Z"
T2 = "2026-08-19T15:12:00Z"
T3 = "2026-08-19T15:13:00Z"
T4 = "2026-08-19T15:14:00Z"


class StableGovernanceReferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_registry = TenantIsolationRegistry()
        self.rls = PostgresRlsPolicy(
            institution_id="bank-demo",
            policy_id="tenant-rls",
            policy_version=1,
            table_name="governance_evidence",
            policy_name="tenant_guard",
            institution_column="institution_id",
            tenant_column="tenant_id",
            institution_setting="regagentops.institution_id",
            tenant_setting="regagentops.tenant_id",
            force_row_level_security=True,
            registered_at=T0,
        )
        self.tenant_registry.register_policy(self.rls)
        self.tenant_profile = TenantIsolationProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            profile_version=1,
            environment=Environment.PRODUCTION,
            database_role="regagentops_worker",
            rls_policy_digests=(self.rls.artifact_digest,),
            registered_at=T0,
        )
        self.tenant_registry.register_profile(self.tenant_profile)
        self.production = ProductionDeploymentRegistry(tenant_isolation_registry=self.tenant_registry)

        self.egress = EgressPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_version=1,
            allowed_destinations=(
                EgressDestination(
                    destination_id="kms-api",
                    protocol=EgressProtocol.HTTPS,
                    host="kms.bank.example",
                    port=443,
                    purpose="Institution KMS adapter endpoint",
                    trust_policy_digest="1" * 64,
                ),
            ),
            default_deny=True,
            allow_wildcards=False,
            allow_plaintext=False,
            registered_at=T0,
        )
        self.tools = ToolAllowlistPolicy(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            policy_version=1,
            bindings=(
                ToolDispatchBinding(
                    governed_tool_id="mcp:payments:read",
                    executor_id="executor-a",
                    governance_binding_digest="2" * 64,
                ),
            ),
            default_deny=True,
            direct_tool_invocation_allowed=False,
            registered_at=T0,
        )
        self.production.register_egress_policy(self.egress)
        self.production.register_tool_allowlist(self.tools)
        self.worker = IsolatedPolicyWorkerProfile(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            worker_profile_version=1,
            worker_image_digest="3" * 64,
            service_account_id="regagentops-policy-worker",
            egress_policy_digest=self.egress.artifact_digest,
            tool_allowlist_policy_digest=self.tools.artifact_digest,
            tenant_isolation_profile_digest=self.tenant_profile.artifact_digest,
            network_namespace_isolated=True,
            run_as_non_root=True,
            read_only_root_filesystem=True,
            no_new_privileges=True,
            drop_all_linux_capabilities=True,
            seccomp_profile="RuntimeDefault",
            privileged=False,
            host_network=False,
            host_pid=False,
            host_ipc=False,
            direct_tool_invocation=False,
            registered_at=T0,
        )
        self.production.register_worker_profile(self.worker)

        self.source_release = self.make_release("release-090", "0.9.0", T1, commit="9" * 40, artifact_digit="4")
        self.target_release = self.make_release("release-100", "1.0.0", T2, commit="a" * 40, artifact_digit="5")
        self.production.register_release(self.source_release)
        self.production.register_release(self.target_release)

        self.compatibility_policy = StableCompatibilityPolicy(
            policy_id="v1-semver-policy",
            stable_since_version="1.0.0",
            semver_required=True,
            breaking_change_requires_major=True,
            python_public_symbol_removal_requires_major=True,
            cli_command_removal_requires_major=True,
            json_schema_discriminator_change_requires_major=True,
            json_required_field_removal_requires_major=True,
            json_enum_value_removal_requires_major=True,
            unknown_json_fields_rejected=True,
            deprecation_min_minor_releases=2,
            declared_at=T2,
        )
        public_api_baseline = json.loads((ROOT / "compatibility" / "v1-public-api.json").read_text(encoding="utf-8"))
        schema_baseline = json.loads((ROOT / "compatibility" / "v1-schema-baseline.json").read_text(encoding="utf-8"))
        self.public_surface = PublicSurfaceManifest(
            release_version="1.0.0",
            compatibility_policy_digest=self.compatibility_policy.artifact_digest,
            python_api_symbols=tuple(public_api_baseline["python_api_symbols"]),
            cli_commands=tuple(public_api_baseline["cli_commands"]),
            json_schema_baseline_digest=digest_artifact(schema_baseline),
            generated_at=T2,
        )
        self.upgrade_path = SupportedUpgradePath(
            path_id="v09-to-v10",
            source_series="0.9.x",
            source_release_digest=self.source_release.artifact_digest,
            target_version="1.0.0",
            target_release_digest=self.target_release.artifact_digest,
            migration_plan_digest="a" * 64,
            preflight_check_digest="b" * 64,
            post_upgrade_check_digest="c" * 64,
            rollback_plan_digest="d" * 64,
            backup_required=True,
            current_source_release_required=True,
            breaking_changes_declared=False,
            declared_at=T3,
        )
        self.security_review = self.make_security_review()
        self.responsibility_scope = LegalAccessibilityResponsibilityScope(
            release_version="1.0.0",
            legal_advice_provided=False,
            regulatory_compliance_determined=False,
            certification_claimed=False,
            accessibility_conformance_claimed=False,
            institution_legal_review_required=True,
            privacy_data_protection_review_required=True,
            accessibility_review_required=True,
            records_retention_review_required=True,
            jurisdiction_role_review_required=True,
            production_iam_review_required=True,
            explicit_non_claims=REQUIRED_V1_NON_CLAIMS,
            declared_at=T3,
        )
        self.baseline = self.make_baseline()

    def make_release(self, release_id, version, created_at, *, commit, artifact_digit):
        return DeploymentReleaseManifest(
            institution_id="bank-demo",
            tenant_id="tenant-a",
            release_id=release_id,
            release_version=version,
            source_commit_sha=commit,
            artifact_name=f"regagentops-{version}-py3-none-any.whl",
            artifact_sha256=artifact_digit * 64,
            worker_profile_digest=self.worker.artifact_digest,
            configuration_digest="6" * 64,
            codeql_evidence_digest="7" * 64,
            provenance_attestation_digest="8" * 64,
            checksum_manifest_digest="9" * 64,
            created_at=created_at,
        )

    def make_security_review(self, *, independence=True, items=None):
        if items is None:
            items = tuple(
                SecurityReviewItem(
                    item_id=item_id,
                    status=SecurityReviewStatus.CLOSED,
                    evidence_digest=f"{index + 20:064x}",
                    reviewer_rationale_digest=f"{index + 60:064x}",
                )
                for index, item_id in enumerate(REQUIRED_SECURITY_REVIEW_ITEMS)
            )
        return IndependentSecurityReviewChecklist(
            review_id="independent-v1-review",
            release_version="1.0.0",
            reviewer_id="independent-reviewer-001",
            reviewer_independence_confirmed=independence,
            items=items,
            reviewed_at=T4,
        )

    def make_boundary_evidence(self):
        result = []
        for index, boundary in enumerate(GovernanceBoundary, start=1):
            artifact_digest = f"{index:064x}"
            if boundary is GovernanceBoundary.PRODUCTION_REFERENCE:
                artifact_digest = self.target_release.artifact_digest
            result.append(
                BoundaryEvidenceReference(
                    boundary=boundary,
                    artifact_digest=artifact_digest,
                    evidence_description_digest=f"{index + 100:064x}",
                )
            )
        return tuple(result)

    def make_baseline(self):
        return StableReleaseBaseline(
            release_id="stable-regagentops-1.0.0",
            release_version="1.0.0",
            compatibility_policy_digest=self.compatibility_policy.artifact_digest,
            public_surface_manifest_digest=self.public_surface.artifact_digest,
            production_release_manifest_digest=self.target_release.artifact_digest,
            supported_upgrade_path_digest=self.upgrade_path.artifact_digest,
            security_review_checklist_digest=self.security_review.artifact_digest,
            responsibility_scope_digest=self.responsibility_scope.artifact_digest,
            reproducible_checksum_manifest_digest=self.target_release.checksum_manifest_digest,
            provenance_attestation_digest=self.target_release.provenance_attestation_digest,
            boundary_evidence=self.make_boundary_evidence(),
            assembled_at=T4,
        )

    def register_baseline(self, baseline=None, **overrides):
        registry = StableReleaseRegistry(self.production)
        kwargs = {
            "compatibility_policy": self.compatibility_policy,
            "public_surface": self.public_surface,
            "source_release": self.source_release,
            "production_release": self.target_release,
            "upgrade_path": self.upgrade_path,
            "security_review": self.security_review,
            "responsibility_scope": self.responsibility_scope,
        }
        kwargs.update(overrides)
        return registry.register_baseline(baseline or self.baseline, **kwargs)

    def test_public_api_and_cli_baseline_matches_runtime(self):
        baseline = json.loads((ROOT / "compatibility" / "v1-public-api.json").read_text(encoding="utf-8"))
        expected_symbols = [f"regagentops.api.{name}" for name in stable_api.__all__]
        self.assertEqual(expected_symbols, baseline["python_api_symbols"])
        self.assertEqual(baseline["cli_commands"], ["contract-snapshot", "demo-decision"])
        for name in stable_api.__all__:
            self.assertTrue(hasattr(stable_api, name), name)

    def test_json_schema_v1_baseline_is_present_and_discriminators_unchanged(self):
        baseline = json.loads((ROOT / "compatibility" / "v1-schema-baseline.json").read_text(encoding="utf-8"))
        for filename, discriminator in baseline["schemas"].items():
            payload = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
            self.assertEqual(payload["properties"]["schema_version"]["const"], discriminator)
            self.assertFalse(payload["additionalProperties"])

    def test_compatibility_policy_forbids_breaking_1x_removal_without_major(self):
        with self.assertRaisesRegex(ValueError, "python_public_symbol_removal_requires_major=true"):
            replace(self.compatibility_policy, python_public_symbol_removal_requires_major=False)
        with self.assertRaisesRegex(ValueError, "at least two minor releases"):
            replace(self.compatibility_policy, deprecation_min_minor_releases=1)

    def test_security_review_requires_independence_exact_items_and_accountable_risk_acceptance(self):
        with self.assertRaisesRegex(ValueError, "independent-review confirmation"):
            self.make_security_review(independence=False)
        with self.assertRaisesRegex(ValueError, "exact required item set"):
            self.make_security_review(items=self.security_review.items[:-1])
        with self.assertRaisesRegex(ValueError, "risk_acceptance_human_id"):
            SecurityReviewItem(
                item_id="authorization-default-deny",
                status=SecurityReviewStatus.RISK_ACCEPTED,
                evidence_digest="a" * 64,
                reviewer_rationale_digest="b" * 64,
            )
        accepted = SecurityReviewItem(
            item_id="authorization-default-deny",
            status=SecurityReviewStatus.RISK_ACCEPTED,
            evidence_digest="a" * 64,
            reviewer_rationale_digest="b" * 64,
            risk_acceptance_human_id="ciso-001",
            risk_acceptance_digest="c" * 64,
        )
        self.assertEqual(accepted.status, SecurityReviewStatus.RISK_ACCEPTED)

    def test_responsibility_scope_structurally_retains_v1_non_claims(self):
        with self.assertRaisesRegex(ValueError, "legal_advice_provided=false"):
            replace(self.responsibility_scope, legal_advice_provided=True)
        with self.assertRaisesRegex(ValueError, "exact required non-claims"):
            replace(self.responsibility_scope, explicit_non_claims=REQUIRED_V1_NON_CLAIMS[:-1])

    def test_stable_baseline_registers_only_with_exact_current_v09_to_v10_chain(self):
        digest = self.register_baseline()
        self.assertEqual(digest, self.baseline.artifact_digest)

    def test_stable_baseline_rejects_upgrade_source_or_target_substitution(self):
        wrong_source = replace(self.upgrade_path, source_release_digest="f" * 64)
        with self.assertRaisesRegex(ValueError, "source release digest mismatch"):
            self.register_baseline(upgrade_path=wrong_source)
        wrong_target = replace(self.upgrade_path, target_release_digest="e" * 64)
        with self.assertRaisesRegex(ValueError, "target release digest mismatch"):
            self.register_baseline(upgrade_path=wrong_target)

    def test_stable_baseline_rejects_missing_boundary_or_production_boundary_substitution(self):
        with self.assertRaisesRegex(ValueError, "every v0.1-v0.9 governance boundary"):
            replace(self.baseline, boundary_evidence=self.baseline.boundary_evidence[:-1])
        replaced_boundary = list(self.baseline.boundary_evidence)
        replaced_boundary[-1] = replace(replaced_boundary[-1], artifact_digest="f" * 64)
        tampered = replace(self.baseline, boundary_evidence=tuple(replaced_boundary))
        with self.assertRaisesRegex(ValueError, "production-reference boundary evidence"):
            self.register_baseline(tampered)

    def test_stable_baseline_rejects_provenance_and_checksum_substitution(self):
        with self.assertRaisesRegex(ValueError, "provenance evidence"):
            self.register_baseline(replace(self.baseline, provenance_attestation_digest="f" * 64))
        with self.assertRaisesRegex(ValueError, "checksum evidence"):
            self.register_baseline(replace(self.baseline, reproducible_checksum_manifest_digest="e" * 64))

    def test_stable_baseline_fails_closed_after_production_policy_drift(self):
        egress_v2 = replace(
            self.egress,
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
            registered_at=T4,
        )
        self.production.register_egress_policy(egress_v2)
        with self.assertRaisesRegex(ValueError, "egress policy is stale"):
            self.register_baseline()


if __name__ == "__main__":
    unittest.main()
