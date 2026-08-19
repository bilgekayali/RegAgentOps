from dataclasses import replace
import unittest

from regagentops.assurance import (
    Applicability,
    AssuranceApplicabilityAssertion,
    AssuranceCrosswalkEntry,
    AssuranceEvidencePackage,
    AssuranceEvidenceReference,
    AssuranceEvidenceRegistry,
    AssuranceFramework,
    AssuranceScope,
    EUAIActRole,
    EvidenceCoverage,
)
from regagentops.models import Environment

BEFORE = "2026-08-19T10:59:59Z"
NOW = "2026-08-19T11:00:00Z"
AFTER = "2026-08-19T11:00:01Z"


class AssuranceEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AssuranceEvidenceRegistry()
        self.scope = AssuranceScope(
            institution_id="bank-demo",
            system_id="agent-platform",
            deployment_id="prod-eu-1",
            owner_human_id="owner-1",
            environment=Environment.PRODUCTION,
            context_digest="a" * 64,
            recorded_at=NOW,
        )
        self.registry.register_scope(self.scope)

    def assertion(
        self,
        *,
        assertion_id="assertion-1",
        framework=AssuranceFramework.NIST_AI_RMF,
        framework_version="1.0",
        reference_id="GOVERN 1.1",
        applicability=Applicability.APPLICABLE,
        roles=(),
        confirmed_at=NOW,
    ):
        return AssuranceApplicabilityAssertion(
            assertion_id=assertion_id,
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            framework=framework,
            framework_version=framework_version,
            reference_id=reference_id,
            applicability=applicability,
            eu_ai_act_roles=roles,
            confirmation_basis="Confirmed by the accountable system owner against the pinned framework version.",
            confirmed_by_human_id="owner-1",
            confirmed_at=confirmed_at,
        )

    def evidence(self, evidence_id="evidence-1", *, digest="b" * 64, scope_digest=None, recorded_at=NOW):
        return AssuranceEvidenceReference(
            evidence_id=evidence_id,
            institution_id="bank-demo",
            scope_digest=scope_digest or self.scope.artifact_digest,
            subject_artifact_digest=digest,
            artifact_type="AuthenticatedAuthorizationDecision",
            artifact_schema_version="regagentops.authenticated-authorization-decision.v1",
            source_component="authenticated_policy",
            recorded_at=recorded_at,
        )

    def entry(
        self,
        assertion,
        *,
        entry_id="entry-1",
        coverage=EvidenceCoverage.SUPPORTED,
        evidence_digests=(),
        mapped_at=NOW,
    ):
        return AssuranceCrosswalkEntry(
            entry_id=entry_id,
            institution_id="bank-demo",
            scope_digest=assertion.scope_digest,
            framework=assertion.framework,
            framework_version=assertion.framework_version,
            reference_id=assertion.reference_id,
            applicability_assertion_digest=assertion.artifact_digest,
            coverage=coverage,
            evidence_reference_digests=tuple(sorted(evidence_digests)),
            mapping_rationale="Exact RegAgentOps governance artifacts provide evidence relevant to this reference.",
            mapped_by_human_id="assurance-reviewer-1",
            mapped_at=mapped_at,
        )

    def test_framework_versions_are_explicitly_pinned(self):
        with self.assertRaisesRegex(ValueError, "pinned to 1.0"):
            self.assertion(framework_version="2.0")
        with self.assertRaisesRegex(ValueError, "pinned to 2023"):
            self.assertion(
                framework=AssuranceFramework.ISO_IEC_42001,
                framework_version="2026",
                reference_id="6.1",
            )
        with self.assertRaisesRegex(ValueError, "pinned to 2024/1689"):
            self.assertion(
                framework=AssuranceFramework.EU_AI_ACT,
                framework_version="2026/0001",
                reference_id="Article 26(2)",
                roles=(EUAIActRole.DEPLOYER,),
            )

    def test_human_confirmation_is_required(self):
        with self.assertRaisesRegex(ValueError, "confirmed_by_human_id"):
            replace(self.assertion(), confirmed_by_human_id="")

    def test_eu_ai_act_mapping_requires_human_confirmed_role(self):
        with self.assertRaisesRegex(ValueError, "operator role"):
            self.assertion(
                framework=AssuranceFramework.EU_AI_ACT,
                framework_version="2024/1689",
                reference_id="Article 26(2)",
            )
        assertion = self.assertion(
            framework=AssuranceFramework.EU_AI_ACT,
            framework_version="2024/1689",
            reference_id="Article 26(2)",
            roles=(EUAIActRole.DEPLOYER,),
        )
        self.assertEqual(assertion.eu_ai_act_roles, (EUAIActRole.DEPLOYER,))

    def test_non_eu_framework_rejects_eu_roles(self):
        with self.assertRaisesRegex(ValueError, "only valid for EU AI Act"):
            self.assertion(roles=(EUAIActRole.DEPLOYER,))

    def test_scope_history_allows_new_context_for_same_deployment(self):
        later_scope = replace(
            self.scope,
            context_digest="c" * 64,
            recorded_at=AFTER,
        )
        first_digest = self.scope.artifact_digest
        second_digest = self.registry.register_scope(later_scope)
        self.assertNotEqual(first_digest, second_digest)
        second_assertion = replace(
            self.assertion(assertion_id="assertion-second-context", confirmed_at=AFTER),
            scope_digest=second_digest,
        )
        self.registry.register_applicability(second_assertion)
        self.assertNotEqual(self.registry.snapshot_digest("bank-demo"), "0" * 64)

    def test_applicability_cannot_predate_scope(self):
        assertion = self.assertion(confirmed_at=BEFORE)
        with self.assertRaisesRegex(ValueError, "cannot predate assurance scope"):
            self.registry.register_applicability(assertion)

    def test_evidence_cannot_predate_scope(self):
        evidence = self.evidence(recorded_at=BEFORE)
        with self.assertRaisesRegex(ValueError, "cannot predate assurance scope"):
            self.registry.register_evidence(evidence)

    def test_mapping_cannot_predate_applicability_confirmation(self):
        assertion = self.assertion(confirmed_at=NOW)
        self.registry.register_applicability(assertion)
        entry = self.entry(assertion, coverage=EvidenceCoverage.GAP, mapped_at=BEFORE)
        with self.assertRaisesRegex(ValueError, "cannot predate applicability confirmation"):
            self.registry.register_entry(entry)

    def test_mapping_cannot_predate_mapped_evidence(self):
        assertion = self.assertion()
        evidence = self.evidence(recorded_at=AFTER)
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(
            assertion,
            evidence_digests=(evidence.artifact_digest,),
            mapped_at=NOW,
        )
        with self.assertRaisesRegex(ValueError, "cannot predate mapped evidence"):
            self.registry.register_entry(entry)

    def test_package_cannot_predate_crosswalk_entry(self):
        assertion = self.assertion()
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(
            assertion,
            evidence_digests=(evidence.artifact_digest,),
            mapped_at=AFTER,
        )
        self.registry.register_entry(entry)
        with self.assertRaisesRegex(ValueError, "cannot predate its crosswalk entries"):
            self.registry.build_package(
                package_id="early-package",
                institution_id="bank-demo",
                scope_digest=self.scope.artifact_digest,
                crosswalk_entry_digests=(entry.artifact_digest,),
                assembled_by_human_id="assurance-reviewer-1",
                assembled_at=NOW,
            )

    def test_nist_crosswalk_binds_exact_human_assertion_and_evidence(self):
        assertion = self.assertion()
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(assertion, evidence_digests=(evidence.artifact_digest,))
        self.registry.register_entry(entry)
        package = self.registry.build_package(
            package_id="package-1",
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            crosswalk_entry_digests=(entry.artifact_digest,),
            assembled_by_human_id="assurance-reviewer-1",
            assembled_at=NOW,
        )
        self.registry.verify_package(package)
        self.assertEqual(package.frameworks, (AssuranceFramework.NIST_AI_RMF,))
        self.assertEqual(package.evidence_reference_digests, (evidence.artifact_digest,))
        self.assertFalse(package.certification_claimed)
        self.assertFalse(package.legal_compliance_determined)
        self.assertTrue(package.requires_human_review)

    def test_iso_42001_evidence_mapping_is_supported_without_conformity_claim(self):
        assertion = self.assertion(
            framework=AssuranceFramework.ISO_IEC_42001,
            framework_version="2023",
            reference_id="6.1",
        )
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(assertion, evidence_digests=(evidence.artifact_digest,))
        self.registry.register_entry(entry)
        package = self.registry.build_package(
            package_id="iso-package",
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            crosswalk_entry_digests=(entry.artifact_digest,),
            assembled_by_human_id="assurance-reviewer-1",
            assembled_at=NOW,
        )
        self.assertEqual(package.frameworks, (AssuranceFramework.ISO_IEC_42001,))
        self.assertFalse(package.conformity_claimed)

    def test_eu_deployer_evidence_mapping_preserves_role_and_reference(self):
        assertion = self.assertion(
            framework=AssuranceFramework.EU_AI_ACT,
            framework_version="2024/1689",
            reference_id="Article 26(2)",
            roles=(EUAIActRole.DEPLOYER,),
        )
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(assertion, evidence_digests=(evidence.artifact_digest,))
        self.registry.register_entry(entry)
        self.assertEqual(entry.reference_id, "Article 26(2)")
        self.assertEqual(assertion.eu_ai_act_roles, (EUAIActRole.DEPLOYER,))

    def test_not_applicable_assertion_cannot_be_rewritten_as_gap_or_supported(self):
        assertion = self.assertion(applicability=Applicability.NOT_APPLICABLE)
        self.registry.register_applicability(assertion)
        gap = self.entry(assertion, coverage=EvidenceCoverage.GAP)
        with self.assertRaisesRegex(ValueError, "requires not_applicable coverage"):
            self.registry.register_entry(gap)
        na = self.entry(assertion, entry_id="entry-na", coverage=EvidenceCoverage.NOT_APPLICABLE)
        self.registry.register_entry(na)

    def test_applicable_assertion_cannot_be_mapped_not_applicable(self):
        assertion = self.assertion()
        self.registry.register_applicability(assertion)
        entry = self.entry(assertion, coverage=EvidenceCoverage.NOT_APPLICABLE)
        with self.assertRaisesRegex(ValueError, "cannot be mapped as not_applicable"):
            self.registry.register_entry(entry)

    def test_supported_or_partial_coverage_requires_evidence_and_gap_forbids_it(self):
        assertion = self.assertion()
        with self.assertRaisesRegex(ValueError, "requires evidence"):
            self.entry(assertion, coverage=EvidenceCoverage.SUPPORTED)
        evidence = self.evidence()
        with self.assertRaisesRegex(ValueError, "must not carry evidence"):
            self.entry(
                assertion,
                coverage=EvidenceCoverage.GAP,
                evidence_digests=(evidence.artifact_digest,),
            )

    def test_cross_scope_evidence_substitution_fails_closed(self):
        other_scope = AssuranceScope(
            institution_id="bank-demo",
            system_id="agent-platform",
            deployment_id="prod-us-1",
            owner_human_id="owner-1",
            environment=Environment.PRODUCTION,
            context_digest="c" * 64,
            recorded_at=NOW,
        )
        self.registry.register_scope(other_scope)
        assertion = self.assertion()
        foreign_evidence = self.evidence(scope_digest=other_scope.artifact_digest)
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(foreign_evidence)
        entry = self.entry(assertion, evidence_digests=(foreign_evidence.artifact_digest,))
        with self.assertRaisesRegex(ValueError, "different assurance scope"):
            self.registry.register_entry(entry)

    def test_package_detects_evidence_set_substitution(self):
        assertion = self.assertion()
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(assertion, evidence_digests=(evidence.artifact_digest,))
        self.registry.register_entry(entry)
        package = self.registry.build_package(
            package_id="package-1",
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            crosswalk_entry_digests=(entry.artifact_digest,),
            assembled_by_human_id="assurance-reviewer-1",
            assembled_at=NOW,
        )
        tampered = replace(package, evidence_reference_digests=("d" * 64,))
        with self.assertRaisesRegex(ValueError, "evidence reference set"):
            self.registry.verify_package(tampered)

    def test_package_verification_rejects_tampered_early_assembly_time(self):
        assertion = self.assertion()
        evidence = self.evidence()
        self.registry.register_applicability(assertion)
        self.registry.register_evidence(evidence)
        entry = self.entry(assertion, evidence_digests=(evidence.artifact_digest,), mapped_at=NOW)
        self.registry.register_entry(entry)
        package = self.registry.build_package(
            package_id="package-chronology",
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            crosswalk_entry_digests=(entry.artifact_digest,),
            assembled_by_human_id="assurance-reviewer-1",
            assembled_at=NOW,
        )
        tampered = replace(package, assembled_at=BEFORE)
        with self.assertRaisesRegex(ValueError, "predates its crosswalk entries"):
            self.registry.verify_package(tampered)

    def test_package_constructor_rejects_certification_conformity_or_legal_claims(self):
        values = dict(
            package_id="package-1",
            institution_id="bank-demo",
            scope_digest=self.scope.artifact_digest,
            crosswalk_entry_digests=("1" * 64,),
            applicability_assertion_digests=("2" * 64,),
            evidence_reference_digests=(),
            frameworks=(AssuranceFramework.NIST_AI_RMF,),
            assembled_by_human_id="assurance-reviewer-1",
            assembled_at=NOW,
        )
        with self.assertRaisesRegex(ValueError, "cannot claim certification"):
            AssuranceEvidencePackage(**values, certification_claimed=True)
        with self.assertRaisesRegex(ValueError, "cannot claim conformity"):
            AssuranceEvidencePackage(**values, conformity_claimed=True)
        with self.assertRaisesRegex(ValueError, "cannot determine legal compliance"):
            AssuranceEvidencePackage(**values, legal_compliance_determined=True)
        with self.assertRaisesRegex(ValueError, "always require human review"):
            AssuranceEvidencePackage(**values, requires_human_review=False)


if __name__ == "__main__":
    unittest.main()
