from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re

from .models import Environment, _require_text, _require_utc_timestamp, digest_artifact

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class AssuranceFramework(str, Enum):
    NIST_AI_RMF = "nist_ai_rmf"
    ISO_IEC_42001 = "iso_iec_42001"
    EU_AI_ACT = "eu_ai_act"


SUPPORTED_FRAMEWORK_VERSIONS: dict[AssuranceFramework, str] = {
    AssuranceFramework.NIST_AI_RMF: "1.0",
    AssuranceFramework.ISO_IEC_42001: "2023",
    AssuranceFramework.EU_AI_ACT: "2024/1689",
}


class EUAIActRole(str, Enum):
    PROVIDER = "provider"
    DEPLOYER = "deployer"
    AUTHORISED_REPRESENTATIVE = "authorised_representative"
    IMPORTER = "importer"
    DISTRIBUTOR = "distributor"
    PRODUCT_MANUFACTURER = "product_manufacturer"


class Applicability(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class EvidenceCoverage(str, Enum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


def _require_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _parse_time(name: str, value: str) -> datetime:
    _require_utc_timestamp(name, value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _require_sorted_unique_enum(name: str, values: tuple[Enum, ...], enum_type: type[Enum], *, allow_empty: bool = False) -> None:
    if not allow_empty and not values:
        raise ValueError(f"{name} must not be empty")
    if any(not isinstance(value, enum_type) for value in values):
        raise ValueError(f"{name} must contain governed enum values")
    if len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique")
    if tuple(sorted(values, key=lambda value: str(value.value))) != values:
        raise ValueError(f"{name} must be sorted")


def _require_framework_version(framework: AssuranceFramework, framework_version: str) -> None:
    if not isinstance(framework, AssuranceFramework):
        raise ValueError("framework must be governed")
    expected = SUPPORTED_FRAMEWORK_VERSIONS[framework]
    if framework_version != expected:
        raise ValueError(f"framework_version must be pinned to {expected} for {framework.value}")


@dataclass(frozen=True, slots=True)
class AssuranceScope:
    institution_id: str
    system_id: str
    deployment_id: str
    owner_human_id: str
    environment: Environment
    context_digest: str
    recorded_at: str
    schema_version: str = "regagentops.assurance-scope.v1"

    def __post_init__(self) -> None:
        for name in ("institution_id", "system_id", "deployment_id", "owner_human_id", "schema_version"):
            _require_text(name, getattr(self, name))
        if not isinstance(self.environment, Environment):
            raise ValueError("environment must be governed")
        _require_digest("context_digest", self.context_digest)
        _require_utc_timestamp("recorded_at", self.recorded_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AssuranceApplicabilityAssertion:
    assertion_id: str
    institution_id: str
    scope_digest: str
    framework: AssuranceFramework
    framework_version: str
    reference_id: str
    applicability: Applicability
    eu_ai_act_roles: tuple[EUAIActRole, ...]
    confirmation_basis: str
    confirmed_by_human_id: str
    confirmed_at: str
    schema_version: str = "regagentops.assurance-applicability-assertion.v1"

    def __post_init__(self) -> None:
        for name in ("assertion_id", "institution_id", "reference_id", "confirmation_basis", "confirmed_by_human_id", "schema_version"):
            _require_text(name, getattr(self, name), limit=1024 if name == "confirmation_basis" else 256)
        _require_digest("scope_digest", self.scope_digest)
        _require_framework_version(self.framework, self.framework_version)
        if not isinstance(self.applicability, Applicability):
            raise ValueError("applicability must be human-confirmed as applicable or not_applicable")
        _require_sorted_unique_enum("eu_ai_act_roles", self.eu_ai_act_roles, EUAIActRole, allow_empty=True)
        if self.framework is AssuranceFramework.EU_AI_ACT and not self.eu_ai_act_roles:
            raise ValueError("EU AI Act applicability requires at least one human-confirmed operator role")
        if self.framework is not AssuranceFramework.EU_AI_ACT and self.eu_ai_act_roles:
            raise ValueError("EU AI Act roles are only valid for EU AI Act applicability")
        _require_utc_timestamp("confirmed_at", self.confirmed_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AssuranceEvidenceReference:
    evidence_id: str
    institution_id: str
    scope_digest: str
    subject_artifact_digest: str
    artifact_type: str
    artifact_schema_version: str
    source_component: str
    recorded_at: str
    schema_version: str = "regagentops.assurance-evidence-reference.v1"

    def __post_init__(self) -> None:
        for name in (
            "evidence_id",
            "institution_id",
            "artifact_type",
            "artifact_schema_version",
            "source_component",
            "schema_version",
        ):
            _require_text(name, getattr(self, name))
        _require_digest("scope_digest", self.scope_digest)
        _require_digest("subject_artifact_digest", self.subject_artifact_digest)
        _require_utc_timestamp("recorded_at", self.recorded_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AssuranceCrosswalkEntry:
    entry_id: str
    institution_id: str
    scope_digest: str
    framework: AssuranceFramework
    framework_version: str
    reference_id: str
    applicability_assertion_digest: str
    coverage: EvidenceCoverage
    evidence_reference_digests: tuple[str, ...]
    mapping_rationale: str
    mapped_by_human_id: str
    mapped_at: str
    schema_version: str = "regagentops.assurance-crosswalk-entry.v1"

    def __post_init__(self) -> None:
        for name in ("entry_id", "institution_id", "reference_id", "mapping_rationale", "mapped_by_human_id", "schema_version"):
            _require_text(name, getattr(self, name), limit=1024 if name == "mapping_rationale" else 256)
        _require_digest("scope_digest", self.scope_digest)
        _require_digest("applicability_assertion_digest", self.applicability_assertion_digest)
        _require_framework_version(self.framework, self.framework_version)
        if not isinstance(self.coverage, EvidenceCoverage):
            raise ValueError("coverage must be governed")
        for value in self.evidence_reference_digests:
            _require_digest("evidence_reference_digest", value)
        if len(self.evidence_reference_digests) != len(set(self.evidence_reference_digests)):
            raise ValueError("evidence_reference_digests must be unique")
        if tuple(sorted(self.evidence_reference_digests)) != self.evidence_reference_digests:
            raise ValueError("evidence_reference_digests must be sorted")
        if self.coverage in {EvidenceCoverage.SUPPORTED, EvidenceCoverage.PARTIAL} and not self.evidence_reference_digests:
            raise ValueError("supported or partial coverage requires evidence references")
        if self.coverage in {EvidenceCoverage.GAP, EvidenceCoverage.NOT_APPLICABLE} and self.evidence_reference_digests:
            raise ValueError("gap or not_applicable coverage must not carry evidence references")
        _require_utc_timestamp("mapped_at", self.mapped_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AssuranceEvidencePackage:
    package_id: str
    institution_id: str
    scope_digest: str
    crosswalk_entry_digests: tuple[str, ...]
    applicability_assertion_digests: tuple[str, ...]
    evidence_reference_digests: tuple[str, ...]
    frameworks: tuple[AssuranceFramework, ...]
    assembled_by_human_id: str
    assembled_at: str
    certification_claimed: bool = False
    conformity_claimed: bool = False
    legal_compliance_determined: bool = False
    requires_human_review: bool = True
    schema_version: str = "regagentops.assurance-evidence-package.v1"

    def __post_init__(self) -> None:
        for name in ("package_id", "institution_id", "assembled_by_human_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_digest("scope_digest", self.scope_digest)
        for name, values, allow_empty in (
            ("crosswalk_entry_digests", self.crosswalk_entry_digests, False),
            ("applicability_assertion_digests", self.applicability_assertion_digests, False),
            ("evidence_reference_digests", self.evidence_reference_digests, True),
        ):
            for value in values:
                _require_digest(name[:-1], value)
            if not allow_empty and not values:
                raise ValueError(f"{name} must not be empty")
            if len(values) != len(set(values)) or tuple(sorted(values)) != values:
                raise ValueError(f"{name} must be unique and sorted")
        _require_sorted_unique_enum("frameworks", self.frameworks, AssuranceFramework)
        _require_utc_timestamp("assembled_at", self.assembled_at)
        if self.certification_claimed is not False:
            raise ValueError("assurance evidence packages cannot claim certification")
        if self.conformity_claimed is not False:
            raise ValueError("assurance evidence packages cannot claim conformity")
        if self.legal_compliance_determined is not False:
            raise ValueError("assurance evidence packages cannot determine legal compliance")
        if self.requires_human_review is not True:
            raise ValueError("assurance evidence packages always require human review")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class AssuranceEvidenceRegistry:
    """Append-only assurance crosswalk registry. It maps evidence; it never determines compliance or applicability."""

    def __init__(self) -> None:
        self._scopes: dict[tuple[str, str, str, str], AssuranceScope] = {}
        self._assertions: dict[tuple[str, str], AssuranceApplicabilityAssertion] = {}
        self._evidence: dict[tuple[str, str], AssuranceEvidenceReference] = {}
        self._entries: dict[tuple[str, str], AssuranceCrosswalkEntry] = {}
        self._packages: dict[tuple[str, str], AssuranceEvidencePackage] = {}

    @staticmethod
    def _same_or_conflict(existing, candidate, label: str) -> str:
        if existing.artifact_digest != candidate.artifact_digest:
            raise ValueError(f"{label} identity already exists with different content")
        return existing.artifact_digest

    def register_scope(self, scope: AssuranceScope) -> str:
        key = (scope.institution_id, scope.system_id, scope.deployment_id, scope.context_digest)
        existing = self._scopes.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, scope, "assurance scope")
        history = tuple(
            item
            for (institution_id, system_id, deployment_id, _), item in self._scopes.items()
            if institution_id == scope.institution_id
            and system_id == scope.system_id
            and deployment_id == scope.deployment_id
        )
        if history:
            latest = max(_parse_time("scope recorded_at", item.recorded_at) for item in history)
            if _parse_time("scope recorded_at", scope.recorded_at) < latest:
                raise ValueError("new assurance scope context cannot predate existing deployment scope history")
        self._scopes[key] = scope
        return scope.artifact_digest

    def _scope_by_digest(self, institution_id: str, scope_digest: str) -> AssuranceScope:
        for (scope_institution, _, _, _), scope in self._scopes.items():
            if scope_institution == institution_id and scope.artifact_digest == scope_digest:
                return scope
        raise ValueError("unknown assurance scope digest")

    def register_applicability(self, assertion: AssuranceApplicabilityAssertion) -> str:
        scope = self._scope_by_digest(assertion.institution_id, assertion.scope_digest)
        if _parse_time("confirmed_at", assertion.confirmed_at) < _parse_time("scope recorded_at", scope.recorded_at):
            raise ValueError("applicability confirmation cannot predate assurance scope")
        key = (assertion.institution_id, assertion.assertion_id)
        existing = self._assertions.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, assertion, "applicability assertion")
        conflict = tuple(
            item
            for (institution_id, _), item in self._assertions.items()
            if institution_id == assertion.institution_id
            and item.scope_digest == assertion.scope_digest
            and item.framework is assertion.framework
            and item.framework_version == assertion.framework_version
            and item.reference_id == assertion.reference_id
        )
        if conflict:
            raise ValueError("exact assurance scope/framework reference already has an applicability assertion")
        self._assertions[key] = assertion
        return assertion.artifact_digest

    def register_evidence(self, evidence: AssuranceEvidenceReference) -> str:
        scope = self._scope_by_digest(evidence.institution_id, evidence.scope_digest)
        if _parse_time("evidence recorded_at", evidence.recorded_at) < _parse_time("scope recorded_at", scope.recorded_at):
            raise ValueError("assurance evidence cannot predate assurance scope")
        key = (evidence.institution_id, evidence.evidence_id)
        existing = self._evidence.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, evidence, "assurance evidence reference")
        self._evidence[key] = evidence
        return evidence.artifact_digest

    def _assertion_by_digest(self, institution_id: str, digest: str) -> AssuranceApplicabilityAssertion:
        for (scope, _), assertion in self._assertions.items():
            if scope == institution_id and assertion.artifact_digest == digest:
                return assertion
        raise ValueError("unknown applicability assertion digest")

    def _evidence_by_digest(self, institution_id: str, digest: str) -> AssuranceEvidenceReference:
        for (scope, _), evidence in self._evidence.items():
            if scope == institution_id and evidence.artifact_digest == digest:
                return evidence
        raise ValueError("unknown assurance evidence reference digest")

    def _entry_by_digest(self, institution_id: str, digest: str) -> AssuranceCrosswalkEntry:
        for (scope, _), entry in self._entries.items():
            if scope == institution_id and entry.artifact_digest == digest:
                return entry
        raise ValueError("unknown assurance crosswalk entry digest")

    def register_entry(self, entry: AssuranceCrosswalkEntry) -> str:
        self._scope_by_digest(entry.institution_id, entry.scope_digest)
        assertion = self._assertion_by_digest(entry.institution_id, entry.applicability_assertion_digest)
        if (
            assertion.scope_digest != entry.scope_digest
            or assertion.framework is not entry.framework
            or assertion.framework_version != entry.framework_version
            or assertion.reference_id != entry.reference_id
        ):
            raise ValueError("crosswalk entry does not match the exact human applicability assertion")
        if _parse_time("mapped_at", entry.mapped_at) < _parse_time("confirmed_at", assertion.confirmed_at):
            raise ValueError("assurance mapping cannot predate applicability confirmation")
        if assertion.applicability is Applicability.NOT_APPLICABLE:
            if entry.coverage is not EvidenceCoverage.NOT_APPLICABLE:
                raise ValueError("not-applicable human assertion requires not_applicable coverage")
        elif entry.coverage is EvidenceCoverage.NOT_APPLICABLE:
            raise ValueError("applicable human assertion cannot be mapped as not_applicable")
        for digest in entry.evidence_reference_digests:
            evidence = self._evidence_by_digest(entry.institution_id, digest)
            if evidence.scope_digest != entry.scope_digest:
                raise ValueError("crosswalk evidence belongs to a different assurance scope")
            if _parse_time("mapped_at", entry.mapped_at) < _parse_time("evidence recorded_at", evidence.recorded_at):
                raise ValueError("assurance mapping cannot predate mapped evidence")
        key = (entry.institution_id, entry.entry_id)
        existing = self._entries.get(key)
        if existing is not None:
            return self._same_or_conflict(existing, entry, "assurance crosswalk entry")
        if any(
            institution_id == entry.institution_id
            and item.applicability_assertion_digest == entry.applicability_assertion_digest
            for (institution_id, _), item in self._entries.items()
        ):
            raise ValueError("exact applicability assertion already has a crosswalk entry")
        self._entries[key] = entry
        return entry.artifact_digest

    def snapshot_digest(self, institution_id: str) -> str:
        return digest_artifact({
            "institution_id": institution_id,
            "scopes": sorted(scope.artifact_digest for (scope_id, _, _, _), scope in self._scopes.items() if scope_id == institution_id),
            "applicability_assertions": sorted(item.artifact_digest for (scope_id, _), item in self._assertions.items() if scope_id == institution_id),
            "evidence_references": sorted(item.artifact_digest for (scope_id, _), item in self._evidence.items() if scope_id == institution_id),
            "crosswalk_entries": sorted(item.artifact_digest for (scope_id, _), item in self._entries.items() if scope_id == institution_id),
            "evidence_packages": sorted(item.artifact_digest for (scope_id, _), item in self._packages.items() if scope_id == institution_id),
        })

    def build_package(
        self,
        *,
        package_id: str,
        institution_id: str,
        scope_digest: str,
        crosswalk_entry_digests: tuple[str, ...],
        assembled_by_human_id: str,
        assembled_at: str,
    ) -> AssuranceEvidencePackage:
        self._scope_by_digest(institution_id, scope_digest)
        if not crosswalk_entry_digests:
            raise ValueError("assurance package requires at least one crosswalk entry")
        if len(crosswalk_entry_digests) != len(set(crosswalk_entry_digests)):
            raise ValueError("assurance package crosswalk entry digests must be unique")
        entries = tuple(self._entry_by_digest(institution_id, digest) for digest in crosswalk_entry_digests)
        if any(entry.scope_digest != scope_digest for entry in entries):
            raise ValueError("assurance package entries must belong to one exact scope")
        if any(_parse_time("assembled_at", assembled_at) < _parse_time("mapped_at", entry.mapped_at) for entry in entries):
            raise ValueError("assurance package cannot predate its crosswalk entries")
        entry_digests = tuple(sorted(entry.artifact_digest for entry in entries))
        assertion_digests = tuple(sorted({entry.applicability_assertion_digest for entry in entries}))
        evidence_digests = tuple(sorted({digest for entry in entries for digest in entry.evidence_reference_digests}))
        frameworks = tuple(sorted({entry.framework for entry in entries}, key=lambda value: value.value))
        package = AssuranceEvidencePackage(
            package_id=package_id,
            institution_id=institution_id,
            scope_digest=scope_digest,
            crosswalk_entry_digests=entry_digests,
            applicability_assertion_digests=assertion_digests,
            evidence_reference_digests=evidence_digests,
            frameworks=frameworks,
            assembled_by_human_id=assembled_by_human_id,
            assembled_at=assembled_at,
        )
        key = (institution_id, package_id)
        existing = self._packages.get(key)
        if existing is not None:
            if existing.artifact_digest != package.artifact_digest:
                raise ValueError("assurance evidence package identity already exists with different content")
            return existing
        self._packages[key] = package
        return package

    def verify_package(self, package: AssuranceEvidencePackage) -> None:
        self._scope_by_digest(package.institution_id, package.scope_digest)
        registered = self._packages.get((package.institution_id, package.package_id))
        if registered is not None and registered.artifact_digest != package.artifact_digest:
            raise ValueError("assurance evidence package does not match registered package identity")
        entries = tuple(self._entry_by_digest(package.institution_id, digest) for digest in package.crosswalk_entry_digests)
        if any(entry.scope_digest != package.scope_digest for entry in entries):
            raise ValueError("assurance package contains cross-scope entries")
        if any(_parse_time("assembled_at", package.assembled_at) < _parse_time("mapped_at", entry.mapped_at) for entry in entries):
            raise ValueError("assurance package predates its crosswalk entries")
        expected_assertions = tuple(sorted({entry.applicability_assertion_digest for entry in entries}))
        expected_evidence = tuple(sorted({digest for entry in entries for digest in entry.evidence_reference_digests}))
        expected_frameworks = tuple(sorted({entry.framework for entry in entries}, key=lambda value: value.value))
        if package.applicability_assertion_digests != expected_assertions:
            raise ValueError("assurance package applicability assertion set does not match its crosswalk entries")
        if package.evidence_reference_digests != expected_evidence:
            raise ValueError("assurance package evidence reference set does not match its crosswalk entries")
        if package.frameworks != expected_frameworks:
            raise ValueError("assurance package framework set does not match its crosswalk entries")
        for digest in package.applicability_assertion_digests:
            assertion = self._assertion_by_digest(package.institution_id, digest)
            if assertion.scope_digest != package.scope_digest:
                raise ValueError("assurance package applicability assertion belongs to a different scope")
        for digest in package.evidence_reference_digests:
            evidence = self._evidence_by_digest(package.institution_id, digest)
            if evidence.scope_digest != package.scope_digest:
                raise ValueError("assurance package evidence belongs to a different scope")
