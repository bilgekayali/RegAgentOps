from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

from .deployment import DeploymentReleaseManifest, ProductionDeploymentRegistry
from .models import digest_artifact, _require_text, _require_utc_timestamp

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_PUBLIC_SYMBOL = re.compile(r"^regagentops\.api\.[A-Za-z_][A-Za-z0-9_]*$")
_CLI_COMMAND = re.compile(r"^[a-z][a-z0-9-]*$")

STABLE_VERSION = "1.0.0"
SUPPORTED_UPGRADE_SOURCE_SERIES = "0.9.x"


class GovernanceBoundary(str, Enum):
    AUTHORIZATION = "authorization"
    AUTHENTICATED_IDENTITY = "authenticated_identity"
    HUMAN_APPROVAL = "human_approval"
    MCP_GOVERNANCE = "mcp_governance"
    EXECUTION_RECEIPTS = "execution_receipts"
    DATA_PURPOSE = "data_purpose"
    ASSURANCE = "assurance"
    TENANT_CRYPTO = "tenant_crypto"
    PRODUCTION_REFERENCE = "production_reference"


REQUIRED_GOVERNANCE_BOUNDARIES = tuple(boundary for boundary in GovernanceBoundary)


class SecurityReviewStatus(str, Enum):
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"


REQUIRED_SECURITY_REVIEW_ITEMS = (
    "approval-replay-and-delegation",
    "assurance-non-claims",
    "authenticated-identity-binding",
    "authorization-default-deny",
    "capability-creep",
    "data-purpose-and-retention",
    "execution-lease-and-receipts",
    "mcp-server-tool-binding",
    "production-egress-tool-worker",
    "release-provenance-and-reproducibility",
    "tenant-isolation-and-crypto-lifecycle",
    "upgrade-rollback-and-recovery",
)


REQUIRED_V1_NON_CLAIMS = (
    "not-accessibility-conformance-certification",
    "not-autonomous-tool-execution-by-core",
    "not-certification-or-conformity-assessment",
    "not-deployed-rls-proof",
    "not-external-anchor-immutability-proof",
    "not-hardware-custody-proof",
    "not-legal-advice-or-legal-determination",
    "not-production-fitness-guarantee",
    "not-regulatory-compliance-determination",
)


def _require_digest(name: str, value: str | None, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_semver(name: str, value: str) -> None:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise ValueError(f"{name} must be strict MAJOR.MINOR.PATCH text")


def _require_positive_int(name: str, value: int, *, maximum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must not exceed {maximum}")


def _require_sorted_unique_text(name: str, values: tuple[str, ...]) -> None:
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{name} must contain non-empty text values")
    if len(values) != len(set(values)) or values != tuple(sorted(values)):
        raise ValueError(f"{name} must be unique and canonically sorted")


@dataclass(frozen=True, slots=True)
class StableCompatibilityPolicy:
    policy_id: str
    stable_since_version: str
    semver_required: bool
    breaking_change_requires_major: bool
    python_public_symbol_removal_requires_major: bool
    cli_command_removal_requires_major: bool
    json_schema_discriminator_change_requires_major: bool
    json_required_field_removal_requires_major: bool
    json_enum_value_removal_requires_major: bool
    unknown_json_fields_rejected: bool
    deprecation_min_minor_releases: int
    declared_at: str
    schema_version: str = "regagentops.stable-compatibility-policy.v1"

    def __post_init__(self) -> None:
        for name in ("policy_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_semver("stable_since_version", self.stable_since_version)
        if self.stable_since_version != STABLE_VERSION:
            raise ValueError("v1 compatibility policy must begin at 1.0.0")
        required_true = (
            "semver_required",
            "breaking_change_requires_major",
            "python_public_symbol_removal_requires_major",
            "cli_command_removal_requires_major",
            "json_schema_discriminator_change_requires_major",
            "json_required_field_removal_requires_major",
            "json_enum_value_removal_requires_major",
            "unknown_json_fields_rejected",
        )
        for name in required_true:
            if getattr(self, name) is not True:
                raise ValueError(f"stable compatibility policy requires {name}=true")
        _require_positive_int("deprecation_min_minor_releases", self.deprecation_min_minor_releases, maximum=12)
        if self.deprecation_min_minor_releases < 2:
            raise ValueError("public deprecations must remain for at least two minor releases")
        _require_utc_timestamp("declared_at", self.declared_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class PublicSurfaceManifest:
    release_version: str
    compatibility_policy_digest: str
    python_api_symbols: tuple[str, ...]
    cli_commands: tuple[str, ...]
    json_schema_baseline_digest: str
    generated_at: str
    schema_version: str = "regagentops.public-surface-manifest.v1"

    def __post_init__(self) -> None:
        _require_semver("release_version", self.release_version)
        if self.release_version != STABLE_VERSION:
            raise ValueError("v1 public surface manifest must describe 1.0.0")
        _require_digest("compatibility_policy_digest", self.compatibility_policy_digest)
        _require_digest("json_schema_baseline_digest", self.json_schema_baseline_digest)
        _require_sorted_unique_text("python_api_symbols", self.python_api_symbols)
        _require_sorted_unique_text("cli_commands", self.cli_commands)
        if any(_PUBLIC_SYMBOL.fullmatch(symbol) is None for symbol in self.python_api_symbols):
            raise ValueError("stable Python API symbols must be regagentops.api-qualified names")
        if any(_CLI_COMMAND.fullmatch(command) is None for command in self.cli_commands):
            raise ValueError("stable CLI commands must use lowercase command syntax")
        _require_utc_timestamp("generated_at", self.generated_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class BoundaryEvidenceReference:
    boundary: GovernanceBoundary
    artifact_digest: str
    evidence_description_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, GovernanceBoundary):
            raise ValueError("boundary evidence must use a governed boundary")
        _require_digest("artifact_digest", self.artifact_digest)
        _require_digest("evidence_description_digest", self.evidence_description_digest)


@dataclass(frozen=True, slots=True)
class SupportedUpgradePath:
    path_id: str
    source_series: str
    target_version: str
    migration_plan_digest: str
    preflight_check_digest: str
    post_upgrade_check_digest: str
    rollback_plan_digest: str
    backup_required: bool
    current_source_release_required: bool
    breaking_changes_declared: bool
    declared_at: str
    schema_version: str = "regagentops.supported-upgrade-path.v1"

    def __post_init__(self) -> None:
        for name in ("path_id", "schema_version"):
            _require_text(name, getattr(self, name))
        if self.source_series != SUPPORTED_UPGRADE_SOURCE_SERIES:
            raise ValueError("v1 supported upgrade source must be final 0.9.x series")
        _require_semver("target_version", self.target_version)
        if self.target_version != STABLE_VERSION:
            raise ValueError("v1 supported upgrade target must be 1.0.0")
        for name in (
            "migration_plan_digest",
            "preflight_check_digest",
            "post_upgrade_check_digest",
            "rollback_plan_digest",
        ):
            _require_digest(name, getattr(self, name))
        if self.backup_required is not True:
            raise ValueError("v1 upgrade path requires a verified backup")
        if self.current_source_release_required is not True:
            raise ValueError("v1 upgrade requires an exact current source release")
        if self.breaking_changes_declared is not False:
            raise ValueError("0.9.x to 1.0.0 supported path cannot declare an unbounded breaking migration")
        _require_utc_timestamp("declared_at", self.declared_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class SecurityReviewItem:
    item_id: str
    status: SecurityReviewStatus
    evidence_digest: str
    reviewer_rationale_digest: str
    risk_acceptance_human_id: str | None = None
    risk_acceptance_digest: str | None = None

    def __post_init__(self) -> None:
        _require_text("item_id", self.item_id)
        if not isinstance(self.status, SecurityReviewStatus):
            raise ValueError("security review status must be governed")
        _require_digest("evidence_digest", self.evidence_digest)
        _require_digest("reviewer_rationale_digest", self.reviewer_rationale_digest)
        if self.status is SecurityReviewStatus.CLOSED:
            if self.risk_acceptance_human_id is not None or self.risk_acceptance_digest is not None:
                raise ValueError("closed security-review items must not carry risk acceptance")
        else:
            _require_text("risk_acceptance_human_id", self.risk_acceptance_human_id)
            _require_digest("risk_acceptance_digest", self.risk_acceptance_digest)


@dataclass(frozen=True, slots=True)
class IndependentSecurityReviewChecklist:
    review_id: str
    release_version: str
    reviewer_id: str
    reviewer_independence_confirmed: bool
    items: tuple[SecurityReviewItem, ...]
    reviewed_at: str
    schema_version: str = "regagentops.independent-security-review-checklist.v1"

    def __post_init__(self) -> None:
        for name in ("review_id", "reviewer_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_semver("release_version", self.release_version)
        if self.release_version != STABLE_VERSION:
            raise ValueError("stable security review must target 1.0.0")
        if self.reviewer_independence_confirmed is not True:
            raise ValueError("stable release requires explicit independent-review confirmation")
        if any(not isinstance(item, SecurityReviewItem) for item in self.items):
            raise ValueError("security review checklist must contain SecurityReviewItem values")
        item_ids = tuple(item.item_id for item in self.items)
        if item_ids != REQUIRED_SECURITY_REVIEW_ITEMS:
            raise ValueError("security review checklist must contain the exact required item set in canonical order")
        _require_utc_timestamp("reviewed_at", self.reviewed_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class LegalAccessibilityResponsibilityScope:
    release_version: str
    legal_advice_provided: bool
    regulatory_compliance_determined: bool
    certification_claimed: bool
    accessibility_conformance_claimed: bool
    institution_legal_review_required: bool
    privacy_data_protection_review_required: bool
    accessibility_review_required: bool
    records_retention_review_required: bool
    jurisdiction_role_review_required: bool
    production_iam_review_required: bool
    explicit_non_claims: tuple[str, ...]
    declared_at: str
    schema_version: str = "regagentops.legal-accessibility-responsibility-scope.v1"

    def __post_init__(self) -> None:
        _require_semver("release_version", self.release_version)
        if self.release_version != STABLE_VERSION:
            raise ValueError("v1 responsibility scope must target 1.0.0")
        required_false = (
            "legal_advice_provided",
            "regulatory_compliance_determined",
            "certification_claimed",
            "accessibility_conformance_claimed",
        )
        for name in required_false:
            if getattr(self, name) is not False:
                raise ValueError(f"v1 responsibility scope requires {name}=false")
        required_true = (
            "institution_legal_review_required",
            "privacy_data_protection_review_required",
            "accessibility_review_required",
            "records_retention_review_required",
            "jurisdiction_role_review_required",
            "production_iam_review_required",
        )
        for name in required_true:
            if getattr(self, name) is not True:
                raise ValueError(f"v1 responsibility scope requires {name}=true")
        if self.explicit_non_claims != REQUIRED_V1_NON_CLAIMS:
            raise ValueError("v1 responsibility scope must retain the exact required non-claims")
        _require_utc_timestamp("declared_at", self.declared_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class StableReleaseBaseline:
    release_id: str
    release_version: str
    compatibility_policy_digest: str
    public_surface_manifest_digest: str
    production_release_manifest_digest: str
    supported_upgrade_path_digest: str
    security_review_checklist_digest: str
    responsibility_scope_digest: str
    reproducible_checksum_manifest_digest: str
    provenance_attestation_digest: str
    boundary_evidence: tuple[BoundaryEvidenceReference, ...]
    assembled_at: str
    schema_version: str = "regagentops.stable-release-baseline.v1"

    def __post_init__(self) -> None:
        for name in ("release_id", "schema_version"):
            _require_text(name, getattr(self, name))
        _require_semver("release_version", self.release_version)
        if self.release_version != STABLE_VERSION:
            raise ValueError("stable release baseline must target 1.0.0")
        for name in (
            "compatibility_policy_digest",
            "public_surface_manifest_digest",
            "production_release_manifest_digest",
            "supported_upgrade_path_digest",
            "security_review_checklist_digest",
            "responsibility_scope_digest",
            "reproducible_checksum_manifest_digest",
            "provenance_attestation_digest",
        ):
            _require_digest(name, getattr(self, name))
        if any(not isinstance(item, BoundaryEvidenceReference) for item in self.boundary_evidence):
            raise ValueError("stable baseline boundary_evidence must contain BoundaryEvidenceReference values")
        boundaries = tuple(item.boundary for item in self.boundary_evidence)
        if boundaries != REQUIRED_GOVERNANCE_BOUNDARIES:
            raise ValueError("stable baseline must bind every v0.1-v0.9 governance boundary in canonical order")
        if len({item.artifact_digest for item in self.boundary_evidence}) != len(self.boundary_evidence):
            raise ValueError("stable baseline boundary evidence digests must be unique")
        _require_utc_timestamp("assembled_at", self.assembled_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class StableReleaseRegistry:
    """Fail-closed v1 release readiness registry. It creates no tag, release, deployment, network call or tool execution."""

    def __init__(self, production_registry: ProductionDeploymentRegistry) -> None:
        if not isinstance(production_registry, ProductionDeploymentRegistry):
            raise ValueError("stable release registry requires ProductionDeploymentRegistry")
        self._production = production_registry
        self._baselines: dict[str, StableReleaseBaseline] = {}

    def register_baseline(
        self,
        baseline: StableReleaseBaseline,
        *,
        compatibility_policy: StableCompatibilityPolicy,
        public_surface: PublicSurfaceManifest,
        production_release: DeploymentReleaseManifest,
        upgrade_path: SupportedUpgradePath,
        security_review: IndependentSecurityReviewChecklist,
        responsibility_scope: LegalAccessibilityResponsibilityScope,
    ) -> str:
        existing = self._baselines.get(baseline.release_version)
        if existing is not None:
            if existing.artifact_digest != baseline.artifact_digest:
                raise ValueError("stable release version already exists with different baseline content")
            return existing.artifact_digest

        if compatibility_policy.artifact_digest != baseline.compatibility_policy_digest:
            raise ValueError("stable baseline compatibility policy digest mismatch")
        if public_surface.compatibility_policy_digest != compatibility_policy.artifact_digest:
            raise ValueError("public surface does not bind exact compatibility policy")
        if public_surface.artifact_digest != baseline.public_surface_manifest_digest:
            raise ValueError("stable baseline public surface digest mismatch")
        if production_release.release_version != STABLE_VERSION:
            raise ValueError("stable baseline requires a production release manifest for 1.0.0")
        if production_release.artifact_digest != baseline.production_release_manifest_digest:
            raise ValueError("stable baseline production release digest mismatch")
        self._production.assert_release_current(production_release)
        if upgrade_path.artifact_digest != baseline.supported_upgrade_path_digest:
            raise ValueError("stable baseline upgrade path digest mismatch")
        if security_review.artifact_digest != baseline.security_review_checklist_digest:
            raise ValueError("stable baseline security review digest mismatch")
        if responsibility_scope.artifact_digest != baseline.responsibility_scope_digest:
            raise ValueError("stable baseline responsibility scope digest mismatch")
        if baseline.provenance_attestation_digest != production_release.provenance_attestation_digest:
            raise ValueError("stable baseline provenance evidence must match exact production release")
        if baseline.reproducible_checksum_manifest_digest != production_release.checksum_manifest_digest:
            raise ValueError("stable baseline checksum evidence must match exact production release")
        production_boundary = next(
            item for item in baseline.boundary_evidence if item.boundary is GovernanceBoundary.PRODUCTION_REFERENCE
        )
        if production_boundary.artifact_digest != production_release.artifact_digest:
            raise ValueError("production-reference boundary evidence must bind exact release manifest")

        self._baselines[baseline.release_version] = baseline
        return baseline.artifact_digest

    def baseline(self, release_version: str = STABLE_VERSION) -> StableReleaseBaseline:
        try:
            return self._baselines[release_version]
        except KeyError as exc:
            raise ValueError("stable release baseline is not registered") from exc
