from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import re

from .approval_models import ApprovalRequirement, ApprovalResolution
from .authenticated_identity_signature import SignedAuthenticatedAgentIdentity
from .authenticated_policy import AuthenticatedAuthorizationDecision, AuthenticatedPolicyEngine
from .execution import ExecutionGate, ExecutionLease, ExecutionLeaseConsumption, ExecutionOutcome, ToolExecutionReceipt
from .identity_models import AuthenticatedAgentIdentity, WorkloadIdentityTrustBundle
from .mcp import McpGovernanceRegistry, McpPolicyEnforcementOutcome, McpPolicyEnforcementPoint, McpPolicyEnforcementResult
from .models import AgentActionEnvelope, DataClassification, Decision, RiskTier, _require_text, _require_utc_timestamp, digest_artifact
from .policy import PolicyBundle
from .registry import AgentRegistry

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RETENTION_SECONDS = 315_360_000
_HIGH_IMPACT_RISKS = {RiskTier.HIGH, RiskTier.CRITICAL}


def _require_digest(name: str, value: str | None, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _parse_time(name: str, value: str) -> datetime:
    _require_utc_timestamp(name, value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _require_retention(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_RETENTION_SECONDS:
        raise ValueError("retention_seconds must be between 0 and 315360000")


def _unique_sorted_text(name: str, values: tuple[str, ...]) -> None:
    if not values or len(values) != len(set(values)):
        raise ValueError(f"{name} must be non-empty and unique")
    if tuple(sorted(values)) != values:
        raise ValueError(f"{name} must be lexically sorted for canonical governance")
    for value in values:
        _require_text(name, value, limit=256)


def _unique_sorted_enum(name: str, values: tuple[Enum, ...], enum_type: type[Enum]) -> None:
    if not values or len(values) != len(set(values)):
        raise ValueError(f"{name} must be non-empty and unique")
    if any(not isinstance(value, enum_type) for value in values):
        raise ValueError(f"{name} must use governed enum values")
    if tuple(sorted(values, key=lambda value: str(value.value))) != values:
        raise ValueError(f"{name} must be sorted for canonical governance")


class DataCategory(str, Enum):
    PERSONAL = "personal"
    SENSITIVE_PERSONAL = "sensitive_personal"
    FINANCIAL = "financial"
    HEALTH = "health"
    BIOMETRIC = "biometric"
    CREDENTIAL = "credential"
    LOCATION = "location"
    CONFIDENTIAL_BUSINESS = "confidential_business"


class OutputHandling(str, Enum):
    RAW = "raw"
    REDACTED = "redacted"
    AGGREGATED = "aggregated"
    METADATA_ONLY = "metadata_only"


_SENSITIVE_CATEGORIES = {
    DataCategory.PERSONAL,
    DataCategory.SENSITIVE_PERSONAL,
    DataCategory.FINANCIAL,
    DataCategory.HEALTH,
    DataCategory.BIOMETRIC,
    DataCategory.CREDENTIAL,
    DataCategory.LOCATION,
}


@dataclass(frozen=True, slots=True)
class DataResourceProfile:
    institution_id: str
    resource_id: str
    profile_version: int
    data_classification: DataClassification
    data_categories: tuple[DataCategory, ...]
    primary_purposes: tuple[str, ...]
    compatible_secondary_purposes: tuple[str, ...]
    permitted_output_handling: tuple[OutputHandling, ...]
    redaction_required_for: tuple[DataCategory, ...]
    max_retention_seconds: int
    enabled: bool
    registered_at: str
    schema_version: str = "regagentops.data-resource-profile.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_text("resource_id", self.resource_id, limit=512)
        if isinstance(self.profile_version, bool) or not isinstance(self.profile_version, int) or self.profile_version <= 0:
            raise ValueError("profile_version must be a positive integer")
        if not isinstance(self.data_classification, DataClassification):
            raise ValueError("data_classification must be governed")
        _unique_sorted_enum("data_categories", self.data_categories, DataCategory)
        _unique_sorted_text("primary_purposes", self.primary_purposes)
        if self.compatible_secondary_purposes:
            if len(self.compatible_secondary_purposes) != len(set(self.compatible_secondary_purposes)):
                raise ValueError("compatible_secondary_purposes must be unique")
            if tuple(sorted(self.compatible_secondary_purposes)) != self.compatible_secondary_purposes:
                raise ValueError("compatible_secondary_purposes must be lexically sorted")
            for value in self.compatible_secondary_purposes:
                _require_text("compatible_secondary_purpose", value)
        if set(self.primary_purposes) & set(self.compatible_secondary_purposes):
            raise ValueError("primary and compatible secondary purposes must be disjoint")
        _unique_sorted_enum("permitted_output_handling", self.permitted_output_handling, OutputHandling)
        if self.redaction_required_for:
            if len(self.redaction_required_for) != len(set(self.redaction_required_for)):
                raise ValueError("redaction_required_for must be unique")
            if tuple(sorted(self.redaction_required_for, key=lambda value: value.value)) != self.redaction_required_for:
                raise ValueError("redaction_required_for must be sorted")
            if any(value not in self.data_categories for value in self.redaction_required_for):
                raise ValueError("redaction_required_for must be a subset of data_categories")
            if not ({OutputHandling.REDACTED, OutputHandling.AGGREGATED, OutputHandling.METADATA_ONLY} & set(self.permitted_output_handling)):
                raise ValueError("redaction-required profiles need a non-raw output handling mode")
        _require_retention(self.max_retention_seconds)
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        _require_utc_timestamp("registered_at", self.registered_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class DataUseDeclaration:
    institution_id: str
    request_digest: str
    resource_id: str
    business_purpose: str
    observed_data_categories: tuple[DataCategory, ...]
    requested_output_handling: OutputHandling
    retention_seconds: int
    declared_at: str
    schema_version: str = "regagentops.data-use-declaration.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_digest("request_digest", self.request_digest)
        _require_text("resource_id", self.resource_id, limit=512)
        _require_text("business_purpose", self.business_purpose, limit=512)
        _unique_sorted_enum("observed_data_categories", self.observed_data_categories, DataCategory)
        if not isinstance(self.requested_output_handling, OutputHandling):
            raise ValueError("requested_output_handling must be governed")
        _require_retention(self.retention_seconds)
        _require_utc_timestamp("declared_at", self.declared_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class DataGovernanceDecision:
    institution_id: str
    request_digest: str
    registry_snapshot_digest: str
    profile_digest: str | None
    declaration_digest: str
    business_purpose: str
    data_categories: tuple[DataCategory, ...]
    requested_output_handling: OutputHandling
    retention_seconds: int
    decision: Decision
    constraints: tuple[str, ...]
    reason_codes: tuple[str, ...]
    evaluated_at: str
    schema_version: str = "regagentops.data-governance-decision.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_digest("request_digest", self.request_digest)
        _require_digest("registry_snapshot_digest", self.registry_snapshot_digest)
        _require_digest("profile_digest", self.profile_digest, optional=True)
        _require_digest("declaration_digest", self.declaration_digest)
        _require_text("business_purpose", self.business_purpose, limit=512)
        _unique_sorted_enum("data_categories", self.data_categories, DataCategory)
        if not isinstance(self.requested_output_handling, OutputHandling):
            raise ValueError("requested_output_handling must be governed")
        _require_retention(self.retention_seconds)
        if self.decision not in {Decision.ALLOW, Decision.ALLOW_WITH_CONSTRAINTS, Decision.DENY}:
            raise ValueError("data governance decision must be ALLOW, ALLOW_WITH_CONSTRAINTS, or DENY")
        if len(self.constraints) != len(set(self.constraints)):
            raise ValueError("data governance constraints must be unique")
        if not self.reason_codes or len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("data governance reason_codes must be non-empty and unique")
        for value in (*self.constraints, *self.reason_codes):
            _require_text("data governance value", value)
        if self.decision is Decision.DENY and self.constraints:
            raise ValueError("data governance DENY must not carry execution constraints")
        if self.decision is Decision.ALLOW and self.constraints:
            raise ValueError("data governance ALLOW must not carry constraints")
        if self.decision is Decision.ALLOW_WITH_CONSTRAINTS and not self.constraints:
            raise ValueError("data governance ALLOW_WITH_CONSTRAINTS requires constraints")
        if self.decision is not Decision.DENY and self.profile_digest is None:
            raise ValueError("positive data governance decisions require an exact resource profile")
        _require_utc_timestamp("evaluated_at", self.evaluated_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class DataGovernanceRegistry:
    """Append-only resource-purpose governance metadata. No discovery or network capability."""

    def __init__(self) -> None:
        self._profiles: dict[tuple[str, str, int], DataResourceProfile] = {}

    def register_profile(self, profile: DataResourceProfile) -> str:
        key = (profile.institution_id, profile.resource_id, profile.profile_version)
        existing = self._profiles.get(key)
        if existing is not None:
            if existing.artifact_digest != profile.artifact_digest:
                raise ValueError("data resource profile identity/version already exists with different content")
            return existing.artifact_digest
        history = self.profile_history(profile.institution_id, profile.resource_id)
        expected = 1 if not history else history[-1].profile_version + 1
        if profile.profile_version != expected:
            raise ValueError(f"profile_version must be contiguous; expected version {expected}")
        if history and _parse_time("registered_at", profile.registered_at) < _parse_time("previous registered_at", history[-1].registered_at):
            raise ValueError("new data resource profile cannot predate the previous version")
        self._profiles[key] = profile
        return profile.artifact_digest

    def profile_history(self, institution_id: str, resource_id: str) -> tuple[DataResourceProfile, ...]:
        return tuple(sorted(
            (profile for (scope, resource, _), profile in self._profiles.items() if scope == institution_id and resource == resource_id),
            key=lambda profile: profile.profile_version,
        ))

    def current_profile(self, institution_id: str, resource_id: str) -> DataResourceProfile:
        history = self.profile_history(institution_id, resource_id)
        if not history:
            raise ValueError("data_resource_not_governed")
        profile = history[-1]
        if not profile.enabled:
            raise ValueError("data_resource_governance_disabled")
        return profile

    def snapshot_digest(self, institution_id: str) -> str:
        return digest_artifact({
            "institution_id": institution_id,
            "profiles": sorted(
                profile.artifact_digest
                for (scope, _, _), profile in self._profiles.items()
                if scope == institution_id
            ),
        })

    def _deny(self, request: AgentActionEnvelope, declaration: DataUseDeclaration, evaluated_at: str, reason: str, profile: DataResourceProfile | None = None) -> DataGovernanceDecision:
        return DataGovernanceDecision(
            institution_id=request.institution_id,
            request_digest=request.artifact_digest,
            registry_snapshot_digest=self.snapshot_digest(request.institution_id),
            profile_digest=profile.artifact_digest if profile else None,
            declaration_digest=declaration.artifact_digest,
            business_purpose=declaration.business_purpose,
            data_categories=declaration.observed_data_categories,
            requested_output_handling=declaration.requested_output_handling,
            retention_seconds=declaration.retention_seconds,
            decision=Decision.DENY,
            constraints=(),
            reason_codes=(reason,),
            evaluated_at=evaluated_at,
        )

    def evaluate(self, request: AgentActionEnvelope, declaration: DataUseDeclaration, *, evaluated_at: str) -> DataGovernanceDecision:
        _parse_time("evaluated_at", evaluated_at)
        if not isinstance(declaration, DataUseDeclaration):
            raise ValueError("data governance requires a DataUseDeclaration")
        if declaration.institution_id != request.institution_id:
            return self._deny(request, declaration, evaluated_at, "data_governance_institution_mismatch")
        if declaration.request_digest != request.artifact_digest:
            return self._deny(request, declaration, evaluated_at, "data_use_request_mismatch")
        if declaration.resource_id != request.resource:
            return self._deny(request, declaration, evaluated_at, "data_use_resource_mismatch")
        if declaration.business_purpose != request.business_purpose:
            return self._deny(request, declaration, evaluated_at, "data_use_purpose_mismatch")
        if _parse_time("declared_at", declaration.declared_at) < _parse_time("requested_at", request.requested_at):
            return self._deny(request, declaration, evaluated_at, "data_use_declaration_predates_request")
        if _parse_time("declared_at", declaration.declared_at) > _parse_time("evaluated_at", evaluated_at):
            return self._deny(request, declaration, evaluated_at, "data_use_declaration_from_future")
        try:
            profile = self.current_profile(request.institution_id, request.resource)
        except ValueError as exc:
            return self._deny(request, declaration, evaluated_at, str(exc))
        if request.data_classification is not profile.data_classification:
            return self._deny(request, declaration, evaluated_at, "data_classification_profile_mismatch", profile)
        if declaration.observed_data_categories != profile.data_categories:
            return self._deny(request, declaration, evaluated_at, "data_category_profile_mismatch", profile)
        constraints: list[str] = []
        reasons: list[str] = []
        if declaration.business_purpose in profile.primary_purposes:
            reasons.append("primary_purpose_permitted")
        elif declaration.business_purpose in profile.compatible_secondary_purposes:
            constraints.append("purpose:compatible-secondary-use")
            reasons.append("compatible_secondary_purpose_permitted")
        else:
            return self._deny(request, declaration, evaluated_at, "purpose_not_compatible_with_resource", profile)
        if declaration.retention_seconds > profile.max_retention_seconds:
            return self._deny(request, declaration, evaluated_at, "retention_exceeds_resource_policy", profile)
        constraints.append(
            "retention:no-persist" if declaration.retention_seconds == 0 else f"retention:seconds={declaration.retention_seconds}"
        )
        sensitive = set(profile.data_categories) & _SENSITIVE_CATEGORIES
        if sensitive:
            constraints.append("data:minimize")
        required_redaction = set(profile.redaction_required_for) & set(profile.data_categories)
        requested = declaration.requested_output_handling
        permitted = set(profile.permitted_output_handling)
        if required_redaction and requested is OutputHandling.RAW:
            if OutputHandling.REDACTED in permitted:
                constraints.append("output:handling=redacted")
            elif OutputHandling.AGGREGATED in permitted:
                constraints.append("output:handling=aggregated")
            elif OutputHandling.METADATA_ONLY in permitted:
                constraints.append("output:handling=metadata_only")
            else:
                return self._deny(request, declaration, evaluated_at, "redaction_required_but_no_safe_output_mode", profile)
            reasons.append("sensitive_output_transformation_required")
        else:
            if requested not in permitted:
                return self._deny(request, declaration, evaluated_at, "output_handling_not_permitted", profile)
            constraints.append(f"output:handling={requested.value}")
            reasons.append("output_handling_permitted")
        decision = Decision.ALLOW_WITH_CONSTRAINTS if constraints else Decision.ALLOW
        return DataGovernanceDecision(
            institution_id=request.institution_id,
            request_digest=request.artifact_digest,
            registry_snapshot_digest=self.snapshot_digest(request.institution_id),
            profile_digest=profile.artifact_digest,
            declaration_digest=declaration.artifact_digest,
            business_purpose=declaration.business_purpose,
            data_categories=declaration.observed_data_categories,
            requested_output_handling=declaration.requested_output_handling,
            retention_seconds=declaration.retention_seconds,
            decision=decision,
            constraints=tuple(sorted(set(constraints))),
            reason_codes=tuple(dict.fromkeys(reasons)),
            evaluated_at=evaluated_at,
        )

    def assert_decision_current(self, decision: DataGovernanceDecision) -> None:
        if decision.decision is Decision.DENY or decision.profile_digest is None:
            raise ValueError("denied data governance decision cannot authorize execution")
        if self.snapshot_digest(decision.institution_id) != decision.registry_snapshot_digest:
            raise ValueError("data governance state changed after authorization")
        profile = self.current_profile(decision.institution_id, self._resource_for_profile_digest(decision.institution_id, decision.profile_digest))
        if profile.artifact_digest != decision.profile_digest:
            raise ValueError("data resource profile changed after authorization")

    def _resource_for_profile_digest(self, institution_id: str, digest: str) -> str:
        for (scope, resource_id, _), profile in self._profiles.items():
            if scope == institution_id and profile.artifact_digest == digest:
                return resource_id
        raise ValueError("unknown data resource profile digest")


@dataclass(frozen=True, slots=True)
class DataGovernedAuthorizationOutcome:
    authorization: AuthenticatedAuthorizationDecision
    data_governance: DataGovernanceDecision | None


class DataGovernedAuthenticatedPolicyEngine:
    """Adds data-purpose guardrails to the existing authenticated policy decision without a second policy language."""

    def __init__(self, agents: AgentRegistry, tools, data_governance: DataGovernanceRegistry) -> None:
        self._base = AuthenticatedPolicyEngine(agents, tools)
        self._data = data_governance

    @staticmethod
    def _with_governance_evidence(
        authorization: AuthenticatedAuthorizationDecision,
        decision: DataGovernanceDecision,
    ) -> AuthenticatedAuthorizationDecision:
        base = authorization.authorization
        evidence = tuple(sorted(set((*base.governance_evidence_digests, decision.artifact_digest))))
        reasons = tuple(dict.fromkeys((*base.reason_codes, *decision.reason_codes)))
        if decision.decision is Decision.DENY:
            governed = replace(
                base,
                decision=Decision.DENY,
                constraints=(),
                reason_codes=decision.reason_codes,
                human_approval_required=False,
                policy_permits_execution=False,
                governance_evidence_digests=evidence,
            )
        elif base.decision is Decision.REQUIRE_HUMAN_APPROVAL:
            governed = replace(base, reason_codes=reasons, governance_evidence_digests=evidence)
        else:
            constraints = tuple(sorted(set((*base.constraints, *decision.constraints))))
            effect = Decision.ALLOW_WITH_CONSTRAINTS if constraints else base.decision
            governed = replace(
                base,
                decision=effect,
                constraints=constraints,
                reason_codes=reasons,
                governance_evidence_digests=evidence,
            )
        return replace(authorization, authorization=governed)

    def evaluate(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        identity: SignedAuthenticatedAgentIdentity | AuthenticatedAgentIdentity,
        *,
        identity_trust_bundle: WorkloadIdentityTrustBundle,
        data_use: DataUseDeclaration | None,
        evaluated_at: str,
    ) -> DataGovernedAuthorizationOutcome:
        base = self._base.evaluate(
            request,
            policy,
            identity,
            identity_trust_bundle=identity_trust_bundle,
            evaluated_at=evaluated_at,
        )
        if not base.identity_verified or base.decision is Decision.DENY:
            return DataGovernedAuthorizationOutcome(base, None)
        if data_use is None:
            denied = replace(
                base.authorization,
                decision=Decision.DENY,
                constraints=(),
                reason_codes=("data_governance_context_missing",),
                human_approval_required=False,
                policy_permits_execution=False,
            )
            return DataGovernedAuthorizationOutcome(replace(base, authorization=denied), None)
        data_decision = self._data.evaluate(request, data_use, evaluated_at=evaluated_at)
        return DataGovernedAuthorizationOutcome(
            self._with_governance_evidence(base, data_decision),
            data_decision,
        )


@dataclass(frozen=True, slots=True)
class DataPurposeMcpPolicyEnforcementOutcome:
    mcp_outcome: McpPolicyEnforcementOutcome
    data_governance: DataGovernanceDecision | None


class DataPurposeMcpPolicyEnforcementPoint:
    """v0.6 adapter that layers resource-purpose governance over the existing v0.4 MCP PEP."""

    def __init__(self, agents: AgentRegistry, mcp_registry: McpGovernanceRegistry, data_governance: DataGovernanceRegistry) -> None:
        self._base = McpPolicyEnforcementPoint(agents, mcp_registry)
        self._data = data_governance

    @staticmethod
    def _approval_required(authorization: AuthenticatedAuthorizationDecision, risk_tier: RiskTier) -> bool:
        if authorization.decision is Decision.DENY:
            return False
        return authorization.authorization.human_approval_required or risk_tier in _HIGH_IMPACT_RISKS

    def evaluate(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        identity: SignedAuthenticatedAgentIdentity | AuthenticatedAgentIdentity,
        *,
        identity_trust_bundle: WorkloadIdentityTrustBundle,
        data_use: DataUseDeclaration | None,
        evaluated_at: str,
    ) -> DataPurposeMcpPolicyEnforcementOutcome:
        base = self._base.evaluate(
            request,
            policy,
            identity,
            identity_trust_bundle=identity_trust_bundle,
            evaluated_at=evaluated_at,
        )
        if base.authorization is None or not base.authorization.identity_verified or base.result.decision is Decision.DENY:
            return DataPurposeMcpPolicyEnforcementOutcome(base, None)
        tools = self._base._mcp.current_tool_registry(request.institution_id)
        agents = self._base._agents
        governed = DataGovernedAuthenticatedPolicyEngine(agents, tools, self._data).evaluate(
            request,
            policy,
            identity,
            identity_trust_bundle=identity_trust_bundle,
            data_use=data_use,
            evaluated_at=evaluated_at,
        )
        authorization = governed.authorization
        approval_required = self._approval_required(authorization, request.risk_tier)
        result = replace(
            base.result,
            authenticated_authorization_digest=authorization.artifact_digest,
            identity_verified=authorization.identity_verified,
            decision=authorization.decision,
            constraints=authorization.authorization.constraints,
            reason_codes=authorization.authorization.reason_codes,
            human_approval_required=approval_required,
            execution_permitted=authorization.authorization.policy_permits_execution and not approval_required,
        )
        outcome = McpPolicyEnforcementOutcome(request, result, authorization)
        return DataPurposeMcpPolicyEnforcementOutcome(outcome, governed.data_governance)


class DataGovernedExecutionGate:
    """Revalidates v0.6 data governance at v0.5 lease issuance and redemption."""

    def __init__(self, execution_gate: ExecutionGate, data_governance: DataGovernanceRegistry) -> None:
        if not isinstance(execution_gate, ExecutionGate):
            raise ValueError("data-governed execution requires an ExecutionGate")
        self._base = execution_gate
        self._data = data_governance

    def _assert_current(self, outcome: DataPurposeMcpPolicyEnforcementOutcome) -> McpPolicyEnforcementOutcome:
        if not isinstance(outcome, DataPurposeMcpPolicyEnforcementOutcome):
            raise ValueError("data-governed execution requires a v0.6 MCP outcome")
        if outcome.data_governance is None:
            raise ValueError("positive execution requires data governance evidence")
        self._data.assert_decision_current(outcome.data_governance)
        return outcome.mcp_outcome

    def issue_lease(
        self,
        outcome: DataPurposeMcpPolicyEnforcementOutcome,
        *,
        lease_id: str,
        executor_id: str,
        issued_at: str,
        expires_at: str,
        approval_requirement: ApprovalRequirement | None = None,
        approval_resolution: ApprovalResolution | None = None,
    ) -> ExecutionLease:
        mcp = self._assert_current(outcome)
        return self._base.issue_lease(
            mcp,
            lease_id=lease_id,
            executor_id=executor_id,
            issued_at=issued_at,
            expires_at=expires_at,
            approval_requirement=approval_requirement,
            approval_resolution=approval_resolution,
        )

    def redeem_lease(
        self,
        lease: ExecutionLease,
        outcome: DataPurposeMcpPolicyEnforcementOutcome,
        *,
        executor_id: str,
        consumed_at: str,
    ) -> ExecutionLeaseConsumption:
        mcp = self._assert_current(outcome)
        return self._base.redeem_lease(lease, mcp, executor_id=executor_id, consumed_at=consumed_at)

    def build_receipt(
        self,
        request: AgentActionEnvelope,
        outcome: DataPurposeMcpPolicyEnforcementOutcome,
        lease: ExecutionLease,
        consumption: ExecutionLeaseConsumption,
        *,
        receipt_id: str,
        executor_id: str,
        result_digest: str,
        execution_outcome: ExecutionOutcome,
        started_at: str,
        completed_at: str,
    ) -> ToolExecutionReceipt:
        mcp = self._assert_current(outcome)
        return self._base.build_receipt(
            request,
            mcp,
            lease,
            consumption,
            receipt_id=receipt_id,
            executor_id=executor_id,
            result_digest=result_digest,
            execution_outcome=execution_outcome,
            started_at=started_at,
            completed_at=completed_at,
        )
