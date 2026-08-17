from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re

from .models import AgentActionEnvelope, Environment, RiskTier, digest_artifact

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_RISK_ORDER = {
    RiskTier.LOW: 0,
    RiskTier.MODERATE: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 3,
}


def _text(name: str, value: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty bounded text")


def _timestamp(name: str, value: str) -> datetime:
    _text(name, value, limit=64)
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} must be valid RFC3339 UTC") from exc


class ApprovalVote(str, Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"


class GrantType(str, Enum):
    DIRECT = "direct"
    DELEGATED = "delegated"


@dataclass(frozen=True, slots=True)
class ApprovalAuthorityGrant:
    grant_id: str
    institution_id: str
    issuer_principal_id: str
    subject_principal_id: str
    role_id: str
    grant_type: GrantType
    allowed_tool_ids: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_environments: tuple[Environment, ...]
    max_risk_tier: RiskTier
    valid_from: str
    valid_until: str
    can_delegate: bool = False
    parent_grant_digest: str | None = None
    schema_version: str = "regagentops.approval-authority-grant.v1"

    def __post_init__(self) -> None:
        for name in ("grant_id", "institution_id", "issuer_principal_id", "subject_principal_id", "role_id"):
            _text(name, getattr(self, name))
        for name, values in (
            ("allowed_tool_ids", self.allowed_tool_ids),
            ("allowed_actions", self.allowed_actions),
            ("allowed_environments", self.allowed_environments),
        ):
            if not values or len(set(values)) != len(values):
                raise ValueError(f"{name} must be non-empty and unique")
        start = _timestamp("valid_from", self.valid_from)
        end = _timestamp("valid_until", self.valid_until)
        if start >= end:
            raise ValueError("approval grant validity interval must be positive")
        if self.grant_type is GrantType.DIRECT and self.parent_grant_digest is not None:
            raise ValueError("direct grants must not specify parent_grant_digest")
        if self.grant_type is GrantType.DELEGATED:
            if self.parent_grant_digest is None or not _HEX_64.fullmatch(self.parent_grant_digest):
                raise ValueError("delegated grants require a parent grant digest")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)

    def permits(self, request: AgentActionEnvelope, *, at: str) -> bool:
        now = _timestamp("approval evaluation time", at)
        return (
            self.institution_id == request.institution_id
            and self.subject_principal_id != request.human_owner_id
            and request.tool_id in self.allowed_tool_ids
            and request.action in self.allowed_actions
            and request.environment in self.allowed_environments
            and _RISK_ORDER[request.risk_tier] <= _RISK_ORDER[self.max_risk_tier]
            and _timestamp("valid_from", self.valid_from) <= now < _timestamp("valid_until", self.valid_until)
        )


@dataclass(frozen=True, slots=True)
class ApprovalAuthorityBundle:
    institution_id: str
    grants: tuple[ApprovalAuthorityGrant, ...]
    schema_version: str = "regagentops.approval-authority-bundle.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        ids = [grant.grant_id for grant in self.grants]
        if len(ids) != len(set(ids)):
            raise ValueError("approval authority bundle contains duplicate grant ids")
        if any(grant.institution_id != self.institution_id for grant in self.grants):
            raise ValueError("approval grants must belong to the bundle institution")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ApprovalEscalationPolicy:
    institution_id: str
    policy_approval_minimum: int = 1
    high_risk_minimum: int = 1
    critical_risk_minimum: int = 2
    max_requirement_lifetime_seconds: int = 600
    schema_version: str = "regagentops.approval-escalation-policy.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        for name in ("policy_approval_minimum", "high_risk_minimum", "critical_risk_minimum"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1 or value > 5:
                raise ValueError(f"{name} must be between 1 and 5")
        if self.critical_risk_minimum < self.high_risk_minimum:
            raise ValueError("critical risk approval minimum cannot be lower than high risk")
        if not 60 <= self.max_requirement_lifetime_seconds <= 1800:
            raise ValueError("approval requirement lifetime must be between 60 and 1800 seconds")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    requirement_id: str
    institution_id: str
    request_digest: str
    authenticated_authorization_digest: str
    identity_context_digest: str
    requester_id: str
    tool_id: str
    action: str
    environment: Environment
    risk_tier: RiskTier
    min_approvals: int
    requester_separation_required: bool
    escalation_policy_digest: str
    issued_at: str
    expires_at: str
    schema_version: str = "regagentops.approval-requirement.v1"

    def __post_init__(self) -> None:
        for name in ("requirement_id", "institution_id", "requester_id", "tool_id", "action"):
            _text(name, getattr(self, name))
        for name in (
            "request_digest",
            "authenticated_authorization_digest",
            "identity_context_digest",
            "escalation_policy_digest",
        ):
            if not _HEX_64.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not isinstance(self.min_approvals, int) or not 1 <= self.min_approvals <= 5:
            raise ValueError("min_approvals must be between 1 and 5")
        issued = _timestamp("issued_at", self.issued_at)
        expires = _timestamp("expires_at", self.expires_at)
        if issued >= expires:
            raise ValueError("approval requirement must expire after issuance")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ApprovalStatement:
    approval_id: str
    institution_id: str
    requirement_digest: str
    request_digest: str
    approver_id: str
    authority_grant_digest: str
    vote: ApprovalVote
    issued_at: str
    expires_at: str
    rationale_digest: str
    schema_version: str = "regagentops.approval-statement.v1"

    def __post_init__(self) -> None:
        for name in ("approval_id", "institution_id", "approver_id"):
            _text(name, getattr(self, name))
        for name in ("requirement_digest", "request_digest", "authority_grant_digest", "rationale_digest"):
            if not _HEX_64.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        issued = _timestamp("issued_at", self.issued_at)
        expires = _timestamp("expires_at", self.expires_at)
        if issued >= expires:
            raise ValueError("approval statement must expire after issuance")
        if (expires - issued).total_seconds() > 900:
            raise ValueError("approval statements are limited to 15 minutes")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ApprovalResolution:
    institution_id: str
    requirement_digest: str
    request_digest: str
    approval_package_digest: str
    approval_satisfied: bool
    replay_consumed: bool
    approved_by: tuple[str, ...]
    denied_by: tuple[str, ...]
    reason_codes: tuple[str, ...]
    authorization_continuation_permitted: bool
    evaluated_at: str
    schema_version: str = "regagentops.approval-resolution.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        for name in ("requirement_digest", "request_digest", "approval_package_digest"):
            if not _HEX_64.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        _timestamp("evaluated_at", self.evaluated_at)
        if len(set(self.approved_by)) != len(self.approved_by) or len(set(self.denied_by)) != len(self.denied_by):
            raise ValueError("approval resolution principal lists must be unique")
        if self.authorization_continuation_permitted and not (
            self.approval_satisfied and self.replay_consumed and not self.denied_by
        ):
            raise ValueError("continuation requires satisfied, consumed approvals without denial")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)
