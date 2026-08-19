from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
from typing import Any

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _canonical(asdict(value))
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_artifact(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_text(name: str, value: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty text no longer than {limit} characters")


def _require_utc_timestamp(name: str, value: str) -> None:
    _require_text(name, value, limit=64)
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be an RFC3339 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid RFC3339 UTC timestamp") from exc


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    ALLOW_WITH_CONSTRAINTS = "ALLOW_WITH_CONSTRAINTS"


class RiskTier(str, Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, Enum):
    SANDBOX = "sandbox"
    DEVELOPMENT = "development"
    TEST = "test"
    STAGING = "staging"
    PRODUCTION = "production"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass(frozen=True, slots=True)
class AgentDescriptor:
    institution_id: str
    agent_id: str
    human_owner_id: str
    model_provider: str
    model_id: str
    enabled: bool = True

    def __post_init__(self) -> None:
        for name in ("institution_id", "agent_id", "human_owner_id", "model_provider", "model_id"):
            _require_text(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class ToolActionDescriptor:
    institution_id: str
    tool_id: str
    action: str
    allowed_data_classifications: tuple[DataClassification, ...]
    production_registered: bool = False
    enabled: bool = True

    def __post_init__(self) -> None:
        for name in ("institution_id", "tool_id", "action"):
            _require_text(name, getattr(self, name))
        if not self.allowed_data_classifications:
            raise ValueError("allowed_data_classifications must not be empty")
        if len(set(self.allowed_data_classifications)) != len(self.allowed_data_classifications):
            raise ValueError("allowed_data_classifications must be unique")


@dataclass(frozen=True, slots=True)
class AgentActionEnvelope:
    request_id: str
    institution_id: str
    agent_id: str
    human_owner_id: str
    model_provider: str
    model_id: str
    tool_id: str
    action: str
    resource: str
    data_classification: DataClassification
    business_purpose: str
    environment: Environment
    risk_tier: RiskTier
    input_digest: str
    requested_at: str
    schema_version: str = "regagentops.agent-action-envelope.v1"

    def __post_init__(self) -> None:
        for name in (
            "request_id", "institution_id", "agent_id", "human_owner_id", "model_provider",
            "model_id", "tool_id", "action", "resource", "business_purpose", "schema_version",
        ):
            _require_text(name, getattr(self, name), limit=512 if name in {"resource", "business_purpose"} else 256)
        if not _HEX_64.fullmatch(self.input_digest):
            raise ValueError("input_digest must be a lowercase SHA-256 hex digest")
        _require_utc_timestamp("requested_at", self.requested_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    request_digest: str
    policy_bundle_digest: str
    decision: Decision
    matched_rule_ids: tuple[str, ...]
    constraints: tuple[str, ...]
    reason_codes: tuple[str, ...]
    human_approval_required: bool
    policy_permits_execution: bool
    evaluated_at: str
    governance_evidence_digests: tuple[str, ...] = ()
    schema_version: str = "regagentops.authorization-decision.v1"

    def __post_init__(self) -> None:
        if not _HEX_64.fullmatch(self.request_digest):
            raise ValueError("request_digest must be a lowercase SHA-256 hex digest")
        if not _HEX_64.fullmatch(self.policy_bundle_digest):
            raise ValueError("policy_bundle_digest must be a lowercase SHA-256 hex digest")
        _require_utc_timestamp("evaluated_at", self.evaluated_at)
        if len(set(self.matched_rule_ids)) != len(self.matched_rule_ids):
            raise ValueError("matched_rule_ids must be unique")
        if len(set(self.constraints)) != len(self.constraints):
            raise ValueError("constraints must be unique")
        if len(set(self.governance_evidence_digests)) != len(self.governance_evidence_digests):
            raise ValueError("governance_evidence_digests must be unique")
        if tuple(sorted(self.governance_evidence_digests)) != self.governance_evidence_digests:
            raise ValueError("governance_evidence_digests must be sorted")
        for digest in self.governance_evidence_digests:
            if not _HEX_64.fullmatch(digest):
                raise ValueError("governance_evidence_digests must contain lowercase SHA-256 digests")
        if self.decision is Decision.DENY and (self.human_approval_required or self.policy_permits_execution):
            raise ValueError("DENY cannot require approval or permit execution")
        if self.decision is Decision.REQUIRE_HUMAN_APPROVAL and (
            not self.human_approval_required or self.policy_permits_execution
        ):
            raise ValueError("REQUIRE_HUMAN_APPROVAL must require approval and must not permit execution")
        if self.decision is Decision.ALLOW and (self.human_approval_required or not self.policy_permits_execution):
            raise ValueError("ALLOW must permit execution without approval")
        if self.decision is Decision.ALLOW_WITH_CONSTRAINTS:
            if self.human_approval_required or not self.policy_permits_execution or not self.constraints:
                raise ValueError("ALLOW_WITH_CONSTRAINTS requires constraints and permits execution without approval")

    @property
    def decision_digest(self) -> str:
        return digest_artifact(self)
