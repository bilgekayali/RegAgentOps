from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re

from .authenticated_identity_signature import SignedAuthenticatedAgentIdentity
from .authenticated_policy import AuthenticatedAuthorizationDecision, AuthenticatedPolicyEngine
from .identity_models import AuthenticatedAgentIdentity, WorkloadIdentityTrustBundle
from .models import (
    AgentActionEnvelope,
    DataClassification,
    Decision,
    ToolActionDescriptor,
    _require_text,
    _require_utc_timestamp,
    digest_artifact,
)
from .policy import PolicyBundle
from .registry import AgentRegistry, ToolRegistry

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_MCP_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MCP_MAX_TOOLS_PER_SNAPSHOT = 128
MCP_TOOL_ACTION = "invoke"


def _require_digest(name: str, value: str | None, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_bool(name: str, value: bool) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")


def _parse_time(value: str) -> datetime:
    _require_utc_timestamp("timestamp", value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


class McpTransportProfile(str, Enum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class McpServerRegistration:
    institution_id: str
    server_id: str
    server_version: int
    expected_server_name: str
    transport_profile: McpTransportProfile
    server_identity_digest: str
    metadata_digest: str
    approved: bool
    registered_at: str
    schema_version: str = "regagentops.mcp-server-registration.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_text("server_id", self.server_id, limit=64)
        _require_positive_int("server_version", self.server_version)
        _require_text("expected_server_name", self.expected_server_name, limit=256)
        if not isinstance(self.transport_profile, McpTransportProfile):
            raise ValueError("transport_profile must be a governed McpTransportProfile")
        _require_digest("server_identity_digest", self.server_identity_digest)
        _require_digest("metadata_digest", self.metadata_digest)
        _require_bool("approved", self.approved)
        _require_utc_timestamp("registered_at", self.registered_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class McpToolDescriptor:
    institution_id: str
    server_id: str
    server_registration_digest: str
    name: str
    input_schema_digest: str
    output_schema_digest: str | None
    description_digest: str | None
    annotations_digest: str | None
    raw_metadata_digest: str
    schema_version: str = "regagentops.mcp-tool-descriptor.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_text("server_id", self.server_id, limit=64)
        _require_digest("server_registration_digest", self.server_registration_digest)
        if not isinstance(self.name, str) or not _MCP_TOOL_NAME.fullmatch(self.name):
            raise ValueError("MCP tool name must use 1-128 ASCII letters, digits, underscore, hyphen, or dot")
        _require_digest("input_schema_digest", self.input_schema_digest)
        _require_digest("output_schema_digest", self.output_schema_digest, optional=True)
        _require_digest("description_digest", self.description_digest, optional=True)
        _require_digest("annotations_digest", self.annotations_digest, optional=True)
        _require_digest("raw_metadata_digest", self.raw_metadata_digest)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class McpToolSnapshot:
    institution_id: str
    snapshot_id: str
    server_id: str
    server_registration_digest: str
    observed_server_name: str
    observed_server_identity_digest: str
    tools: tuple[McpToolDescriptor, ...]
    captured_at: str
    schema_version: str = "regagentops.mcp-tool-snapshot.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_text("snapshot_id", self.snapshot_id)
        _require_text("server_id", self.server_id, limit=64)
        _require_digest("server_registration_digest", self.server_registration_digest)
        _require_text("observed_server_name", self.observed_server_name)
        _require_digest("observed_server_identity_digest", self.observed_server_identity_digest)
        if len(self.tools) > MCP_MAX_TOOLS_PER_SNAPSHOT:
            raise ValueError(f"MCP tool snapshot cannot contain more than {MCP_MAX_TOOLS_PER_SNAPSHOT} tools")
        if any(not isinstance(tool, McpToolDescriptor) for tool in self.tools):
            raise ValueError("MCP tool snapshot entries must be McpToolDescriptor values")
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("MCP tool snapshot contains duplicate tool names within one server")
        for tool in self.tools:
            if tool.institution_id != self.institution_id or tool.server_id != self.server_id:
                raise ValueError("MCP tool snapshot contains cross-scope tool metadata")
            if tool.server_registration_digest != self.server_registration_digest:
                raise ValueError("MCP tool snapshot tool is bound to a different server registration")
        _require_utc_timestamp("captured_at", self.captured_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class McpToolBinding:
    institution_id: str
    binding_id: str
    binding_version: int
    server_id: str
    server_registration_digest: str
    tool_snapshot_digest: str
    tool_descriptor_digest: str
    governed_tool_id: str
    allowed_data_classifications: tuple[DataClassification, ...]
    production_registered: bool
    enabled: bool
    registered_at: str
    action: str = MCP_TOOL_ACTION
    schema_version: str = "regagentops.mcp-tool-binding.v1"

    def __post_init__(self) -> None:
        for name, limit in (("institution_id", 256), ("binding_id", 256), ("server_id", 64), ("governed_tool_id", 256)):
            _require_text(name, getattr(self, name), limit=limit)
        _require_positive_int("binding_version", self.binding_version)
        _require_digest("server_registration_digest", self.server_registration_digest)
        _require_digest("tool_snapshot_digest", self.tool_snapshot_digest)
        _require_digest("tool_descriptor_digest", self.tool_descriptor_digest)
        if not self.allowed_data_classifications:
            raise ValueError("allowed_data_classifications must not be empty")
        if any(not isinstance(value, DataClassification) for value in self.allowed_data_classifications):
            raise ValueError("allowed_data_classifications must use governed DataClassification values")
        if len(set(self.allowed_data_classifications)) != len(self.allowed_data_classifications):
            raise ValueError("allowed_data_classifications must be unique")
        _require_bool("production_registered", self.production_registered)
        _require_bool("enabled", self.enabled)
        _require_utc_timestamp("registered_at", self.registered_at)
        if self.action != MCP_TOOL_ACTION:
            raise ValueError(f"MCP governed tool action must be {MCP_TOOL_ACTION!r}")
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class McpPolicyEnforcementResult:
    institution_id: str
    request_digest: str
    mcp_registry_snapshot_digest: str
    server_registration_digest: str | None
    tool_snapshot_digest: str | None
    tool_descriptor_digest: str | None
    authenticated_authorization_digest: str | None
    identity_verified: bool
    decision: Decision
    constraints: tuple[str, ...]
    reason_codes: tuple[str, ...]
    human_approval_required: bool
    execution_permitted: bool
    execution_performed: bool
    evaluated_at: str
    schema_version: str = "regagentops.mcp-policy-enforcement-result.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_digest("request_digest", self.request_digest)
        _require_digest("mcp_registry_snapshot_digest", self.mcp_registry_snapshot_digest)
        for name in (
            "server_registration_digest",
            "tool_snapshot_digest",
            "tool_descriptor_digest",
            "authenticated_authorization_digest",
        ):
            _require_digest(name, getattr(self, name), optional=True)
        _require_bool("identity_verified", self.identity_verified)
        if not isinstance(self.decision, Decision):
            raise ValueError("decision must be a governed Decision")
        if len(set(self.constraints)) != len(self.constraints):
            raise ValueError("constraints must be unique")
        for constraint in self.constraints:
            _require_text("constraint", constraint)
        if self.decision is Decision.ALLOW_WITH_CONSTRAINTS and not self.constraints:
            raise ValueError("ALLOW_WITH_CONSTRAINTS requires represented constraints")
        if self.decision is not Decision.ALLOW_WITH_CONSTRAINTS and self.constraints:
            raise ValueError("constraints are only valid for ALLOW_WITH_CONSTRAINTS")
        if not self.reason_codes or len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("reason_codes must be non-empty and unique")
        for reason in self.reason_codes:
            _require_text("reason_code", reason)
        _require_bool("human_approval_required", self.human_approval_required)
        _require_bool("execution_permitted", self.execution_permitted)
        _require_bool("execution_performed", self.execution_performed)
        if self.execution_performed:
            raise ValueError("MCP policy enforcement adapter does not execute tools")
        if self.decision is Decision.DENY:
            if self.human_approval_required or self.execution_permitted:
                raise ValueError("DENY cannot require human approval or permit execution")
        elif self.decision is Decision.REQUIRE_HUMAN_APPROVAL:
            if not self.human_approval_required or self.execution_permitted:
                raise ValueError("REQUIRE_HUMAN_APPROVAL must require approval and cannot yet permit execution")
        elif self.human_approval_required:
            raise ValueError("non-approval decisions cannot require human approval")
        _require_utc_timestamp("evaluated_at", self.evaluated_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class McpPolicyEnforcementOutcome:
    result: McpPolicyEnforcementResult
    authorization: AuthenticatedAuthorizationDecision | None

    def __post_init__(self) -> None:
        if self.authorization is None:
            if self.result.authenticated_authorization_digest is not None:
                raise ValueError("missing authorization object for represented authorization digest")
            return
        if self.result.authenticated_authorization_digest != self.authorization.artifact_digest:
            raise ValueError("MCP result is bound to a different authenticated authorization")
        if self.authorization.request_digest != self.result.request_digest:
            raise ValueError("MCP result and authenticated authorization must bind the same request")
        if self.authorization.decision is not self.result.decision:
            raise ValueError("MCP result and authenticated authorization decisions must match")
        if self.authorization.authorization.constraints != self.result.constraints:
            raise ValueError("MCP result constraints must match authenticated authorization")
        if self.authorization.authorization.human_approval_required != self.result.human_approval_required:
            raise ValueError("MCP result approval flag must match authenticated authorization")


class McpGovernanceRegistry:
    """Append-only governed MCP metadata. This class has no discovery or network capability."""

    def __init__(self) -> None:
        self._servers: dict[tuple[str, str, int], McpServerRegistration] = {}
        self._snapshots: dict[tuple[str, str], McpToolSnapshot] = {}
        self._bindings: dict[tuple[str, str, int], McpToolBinding] = {}

    @staticmethod
    def governed_tool_id(server_id: str, tool_name: str) -> str:
        _require_text("server_id", server_id, limit=64)
        if not isinstance(tool_name, str) or not _MCP_TOOL_NAME.fullmatch(tool_name):
            raise ValueError("invalid MCP tool name")
        value = f"mcp:{server_id}:{tool_name}"
        _require_text("governed_tool_id", value, limit=256)
        return value

    def register_server(self, registration: McpServerRegistration) -> str:
        key = (registration.institution_id, registration.server_id, registration.server_version)
        existing = self._servers.get(key)
        if existing is not None:
            if existing.artifact_digest != registration.artifact_digest:
                raise ValueError("MCP server identity/version already exists with different content")
            return existing.artifact_digest
        history = self.server_history(registration.institution_id, registration.server_id)
        expected = 1 if not history else history[-1].server_version + 1
        if registration.server_version != expected:
            raise ValueError(f"server_version must be contiguous; expected version {expected}")
        if history and _parse_time(registration.registered_at) < _parse_time(history[-1].registered_at):
            raise ValueError("new MCP server registration cannot predate the previous version")
        self._servers[key] = registration
        return registration.artifact_digest

    def server_history(self, institution_id: str, server_id: str) -> tuple[McpServerRegistration, ...]:
        return tuple(sorted(
            (item for (scope, current_id, _), item in self._servers.items() if scope == institution_id and current_id == server_id),
            key=lambda item: item.server_version,
        ))

    def latest_server(self, institution_id: str, server_id: str) -> McpServerRegistration:
        history = self.server_history(institution_id, server_id)
        if not history:
            raise ValueError("MCP server is not registered")
        return history[-1]

    def _server_by_digest(self, institution_id: str, digest: str) -> McpServerRegistration:
        for (scope, _, _), item in self._servers.items():
            if scope == institution_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown MCP server registration digest")

    def register_snapshot(self, snapshot: McpToolSnapshot) -> str:
        server = self._server_by_digest(snapshot.institution_id, snapshot.server_registration_digest)
        latest = self.latest_server(snapshot.institution_id, snapshot.server_id)
        if server.artifact_digest != latest.artifact_digest:
            raise ValueError("MCP tool snapshot is bound to stale server registration")
        if not latest.approved:
            raise ValueError("MCP server is not currently approved")
        if snapshot.observed_server_name != latest.expected_server_name:
            raise ValueError("MCP observed server name does not match governed registration")
        if snapshot.observed_server_identity_digest != latest.server_identity_digest:
            raise ValueError("MCP observed server identity does not match governed pin")
        if _parse_time(snapshot.captured_at) < _parse_time(latest.registered_at):
            raise ValueError("MCP tool snapshot cannot predate server registration")
        key = (snapshot.institution_id, snapshot.snapshot_id)
        existing = self._snapshots.get(key)
        if existing is not None:
            if existing.artifact_digest != snapshot.artifact_digest:
                raise ValueError("MCP snapshot_id already exists with different content")
            return existing.artifact_digest
        self._snapshots[key] = snapshot
        return snapshot.artifact_digest

    def _snapshots_for_server(self, institution_id: str, server_id: str) -> tuple[McpToolSnapshot, ...]:
        return tuple(item for (scope, _), item in self._snapshots.items() if scope == institution_id and item.server_id == server_id)

    def latest_snapshot(self, institution_id: str, server_id: str) -> McpToolSnapshot:
        server = self.latest_server(institution_id, server_id)
        if not server.approved:
            raise ValueError("MCP server is not currently approved")
        candidates = tuple(
            item for item in self._snapshots_for_server(institution_id, server_id)
            if item.server_registration_digest == server.artifact_digest
        )
        if not candidates:
            raise ValueError("approved MCP server has no governed tool snapshot")
        latest_time = max(_parse_time(item.captured_at) for item in candidates)
        latest = tuple(item for item in candidates if _parse_time(item.captured_at) == latest_time)
        if len({item.artifact_digest for item in latest}) != 1:
            raise ValueError("conflicting latest MCP tool snapshots fail closed")
        return latest[0]

    def snapshot_by_digest(self, institution_id: str, digest: str) -> McpToolSnapshot:
        for (scope, _), item in self._snapshots.items():
            if scope == institution_id and item.artifact_digest == digest:
                return item
        raise ValueError("unknown MCP tool snapshot digest")

    @staticmethod
    def _descriptor_by_digest(snapshot: McpToolSnapshot, digest: str) -> McpToolDescriptor:
        for item in snapshot.tools:
            if item.artifact_digest == digest:
                return item
        raise ValueError("MCP tool descriptor is not present in bound snapshot")

    def register_binding(self, binding: McpToolBinding) -> str:
        server = self._server_by_digest(binding.institution_id, binding.server_registration_digest)
        latest_server = self.latest_server(binding.institution_id, binding.server_id)
        if server.artifact_digest != latest_server.artifact_digest or not latest_server.approved:
            raise ValueError("MCP tool binding requires current approved server registration")
        snapshot = self.snapshot_by_digest(binding.institution_id, binding.tool_snapshot_digest)
        latest_snapshot = self.latest_snapshot(binding.institution_id, binding.server_id)
        if snapshot.artifact_digest != latest_snapshot.artifact_digest:
            raise ValueError("MCP tool binding requires latest governed tool snapshot")
        descriptor = self._descriptor_by_digest(snapshot, binding.tool_descriptor_digest)
        expected_tool_id = self.governed_tool_id(binding.server_id, descriptor.name)
        if binding.governed_tool_id != expected_tool_id:
            raise ValueError("governed MCP tool id does not match institution-pinned server/tool identity")
        if _parse_time(binding.registered_at) < _parse_time(snapshot.captured_at):
            raise ValueError("MCP tool binding cannot predate its governed tool snapshot")
        key = (binding.institution_id, binding.binding_id, binding.binding_version)
        existing = self._bindings.get(key)
        if existing is not None:
            if existing.artifact_digest != binding.artifact_digest:
                raise ValueError("MCP binding identity/version already exists with different content")
            return existing.artifact_digest
        history = self.binding_history(binding.institution_id, binding.binding_id)
        expected = 1 if not history else history[-1].binding_version + 1
        if binding.binding_version != expected:
            raise ValueError(f"binding_version must be contiguous; expected version {expected}")
        if history and history[0].governed_tool_id != binding.governed_tool_id:
            raise ValueError("MCP binding identity cannot move to a different governed tool")
        if history and _parse_time(binding.registered_at) < _parse_time(history[-1].registered_at):
            raise ValueError("new MCP binding version cannot predate the previous version")
        self._bindings[key] = binding
        return binding.artifact_digest

    def binding_history(self, institution_id: str, binding_id: str) -> tuple[McpToolBinding, ...]:
        return tuple(sorted(
            (item for (scope, current_id, _), item in self._bindings.items() if scope == institution_id and current_id == binding_id),
            key=lambda item: item.binding_version,
        ))

    def latest_binding(self, institution_id: str, binding_id: str) -> McpToolBinding:
        history = self.binding_history(institution_id, binding_id)
        if not history:
            raise ValueError("unknown MCP tool binding")
        return history[-1]

    def assert_binding_current(self, binding: McpToolBinding) -> McpToolDescriptor:
        if self.latest_binding(binding.institution_id, binding.binding_id).artifact_digest != binding.artifact_digest:
            raise ValueError("MCP tool binding is stale")
        server = self.latest_server(binding.institution_id, binding.server_id)
        if server.artifact_digest != binding.server_registration_digest or not server.approved:
            raise ValueError("MCP tool binding server registration is stale or unapproved")
        snapshot = self.latest_snapshot(binding.institution_id, binding.server_id)
        if snapshot.artifact_digest != binding.tool_snapshot_digest:
            raise ValueError("MCP tool binding snapshot is stale")
        descriptor = self._descriptor_by_digest(snapshot, binding.tool_descriptor_digest)
        if binding.governed_tool_id != self.governed_tool_id(binding.server_id, descriptor.name):
            raise ValueError("MCP tool binding identity mismatch")
        return descriptor

    def current_binding_for_tool(self, institution_id: str, governed_tool_id: str) -> McpToolBinding:
        candidates: list[McpToolBinding] = []
        binding_ids = sorted({binding_id for (scope, binding_id, _) in self._bindings if scope == institution_id})
        for binding_id in binding_ids:
            binding = self.latest_binding(institution_id, binding_id)
            if binding.governed_tool_id != governed_tool_id:
                continue
            try:
                self.assert_binding_current(binding)
            except ValueError:
                continue
            candidates.append(binding)
        if not candidates:
            raise ValueError("MCP tool is not currently governed")
        if len({item.artifact_digest for item in candidates}) != 1:
            raise ValueError("conflicting current MCP tool bindings fail closed")
        return candidates[0]

    def current_tool_registry(self, institution_id: str) -> ToolRegistry:
        actions: list[ToolActionDescriptor] = []
        binding_ids = sorted({binding_id for (scope, binding_id, _) in self._bindings if scope == institution_id})
        seen: set[tuple[str, str]] = set()
        for binding_id in binding_ids:
            binding = self.latest_binding(institution_id, binding_id)
            try:
                self.assert_binding_current(binding)
            except ValueError:
                continue
            key = (binding.governed_tool_id, binding.action)
            if key in seen:
                raise ValueError("conflicting current MCP bindings produce duplicate tool/action identity")
            seen.add(key)
            actions.append(ToolActionDescriptor(
                institution_id=institution_id,
                tool_id=binding.governed_tool_id,
                action=binding.action,
                allowed_data_classifications=binding.allowed_data_classifications,
                production_registered=binding.production_registered,
                enabled=binding.enabled,
            ))
        return ToolRegistry(tuple(actions))

    def snapshot_digest(self, institution_id: str) -> str:
        return digest_artifact({
            "institution_id": institution_id,
            "servers": sorted(item.artifact_digest for (scope, _, _), item in self._servers.items() if scope == institution_id),
            "tool_snapshots": sorted(item.artifact_digest for (scope, _), item in self._snapshots.items() if scope == institution_id),
            "tool_bindings": sorted(item.artifact_digest for (scope, _, _), item in self._bindings.items() if scope == institution_id),
        })


class McpPolicyEnforcementPoint:
    """Offline MCP policy-enforcement adapter. It evaluates governance state and never invokes a tool."""

    def __init__(self, agents: AgentRegistry, mcp_registry: McpGovernanceRegistry) -> None:
        if not isinstance(agents, AgentRegistry) or not isinstance(mcp_registry, McpGovernanceRegistry):
            raise ValueError("MCP policy enforcement point requires governed registries")
        self._agents = agents
        self._mcp = mcp_registry

    def evaluate(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        identity: SignedAuthenticatedAgentIdentity | AuthenticatedAgentIdentity,
        *,
        identity_trust_bundle: WorkloadIdentityTrustBundle,
        evaluated_at: str,
    ) -> McpPolicyEnforcementOutcome:
        registry_digest = self._mcp.snapshot_digest(request.institution_id)
        server_digest: str | None = None
        snapshot_digest: str | None = None
        descriptor_digest: str | None = None
        try:
            if request.action != MCP_TOOL_ACTION:
                raise ValueError("mcp_action_not_governed")
            binding = self._mcp.current_binding_for_tool(request.institution_id, request.tool_id)
            descriptor = self._mcp.assert_binding_current(binding)
            server_digest = binding.server_registration_digest
            snapshot_digest = binding.tool_snapshot_digest
            descriptor_digest = descriptor.artifact_digest
            tools = self._mcp.current_tool_registry(request.institution_id)
        except ValueError as exc:
            reason = str(exc)
            if not reason.startswith("mcp_"):
                reason = "mcp_governance_precondition_failed"
            result = McpPolicyEnforcementResult(
                institution_id=request.institution_id,
                request_digest=request.artifact_digest,
                mcp_registry_snapshot_digest=registry_digest,
                server_registration_digest=server_digest,
                tool_snapshot_digest=snapshot_digest,
                tool_descriptor_digest=descriptor_digest,
                authenticated_authorization_digest=None,
                identity_verified=False,
                decision=Decision.DENY,
                constraints=(),
                reason_codes=(reason,),
                human_approval_required=False,
                execution_permitted=False,
                execution_performed=False,
                evaluated_at=evaluated_at,
            )
            return McpPolicyEnforcementOutcome(result, None)

        authorization = AuthenticatedPolicyEngine(self._agents, tools).evaluate(
            request,
            policy,
            identity,
            identity_trust_bundle=identity_trust_bundle,
            evaluated_at=evaluated_at,
        )
        result = McpPolicyEnforcementResult(
            institution_id=request.institution_id,
            request_digest=request.artifact_digest,
            mcp_registry_snapshot_digest=registry_digest,
            server_registration_digest=server_digest,
            tool_snapshot_digest=snapshot_digest,
            tool_descriptor_digest=descriptor_digest,
            authenticated_authorization_digest=authorization.artifact_digest,
            identity_verified=authorization.identity_verified,
            decision=authorization.decision,
            constraints=authorization.authorization.constraints,
            reason_codes=authorization.authorization.reason_codes,
            human_approval_required=authorization.authorization.human_approval_required,
            execution_permitted=authorization.authorization.policy_permits_execution,
            execution_performed=False,
            evaluated_at=evaluated_at,
        )
        return McpPolicyEnforcementOutcome(result, authorization)
