from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
import re
import sqlite3
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .approval_models import ApprovalRequirement, ApprovalResolution
from .mcp import McpGovernanceRegistry, McpPolicyEnforcementOutcome
from .models import AgentActionEnvelope, Decision, canonical_json, digest_artifact, _require_text, _require_utc_timestamp

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
EXECUTION_LEASE_MAX_SECONDS = 120
EXECUTION_AUTHORIZATION_MAX_AGE_SECONDS = 120


def _require_digest(name: str, value: str | None, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")


def _require_bool(name: str, value: bool) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")


def _require_positive_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _parse_time(name: str, value: str) -> datetime:
    _require_utc_timestamp(name, value)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("base64url values must be unpadded text")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # pragma: no cover
        raise ValueError("invalid base64url value") from exc


class ExecutionOutcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ExecutionKeyStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class EmergencyStopState:
    institution_id: str
    state_version: int
    halted: bool
    reason_digest: str | None
    effective_at: str
    schema_version: str = "regagentops.emergency-stop-state.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_positive_int("state_version", self.state_version)
        _require_bool("halted", self.halted)
        _require_digest("reason_digest", self.reason_digest, optional=True)
        _require_utc_timestamp("effective_at", self.effective_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class EmergencyStopRegistry:
    """Append-only institution emergency-stop state used at lease issue and redemption."""

    def __init__(self) -> None:
        self._states: dict[tuple[str, int], EmergencyStopState] = {}

    def register(self, state: EmergencyStopState) -> str:
        if not isinstance(state, EmergencyStopState):
            raise ValueError("emergency-stop registry accepts EmergencyStopState values")
        key = (state.institution_id, state.state_version)
        existing = self._states.get(key)
        if existing is not None:
            if existing.artifact_digest != state.artifact_digest:
                raise ValueError("emergency-stop version already exists with different content")
            return existing.artifact_digest
        history = self.history(state.institution_id)
        expected = 1 if not history else history[-1].state_version + 1
        if state.state_version != expected:
            raise ValueError(f"emergency-stop state_version must be contiguous; expected version {expected}")
        if history and _parse_time("effective_at", state.effective_at) < _parse_time(
            "previous effective_at", history[-1].effective_at
        ):
            raise ValueError("new emergency-stop state cannot predate the previous version")
        self._states[key] = state
        return state.artifact_digest

    def history(self, institution_id: str) -> tuple[EmergencyStopState, ...]:
        return tuple(
            sorted(
                (state for (scope, _), state in self._states.items() if scope == institution_id),
                key=lambda state: state.state_version,
            )
        )

    def current(self, institution_id: str) -> EmergencyStopState:
        history = self.history(institution_id)
        if not history:
            raise ValueError("emergency-stop state is not registered")
        return history[-1]


@dataclass(frozen=True, slots=True)
class ExecutionLease:
    lease_id: str
    institution_id: str
    executor_id: str
    request_digest: str
    authenticated_authorization_digest: str
    policy_decision_digest: str
    mcp_policy_enforcement_result_digest: str
    mcp_registry_snapshot_digest: str
    approval_requirement_digest: str | None
    approval_resolution_digest: str | None
    emergency_stop_state_digest: str
    issued_at: str
    expires_at: str
    schema_version: str = "regagentops.execution-lease.v1"

    def __post_init__(self) -> None:
        for name in ("lease_id", "institution_id", "executor_id"):
            _require_text(name, getattr(self, name))
        for name in (
            "request_digest",
            "authenticated_authorization_digest",
            "policy_decision_digest",
            "mcp_policy_enforcement_result_digest",
            "mcp_registry_snapshot_digest",
            "emergency_stop_state_digest",
        ):
            _require_digest(name, getattr(self, name))
        _require_digest("approval_requirement_digest", self.approval_requirement_digest, optional=True)
        _require_digest("approval_resolution_digest", self.approval_resolution_digest, optional=True)
        if (self.approval_requirement_digest is None) != (self.approval_resolution_digest is None):
            raise ValueError("execution lease approval requirement and resolution digests must be represented together")
        issued = _parse_time("issued_at", self.issued_at)
        expires = _parse_time("expires_at", self.expires_at)
        lifetime = (expires - issued).total_seconds()
        if lifetime <= 0 or lifetime > EXECUTION_LEASE_MAX_SECONDS:
            raise ValueError(f"execution lease lifetime must be between 1 and {EXECUTION_LEASE_MAX_SECONDS} seconds")
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ExecutionLeaseConsumption:
    institution_id: str
    executor_id: str
    lease_digest: str
    request_digest: str
    mcp_registry_snapshot_digest: str
    emergency_stop_state_digest: str
    consumed_at: str
    schema_version: str = "regagentops.execution-lease-consumption.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        _require_text("executor_id", self.executor_id)
        for name in (
            "lease_digest",
            "request_digest",
            "mcp_registry_snapshot_digest",
            "emergency_stop_state_digest",
        ):
            _require_digest(name, getattr(self, name))
        _require_utc_timestamp("consumed_at", self.consumed_at)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ExecutionLeaseLedger:
    """Append-only atomic one-time execution-lease redemption ledger."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._database = str(database)
        self._connection = sqlite3.connect(self._database, isolation_level=None)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_lease_consumptions (
                lease_digest TEXT PRIMARY KEY,
                consumption_digest TEXT NOT NULL UNIQUE,
                institution_id TEXT NOT NULL,
                executor_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                mcp_registry_snapshot_digest TEXT NOT NULL,
                emergency_stop_state_digest TEXT NOT NULL,
                consumed_at TEXT NOT NULL
            )
            """
        )

    def close(self) -> None:
        self._connection.close()

    def consume(self, consumption: ExecutionLeaseConsumption) -> None:
        if not isinstance(consumption, ExecutionLeaseConsumption):
            raise ValueError("execution lease ledger accepts ExecutionLeaseConsumption values")
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                INSERT INTO execution_lease_consumptions (
                    lease_digest,
                    consumption_digest,
                    institution_id,
                    executor_id,
                    request_digest,
                    mcp_registry_snapshot_digest,
                    emergency_stop_state_digest,
                    consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    consumption.lease_digest,
                    consumption.artifact_digest,
                    consumption.institution_id,
                    consumption.executor_id,
                    consumption.request_digest,
                    consumption.mcp_registry_snapshot_digest,
                    consumption.emergency_stop_state_digest,
                    consumption.consumed_at,
                ),
            )
            self._connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            self._connection.execute("ROLLBACK")
            raise ValueError("execution lease has already been consumed") from exc
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def assert_recorded(self, consumption: ExecutionLeaseConsumption) -> None:
        if not isinstance(consumption, ExecutionLeaseConsumption):
            raise ValueError("execution receipt requires a typed lease consumption")
        row = self._connection.execute(
            """
            SELECT consumption_digest, institution_id, executor_id, request_digest,
                   mcp_registry_snapshot_digest, emergency_stop_state_digest, consumed_at
              FROM execution_lease_consumptions
             WHERE lease_digest = ?
            """,
            (consumption.lease_digest,),
        ).fetchone()
        if row is None:
            raise ValueError("execution lease consumption is not recorded in the append-only ledger")
        expected = (
            consumption.artifact_digest,
            consumption.institution_id,
            consumption.executor_id,
            consumption.request_digest,
            consumption.mcp_registry_snapshot_digest,
            consumption.emergency_stop_state_digest,
            consumption.consumed_at,
        )
        if tuple(row) != expected:
            raise ValueError("execution lease consumption does not match the append-only ledger record")

    def consumption_count(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) FROM execution_lease_consumptions").fetchone()
        return int(row[0]) if row else 0


@dataclass(frozen=True, slots=True)
class ToolExecutionReceipt:
    receipt_id: str
    institution_id: str
    executor_id: str
    request_digest: str
    tool_id: str
    action: str
    resource: str
    input_digest: str
    execution_lease_digest: str
    lease_consumption_digest: str
    mcp_policy_enforcement_result_digest: str
    authenticated_authorization_digest: str
    policy_decision: Decision
    policy_decision_digest: str
    approval_requirement_digest: str | None
    approval_resolution_digest: str | None
    emergency_stop_state_digest: str
    result_digest: str
    execution_outcome: ExecutionOutcome
    started_at: str
    completed_at: str
    schema_version: str = "regagentops.tool-execution-receipt.v1"

    def __post_init__(self) -> None:
        for name, limit in (
            ("receipt_id", 256),
            ("institution_id", 256),
            ("executor_id", 256),
            ("tool_id", 256),
            ("action", 256),
            ("resource", 512),
        ):
            _require_text(name, getattr(self, name), limit=limit)
        for name in (
            "request_digest",
            "input_digest",
            "execution_lease_digest",
            "lease_consumption_digest",
            "mcp_policy_enforcement_result_digest",
            "authenticated_authorization_digest",
            "policy_decision_digest",
            "emergency_stop_state_digest",
            "result_digest",
        ):
            _require_digest(name, getattr(self, name))
        _require_digest("approval_requirement_digest", self.approval_requirement_digest, optional=True)
        _require_digest("approval_resolution_digest", self.approval_resolution_digest, optional=True)
        if (self.approval_requirement_digest is None) != (self.approval_resolution_digest is None):
            raise ValueError("execution receipt approval requirement and resolution digests must be represented together")
        if not isinstance(self.policy_decision, Decision) or self.policy_decision is Decision.DENY:
            raise ValueError("execution receipt must bind a non-DENY governed policy decision")
        if not isinstance(self.execution_outcome, ExecutionOutcome):
            raise ValueError("execution_outcome must be a governed ExecutionOutcome")
        started = _parse_time("started_at", self.started_at)
        completed = _parse_time("completed_at", self.completed_at)
        if started > completed:
            raise ValueError("execution completion cannot predate execution start")
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ExecutionTrustKey:
    institution_id: str
    executor_id: str
    key_id: str
    public_key_base64url: str
    not_before: str
    not_after: str
    status: ExecutionKeyStatus = ExecutionKeyStatus.ACTIVE
    algorithm: str = "Ed25519"

    def __post_init__(self) -> None:
        for name in ("institution_id", "executor_id", "key_id"):
            _require_text(name, getattr(self, name))
        if self.algorithm != "Ed25519":
            raise ValueError("v0.5 execution receipt trust keys require Ed25519")
        if len(_decode(self.public_key_base64url)) != 32:
            raise ValueError("Ed25519 execution public key must decode to 32 bytes")
        if _parse_time("not_before", self.not_before) >= _parse_time("not_after", self.not_after):
            raise ValueError("execution trust key validity interval must be positive")


@dataclass(frozen=True, slots=True)
class ExecutionTrustBundle:
    institution_id: str
    keys: tuple[ExecutionTrustKey, ...]
    schema_version: str = "regagentops.execution-trust-bundle.v1"

    def __post_init__(self) -> None:
        _require_text("institution_id", self.institution_id)
        if not self.keys:
            raise ValueError("execution trust bundle must contain at least one key")
        if any(key.institution_id != self.institution_id for key in self.keys):
            raise ValueError("execution trust keys must belong to the bundle institution")
        identities = [(key.executor_id, key.key_id) for key in self.keys]
        if len(identities) != len(set(identities)):
            raise ValueError("execution trust bundle contains duplicate executor/key ids")
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ExecutionReceiptSigner(Protocol):
    institution_id: str
    executor_id: str
    key_id: str
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SignedToolExecutionReceipt:
    receipt: ToolExecutionReceipt
    key_id: str
    algorithm: str
    signature_base64url: str
    signing_document_digest: str
    schema_version: str = "regagentops.signed-tool-execution-receipt.v1"

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ToolExecutionReceipt):
            raise ValueError("signed execution receipt must contain a ToolExecutionReceipt")
        _require_text("key_id", self.key_id)
        if self.algorithm != "Ed25519":
            raise ValueError("v0.5 execution receipt signatures require Ed25519")
        if len(_decode(self.signature_base64url)) != 64:
            raise ValueError("Ed25519 execution receipt signature must decode to 64 bytes")
        _require_digest("signing_document_digest", self.signing_document_digest)
        _require_text("schema_version", self.schema_version)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class ExecutionReceiptSignatureError(ValueError):
    pass


def execution_receipt_signing_document(receipt: ToolExecutionReceipt, *, key_id: str, algorithm: str) -> dict[str, str]:
    return {
        "purpose": "regagentops.tool-execution-receipt.v1",
        "institution_id": receipt.institution_id,
        "receipt_id": receipt.receipt_id,
        "executor_id": receipt.executor_id,
        "request_digest": receipt.request_digest,
        "execution_lease_digest": receipt.execution_lease_digest,
        "lease_consumption_digest": receipt.lease_consumption_digest,
        "mcp_policy_enforcement_result_digest": receipt.mcp_policy_enforcement_result_digest,
        "authenticated_authorization_digest": receipt.authenticated_authorization_digest,
        "policy_decision_digest": receipt.policy_decision_digest,
        "result_digest": receipt.result_digest,
        "receipt_digest": receipt.artifact_digest,
        "key_id": key_id,
        "algorithm": algorithm,
    }


def sign_tool_execution_receipt(receipt: ToolExecutionReceipt, *, signer: ExecutionReceiptSigner) -> SignedToolExecutionReceipt:
    if signer.institution_id != receipt.institution_id:
        raise ExecutionReceiptSignatureError("execution receipt signer institution mismatch")
    if signer.executor_id != receipt.executor_id:
        raise ExecutionReceiptSignatureError("execution receipt signer executor mismatch")
    if signer.algorithm != "Ed25519":
        raise ExecutionReceiptSignatureError("v0.5 execution receipt signer must use Ed25519")
    document = execution_receipt_signing_document(receipt, key_id=signer.key_id, algorithm=signer.algorithm)
    signature = signer.sign(canonical_json(document).encode("utf-8"))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ExecutionReceiptSignatureError("execution receipt signer must return a 64-byte Ed25519 signature")
    return SignedToolExecutionReceipt(
        receipt=receipt,
        key_id=signer.key_id,
        algorithm=signer.algorithm,
        signature_base64url=_encode(signature),
        signing_document_digest=digest_artifact(document),
    )


def verify_signed_tool_execution_receipt(
    signed: SignedToolExecutionReceipt,
    *,
    trust_bundle: ExecutionTrustBundle,
    now: str,
) -> ToolExecutionReceipt:
    receipt = signed.receipt
    if trust_bundle.institution_id != receipt.institution_id:
        raise ExecutionReceiptSignatureError("execution trust bundle institution mismatch")
    matches = [
        key for key in trust_bundle.keys
        if key.executor_id == receipt.executor_id and key.key_id == signed.key_id
    ]
    if len(matches) != 1:
        raise ExecutionReceiptSignatureError("execution key must resolve uniquely for the executor")
    key = matches[0]
    if key.status is not ExecutionKeyStatus.ACTIVE:
        raise ExecutionReceiptSignatureError("execution trust key is not active")
    if key.algorithm != signed.algorithm or signed.algorithm != "Ed25519":
        raise ExecutionReceiptSignatureError("execution receipt signature algorithm mismatch")
    now_dt = _parse_time("verification time", now)
    completed = _parse_time("completed_at", receipt.completed_at)
    key_start = _parse_time("key not_before", key.not_before)
    key_end = _parse_time("key not_after", key.not_after)
    if completed > now_dt:
        raise ExecutionReceiptSignatureError("execution receipt completion is in the future")
    if not (key_start <= completed < key_end):
        raise ExecutionReceiptSignatureError("execution trust key was not valid when the receipt completed")
    document = execution_receipt_signing_document(receipt, key_id=signed.key_id, algorithm=signed.algorithm)
    if signed.signing_document_digest != digest_artifact(document):
        raise ExecutionReceiptSignatureError("execution receipt signing document digest mismatch")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(_decode(key.public_key_base64url))
        public_key.verify(_decode(signed.signature_base64url), canonical_json(document).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise ExecutionReceiptSignatureError("execution receipt signature is invalid") from exc
    return receipt


class ExecutionGate:
    """Non-executing v0.5 boundary for exact execution leases and signed result evidence."""

    def __init__(
        self,
        mcp_registry: McpGovernanceRegistry,
        emergency_stops: EmergencyStopRegistry,
        lease_ledger: ExecutionLeaseLedger,
    ) -> None:
        if not isinstance(mcp_registry, McpGovernanceRegistry):
            raise ValueError("execution gate requires a governed MCP registry")
        if not isinstance(emergency_stops, EmergencyStopRegistry):
            raise ValueError("execution gate requires an emergency-stop registry")
        if not isinstance(lease_ledger, ExecutionLeaseLedger):
            raise ValueError("execution gate requires an execution lease ledger")
        self._mcp = mcp_registry
        self._stops = emergency_stops
        self._ledger = lease_ledger

    @staticmethod
    def _validate_outcome(outcome: McpPolicyEnforcementOutcome) -> None:
        if not isinstance(outcome, McpPolicyEnforcementOutcome):
            raise ValueError("execution requires an exact MCP policy-enforcement outcome")
        if outcome.authorization is None or not outcome.authorization.identity_verified:
            raise ValueError("execution requires verified authenticated authorization")
        if outcome.result.decision is Decision.DENY:
            raise ValueError("DENY decisions cannot produce an execution lease")
        if outcome.result.execution_performed:
            raise ValueError("MCP policy-enforcement result must remain non-executing")
        if any(
            value is None
            for value in (
                outcome.result.server_registration_digest,
                outcome.result.tool_snapshot_digest,
                outcome.result.tool_descriptor_digest,
                outcome.result.authenticated_authorization_digest,
            )
        ):
            raise ValueError("execution requires complete governed MCP and authorization evidence")

    def _assert_current_governance(self, outcome: McpPolicyEnforcementOutcome) -> None:
        current = self._mcp.snapshot_digest(outcome.request.institution_id)
        if current != outcome.result.mcp_registry_snapshot_digest:
            raise ValueError("MCP governance state changed after policy enforcement")
        binding = self._mcp.current_binding_for_tool(outcome.request.institution_id, outcome.request.tool_id)
        descriptor = self._mcp.assert_binding_current(binding)
        if binding.server_registration_digest != outcome.result.server_registration_digest:
            raise ValueError("MCP server registration changed after policy enforcement")
        if binding.tool_snapshot_digest != outcome.result.tool_snapshot_digest:
            raise ValueError("MCP tool snapshot changed after policy enforcement")
        if descriptor.artifact_digest != outcome.result.tool_descriptor_digest:
            raise ValueError("MCP tool descriptor changed after policy enforcement")

    @staticmethod
    def _validate_approval_chain(
        outcome: McpPolicyEnforcementOutcome,
        requirement: ApprovalRequirement | None,
        resolution: ApprovalResolution | None,
        *,
        at: str,
    ) -> tuple[str | None, str | None]:
        required = outcome.result.human_approval_required
        if not required:
            if requirement is not None or resolution is not None:
                raise ValueError("approval artifacts must not be attached when no approval gate is required")
            if not outcome.result.execution_permitted:
                raise ValueError("non-approved execution path is not permitted by the MCP policy result")
            return None, None
        if requirement is None or resolution is None:
            raise ValueError("approval-required execution needs the exact requirement and resolution")
        authorization = outcome.authorization
        assert authorization is not None
        request = outcome.request
        at_dt = _parse_time("lease issue time", at)
        requirement_start = _parse_time("approval requirement issued_at", requirement.issued_at)
        requirement_end = _parse_time("approval requirement expires_at", requirement.expires_at)
        resolution_time = _parse_time("approval evaluated_at", resolution.evaluated_at)
        if requirement.institution_id != request.institution_id:
            raise ValueError("approval requirement institution mismatch")
        if requirement.request_digest != request.artifact_digest:
            raise ValueError("approval requirement request mismatch")
        if requirement.authenticated_authorization_digest != authorization.artifact_digest:
            raise ValueError("approval requirement authorization mismatch")
        if requirement.identity_context_digest != authorization.identity_context_digest:
            raise ValueError("approval requirement identity-context mismatch")
        if (
            requirement.requester_id != request.human_owner_id
            or requirement.tool_id != request.tool_id
            or requirement.action != request.action
            or requirement.environment is not request.environment
            or requirement.risk_tier is not request.risk_tier
        ):
            raise ValueError("approval requirement scope mismatch")
        if not (requirement_start <= at_dt < requirement_end):
            raise ValueError("approval requirement is expired or not yet valid at execution lease issuance")
        if not (requirement_start <= resolution_time < requirement_end):
            raise ValueError("approval resolution falls outside the approval requirement validity window")
        if resolution_time > at_dt:
            raise ValueError("approval resolution cannot postdate execution lease issuance")
        if resolution.institution_id != request.institution_id or resolution.request_digest != request.artifact_digest:
            raise ValueError("approval resolution request scope mismatch")
        if resolution.requirement_digest != requirement.artifact_digest:
            raise ValueError("approval resolution is bound to a different requirement")
        if not resolution.authorization_continuation_permitted:
            raise ValueError("approval resolution does not permit authorization continuation")
        return requirement.artifact_digest, resolution.artifact_digest

    def issue_lease(
        self,
        outcome: McpPolicyEnforcementOutcome,
        *,
        lease_id: str,
        executor_id: str,
        issued_at: str,
        expires_at: str,
        approval_requirement: ApprovalRequirement | None = None,
        approval_resolution: ApprovalResolution | None = None,
    ) -> ExecutionLease:
        self._validate_outcome(outcome)
        self._assert_current_governance(outcome)
        _require_text("executor_id", executor_id)
        authorization = outcome.authorization
        assert authorization is not None
        issue_time = _parse_time("issued_at", issued_at)
        evaluated_at = _parse_time("policy evaluated_at", outcome.result.evaluated_at)
        if issue_time < evaluated_at:
            raise ValueError("execution lease cannot predate policy enforcement")
        if (issue_time - evaluated_at).total_seconds() > EXECUTION_AUTHORIZATION_MAX_AGE_SECONDS:
            raise ValueError("authenticated authorization is too old for execution lease issuance")
        stop = self._stops.current(outcome.request.institution_id)
        if _parse_time("emergency-stop effective_at", stop.effective_at) > issue_time:
            raise ValueError("current emergency-stop state is not yet effective")
        if stop.halted:
            raise ValueError("emergency stop is active; execution lease issuance denied")
        requirement_digest, resolution_digest = self._validate_approval_chain(
            outcome,
            approval_requirement,
            approval_resolution,
            at=issued_at,
        )
        return ExecutionLease(
            lease_id=lease_id,
            institution_id=outcome.request.institution_id,
            executor_id=executor_id,
            request_digest=outcome.request.artifact_digest,
            authenticated_authorization_digest=authorization.artifact_digest,
            policy_decision_digest=authorization.authorization.decision_digest,
            mcp_policy_enforcement_result_digest=outcome.result.artifact_digest,
            mcp_registry_snapshot_digest=outcome.result.mcp_registry_snapshot_digest,
            approval_requirement_digest=requirement_digest,
            approval_resolution_digest=resolution_digest,
            emergency_stop_state_digest=stop.artifact_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _validate_lease_linkage(lease: ExecutionLease, outcome: McpPolicyEnforcementOutcome) -> None:
        if not isinstance(lease, ExecutionLease):
            raise ValueError("execution boundary requires an ExecutionLease")
        ExecutionGate._validate_outcome(outcome)
        authorization = outcome.authorization
        assert authorization is not None
        if lease.institution_id != outcome.request.institution_id:
            raise ValueError("execution lease institution mismatch")
        if lease.request_digest != outcome.request.artifact_digest:
            raise ValueError("execution lease request mismatch")
        if lease.authenticated_authorization_digest != authorization.artifact_digest:
            raise ValueError("execution lease authorization mismatch")
        if lease.policy_decision_digest != authorization.authorization.decision_digest:
            raise ValueError("execution lease policy-decision mismatch")
        if lease.mcp_policy_enforcement_result_digest != outcome.result.artifact_digest:
            raise ValueError("execution lease MCP result mismatch")
        if lease.mcp_registry_snapshot_digest != outcome.result.mcp_registry_snapshot_digest:
            raise ValueError("execution lease MCP registry snapshot mismatch")
        if outcome.result.human_approval_required != (lease.approval_resolution_digest is not None):
            raise ValueError("execution lease approval linkage is inconsistent with the policy result")

    def redeem_lease(
        self,
        lease: ExecutionLease,
        outcome: McpPolicyEnforcementOutcome,
        *,
        executor_id: str,
        consumed_at: str,
    ) -> ExecutionLeaseConsumption:
        self._validate_lease_linkage(lease, outcome)
        _require_text("executor_id", executor_id)
        if executor_id != lease.executor_id:
            raise ValueError("execution lease is bound to a different executor")
        self._assert_current_governance(outcome)
        consumed = _parse_time("consumed_at", consumed_at)
        if consumed < _parse_time("issued_at", lease.issued_at) or consumed >= _parse_time("expires_at", lease.expires_at):
            raise ValueError("execution lease is expired or not yet valid")
        stop = self._stops.current(lease.institution_id)
        if _parse_time("emergency-stop effective_at", stop.effective_at) > consumed:
            raise ValueError("current emergency-stop state is not yet effective")
        if stop.halted:
            raise ValueError("emergency stop is active; execution lease redemption denied")
        if stop.artifact_digest != lease.emergency_stop_state_digest:
            raise ValueError("emergency-stop state changed after execution lease issuance")
        current_registry = self._mcp.snapshot_digest(lease.institution_id)
        if current_registry != lease.mcp_registry_snapshot_digest:
            raise ValueError("MCP governance state changed after execution lease issuance")
        consumption = ExecutionLeaseConsumption(
            institution_id=lease.institution_id,
            executor_id=lease.executor_id,
            lease_digest=lease.artifact_digest,
            request_digest=lease.request_digest,
            mcp_registry_snapshot_digest=current_registry,
            emergency_stop_state_digest=stop.artifact_digest,
            consumed_at=consumed_at,
        )
        self._ledger.consume(consumption)
        return consumption

    def build_receipt(
        self,
        request: AgentActionEnvelope,
        outcome: McpPolicyEnforcementOutcome,
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
        if not isinstance(request, AgentActionEnvelope) or request.artifact_digest != outcome.request.artifact_digest:
            raise ValueError("execution receipt requires the exact authorized request")
        self._validate_lease_linkage(lease, outcome)
        _require_text("executor_id", executor_id)
        if executor_id != lease.executor_id:
            raise ValueError("execution receipt executor does not match the execution lease")
        if consumption.institution_id != lease.institution_id or consumption.executor_id != lease.executor_id:
            raise ValueError("execution lease consumption institution/executor mismatch")
        if consumption.lease_digest != lease.artifact_digest or consumption.request_digest != request.artifact_digest:
            raise ValueError("execution lease consumption is bound to a different lease or request")
        if consumption.mcp_registry_snapshot_digest != lease.mcp_registry_snapshot_digest:
            raise ValueError("execution lease consumption MCP snapshot mismatch")
        if consumption.emergency_stop_state_digest != lease.emergency_stop_state_digest:
            raise ValueError("execution lease consumption emergency-stop mismatch")
        self._ledger.assert_recorded(consumption)
        consumed = _parse_time("consumed_at", consumption.consumed_at)
        started = _parse_time("started_at", started_at)
        completed = _parse_time("completed_at", completed_at)
        if started < consumed:
            raise ValueError("execution cannot start before one-time lease consumption")
        if started >= _parse_time("lease expires_at", lease.expires_at):
            raise ValueError("execution cannot start after the execution lease expires")
        if completed < started:
            raise ValueError("execution completion cannot predate execution start")
        authorization = outcome.authorization
        assert authorization is not None
        return ToolExecutionReceipt(
            receipt_id=receipt_id,
            institution_id=request.institution_id,
            executor_id=lease.executor_id,
            request_digest=request.artifact_digest,
            tool_id=request.tool_id,
            action=request.action,
            resource=request.resource,
            input_digest=request.input_digest,
            execution_lease_digest=lease.artifact_digest,
            lease_consumption_digest=consumption.artifact_digest,
            mcp_policy_enforcement_result_digest=outcome.result.artifact_digest,
            authenticated_authorization_digest=authorization.artifact_digest,
            policy_decision=authorization.decision,
            policy_decision_digest=authorization.authorization.decision_digest,
            approval_requirement_digest=lease.approval_requirement_digest,
            approval_resolution_digest=lease.approval_resolution_digest,
            emergency_stop_state_digest=lease.emergency_stop_state_digest,
            result_digest=result_digest,
            execution_outcome=execution_outcome,
            started_at=started_at,
            completed_at=completed_at,
        )