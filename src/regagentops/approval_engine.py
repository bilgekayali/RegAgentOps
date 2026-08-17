from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .approval_authority import ApprovalAuthorityError, ApprovalAuthorityRegistry
from .approval_models import (
    ApprovalEscalationPolicy,
    ApprovalRequirement,
    ApprovalResolution,
    ApprovalVote,
)
from .approval_replay import ApprovalReplayLedger
from .approval_signature import (
    ApprovalSignatureError,
    ApprovalTrustBundle,
    SignedApprovalStatement,
    verify_signed_approval,
)
from .authenticated_policy import AuthenticatedAuthorizationDecision
from .models import AgentActionEnvelope, Decision, RiskTier, digest_artifact


class ApprovalGateError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SignedApprovalPackage:
    requirement: ApprovalRequirement
    approvals: tuple[SignedApprovalStatement, ...]
    schema_version: str = "regagentops.signed-approval-package.v1"

    def __post_init__(self) -> None:
        if len(self.approvals) > 5:
            raise ValueError("approval package cannot contain more than five approvals")
        approval_ids = [item.statement.approval_id for item in self.approvals]
        if len(approval_ids) != len(set(approval_ids)):
            raise ValueError("approval package contains duplicate approval ids")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


def _parse(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ApprovalGateError("approval time must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ApprovalGateError("approval time is invalid") from exc


def _format(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ApprovalGate:
    def __init__(
        self,
        *,
        authority_registry: ApprovalAuthorityRegistry,
        trust_bundle: ApprovalTrustBundle,
        replay_ledger: ApprovalReplayLedger,
    ) -> None:
        if authority_registry.bundle.institution_id != trust_bundle.institution_id:
            raise ApprovalGateError("approval authority and trust bundle institutions must match")
        self._authority = authority_registry
        self._trust = trust_bundle
        self._replay = replay_ledger

    @staticmethod
    def build_requirement(
        request: AgentActionEnvelope,
        authorization: AuthenticatedAuthorizationDecision,
        *,
        escalation_policy: ApprovalEscalationPolicy,
        issued_at: str,
    ) -> ApprovalRequirement | None:
        if escalation_policy.institution_id != request.institution_id:
            raise ApprovalGateError("approval escalation policy institution mismatch")
        if authorization.request_digest != request.artifact_digest:
            raise ApprovalGateError("authenticated authorization does not bind the request")
        if not authorization.identity_verified:
            raise ApprovalGateError("unverified identity cannot enter the approval gate")
        if authorization.decision is Decision.DENY:
            raise ApprovalGateError("DENY decisions cannot be overridden by human approval")

        minimum = 0
        separation = False
        if authorization.decision is Decision.REQUIRE_HUMAN_APPROVAL:
            minimum = escalation_policy.policy_approval_minimum
            separation = True
        if request.risk_tier is RiskTier.HIGH:
            minimum = max(minimum, escalation_policy.high_risk_minimum)
            separation = True
        if request.risk_tier is RiskTier.CRITICAL:
            minimum = max(minimum, escalation_policy.critical_risk_minimum)
            separation = True
        if minimum == 0:
            return None

        issued = _parse(issued_at)
        expires = issued + timedelta(seconds=escalation_policy.max_requirement_lifetime_seconds)
        seed = {
            "purpose": "regagentops.approval-requirement-id.v1",
            "request_digest": request.artifact_digest,
            "authenticated_authorization_digest": authorization.artifact_digest,
            "escalation_policy_digest": escalation_policy.artifact_digest,
            "issued_at": issued_at,
        }
        requirement_id = f"approval-{digest_artifact(seed)[:24]}"
        return ApprovalRequirement(
            requirement_id=requirement_id,
            institution_id=request.institution_id,
            request_digest=request.artifact_digest,
            authenticated_authorization_digest=authorization.artifact_digest,
            identity_context_digest=authorization.identity_context_digest,
            requester_id=request.human_owner_id,
            tool_id=request.tool_id,
            action=request.action,
            environment=request.environment,
            risk_tier=request.risk_tier,
            min_approvals=minimum,
            requester_separation_required=separation,
            escalation_policy_digest=escalation_policy.artifact_digest,
            issued_at=issued_at,
            expires_at=_format(expires),
        )

    def resolve(
        self,
        request: AgentActionEnvelope,
        authorization: AuthenticatedAuthorizationDecision,
        package: SignedApprovalPackage,
        *,
        evaluated_at: str,
    ) -> ApprovalResolution:
        requirement = package.requirement
        if requirement.institution_id != request.institution_id or self._trust.institution_id != request.institution_id:
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_institution_mismatch",))
        if requirement.request_digest != request.artifact_digest:
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_request_digest_mismatch",))
        if requirement.authenticated_authorization_digest != authorization.artifact_digest:
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_authorization_digest_mismatch",))
        if requirement.identity_context_digest != authorization.identity_context_digest:
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_identity_context_mismatch",))
        if not authorization.identity_verified or authorization.decision is Decision.DENY:
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_cannot_override_identity_or_policy_deny",))
        now = _parse(evaluated_at)
        if not (_parse(requirement.issued_at) <= now < _parse(requirement.expires_at)):
            return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_requirement_expired_or_not_yet_valid",))

        approved: list[str] = []
        denied: list[str] = []
        seen_principals: set[str] = set()
        for signed in package.approvals:
            try:
                statement = verify_signed_approval(signed, trust_bundle=self._trust, now=evaluated_at)
            except (ApprovalSignatureError, ValueError):
                return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_signature_invalid",))
            if statement.requirement_digest != requirement.artifact_digest:
                return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_requirement_digest_mismatch",))
            if statement.request_digest != request.artifact_digest:
                return self._resolution(package, request, evaluated_at, False, False, (), (), ("approval_statement_request_mismatch",))
            if statement.approver_id in seen_principals:
                return self._resolution(package, request, evaluated_at, False, False, (), (), ("duplicate_approver_not_counted",))
            try:
                self._authority.authorize_approver(
                    approver_id=statement.approver_id,
                    grant_digest=statement.authority_grant_digest,
                    request=request,
                    evaluated_at=evaluated_at,
                    requester_separation_required=requirement.requester_separation_required,
                )
            except ApprovalAuthorityError:
                return self._resolution(package, request, evaluated_at, False, False, (), (), ("approver_outside_delegated_authority",))
            seen_principals.add(statement.approver_id)
            if statement.vote is ApprovalVote.DENY:
                denied.append(statement.approver_id)
            else:
                approved.append(statement.approver_id)

        terminal = bool(denied) or len(approved) >= requirement.min_approvals
        if not terminal:
            return self._resolution(
                package,
                request,
                evaluated_at,
                False,
                False,
                tuple(sorted(approved)),
                (),
                ("insufficient_valid_approvals",),
            )

        consumed = self._replay.consume(
            approval_package_digest=package.artifact_digest,
            institution_id=request.institution_id,
            requirement_digest=requirement.artifact_digest,
            request_digest=request.artifact_digest,
            redeemed_at=evaluated_at,
        )
        if not consumed:
            return self._resolution(
                package,
                request,
                evaluated_at,
                False,
                False,
                tuple(sorted(approved)),
                tuple(sorted(denied)),
                ("approval_requirement_already_redeemed",),
            )
        if denied:
            return self._resolution(
                package,
                request,
                evaluated_at,
                False,
                True,
                tuple(sorted(approved)),
                tuple(sorted(denied)),
                ("valid_approval_denial_present",),
            )
        return self._resolution(
            package,
            request,
            evaluated_at,
            True,
            True,
            tuple(sorted(approved)),
            (),
            ("approval_requirement_satisfied",),
        )

    @staticmethod
    def _resolution(
        package: SignedApprovalPackage,
        request: AgentActionEnvelope,
        evaluated_at: str,
        satisfied: bool,
        consumed: bool,
        approved_by: tuple[str, ...],
        denied_by: tuple[str, ...],
        reasons: tuple[str, ...],
    ) -> ApprovalResolution:
        return ApprovalResolution(
            institution_id=request.institution_id,
            requirement_digest=package.requirement.artifact_digest,
            request_digest=request.artifact_digest,
            approval_package_digest=package.artifact_digest,
            approval_satisfied=satisfied,
            replay_consumed=consumed,
            approved_by=approved_by,
            denied_by=denied_by,
            reason_codes=reasons,
            authorization_continuation_permitted=satisfied and consumed and not denied_by,
            evaluated_at=evaluated_at,
        )
