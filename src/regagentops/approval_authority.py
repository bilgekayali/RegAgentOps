from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .approval_models import ApprovalAuthorityBundle, ApprovalAuthorityGrant, GrantType, _RISK_ORDER
from .models import AgentActionEnvelope


class ApprovalAuthorityError(ValueError):
    pass


def _parse(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ApprovalAuthorityError("approval authority time must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ApprovalAuthorityError("approval authority time is invalid") from exc


@dataclass(frozen=True, slots=True)
class ApprovalAuthorityRegistry:
    bundle: ApprovalAuthorityBundle

    def __post_init__(self) -> None:
        by_digest = {grant.artifact_digest: grant for grant in self.bundle.grants}
        for grant in self.bundle.grants:
            self._validate_grant(grant, by_digest, trail=())

    def _validate_grant(
        self,
        grant: ApprovalAuthorityGrant,
        by_digest: dict[str, ApprovalAuthorityGrant],
        *,
        trail: tuple[str, ...],
    ) -> None:
        digest = grant.artifact_digest
        if digest in trail:
            raise ApprovalAuthorityError("approval delegation cycle detected")
        if grant.grant_type is GrantType.DIRECT:
            return
        parent = by_digest.get(grant.parent_grant_digest or "")
        if parent is None:
            raise ApprovalAuthorityError("delegated approval grant parent is missing")
        self._validate_grant(parent, by_digest, trail=trail + (digest,))
        if not parent.can_delegate:
            raise ApprovalAuthorityError("parent approval grant does not permit delegation")
        if grant.issuer_principal_id != parent.subject_principal_id:
            raise ApprovalAuthorityError("delegated grant issuer must be the parent grant subject")
        if grant.institution_id != parent.institution_id:
            raise ApprovalAuthorityError("delegated grant cannot cross institutions")
        if not set(grant.allowed_tool_ids).issubset(parent.allowed_tool_ids):
            raise ApprovalAuthorityError("delegated grant cannot widen tool scope")
        if not set(grant.allowed_actions).issubset(parent.allowed_actions):
            raise ApprovalAuthorityError("delegated grant cannot widen action scope")
        if not set(grant.allowed_environments).issubset(parent.allowed_environments):
            raise ApprovalAuthorityError("delegated grant cannot widen environment scope")
        if _RISK_ORDER[grant.max_risk_tier] > _RISK_ORDER[parent.max_risk_tier]:
            raise ApprovalAuthorityError("delegated grant cannot increase maximum risk tier")
        if _parse(grant.valid_from) < _parse(parent.valid_from) or _parse(grant.valid_until) > _parse(parent.valid_until):
            raise ApprovalAuthorityError("delegated grant validity must remain within parent validity")

    def grant_by_digest(self, digest: str) -> ApprovalAuthorityGrant | None:
        matches = [grant for grant in self.bundle.grants if grant.artifact_digest == digest]
        if len(matches) > 1:
            raise ApprovalAuthorityError("approval grant digest is ambiguous")
        return matches[0] if matches else None

    def authorize_approver(
        self,
        *,
        approver_id: str,
        grant_digest: str,
        request: AgentActionEnvelope,
        evaluated_at: str,
        requester_separation_required: bool,
    ) -> ApprovalAuthorityGrant:
        grant = self.grant_by_digest(grant_digest)
        if grant is None:
            raise ApprovalAuthorityError("approval authority grant not found")
        if grant.subject_principal_id != approver_id:
            raise ApprovalAuthorityError("approval signer is not the grant subject")
        now = _parse(evaluated_at)
        if not (_parse(grant.valid_from) <= now < _parse(grant.valid_until)):
            raise ApprovalAuthorityError("approval authority grant is not currently valid")
        if grant.institution_id != request.institution_id:
            raise ApprovalAuthorityError("approval authority institution mismatch")
        if request.tool_id not in grant.allowed_tool_ids or request.action not in grant.allowed_actions:
            raise ApprovalAuthorityError("approval authority does not cover the requested tool action")
        if request.environment not in grant.allowed_environments:
            raise ApprovalAuthorityError("approval authority does not cover the requested environment")
        if _RISK_ORDER[request.risk_tier] > _RISK_ORDER[grant.max_risk_tier]:
            raise ApprovalAuthorityError("approval authority does not cover the request risk tier")
        if requester_separation_required and approver_id == request.human_owner_id:
            raise ApprovalAuthorityError("requester and approver must be separated")
        return grant
