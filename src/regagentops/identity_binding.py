from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .identity_models import AuthenticatedAgentIdentity, HumanIdentityAssertion, SignedWorkloadIdentity, WorkloadIdentityTrustBundle
from .models import AgentDescriptor, digest_artifact
from .workload_identity import verify_workload_identity


class IdentityBindingError(ValueError):
    pass


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class HumanIdentityRegistration:
    institution_id: str
    human_owner_id: str
    provider_id: str
    subject: str

    def __post_init__(self) -> None:
        for name in ("institution_id", "human_owner_id", "provider_id", "subject"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{name} must be non-empty bounded text")


class HumanIdentityRegistry:
    def __init__(self, registrations: tuple[HumanIdentityRegistration, ...] = ()) -> None:
        self._items: dict[tuple[str, str], HumanIdentityRegistration] = {}
        for registration in registrations:
            self.register(registration)

    def register(self, registration: HumanIdentityRegistration) -> None:
        key = (registration.institution_id, registration.human_owner_id)
        if key in self._items:
            raise ValueError("human identity registration already exists")
        self._items[key] = registration

    def get(self, institution_id: str, human_owner_id: str) -> HumanIdentityRegistration | None:
        return self._items.get((institution_id, human_owner_id))


def establish_authenticated_agent_identity(
    agent: AgentDescriptor,
    *,
    human_identity: HumanIdentityAssertion,
    workload_identity: SignedWorkloadIdentity,
    workload_trust_bundle: WorkloadIdentityTrustBundle,
    established_at: str,
) -> AuthenticatedAgentIdentity:
    now = _parse_timestamp(established_at)
    if human_identity.institution_id != agent.institution_id:
        raise IdentityBindingError("human identity institution does not match registered agent")
    if human_identity.human_owner_id != agent.human_owner_id:
        raise IdentityBindingError("human identity owner does not match registered agent")
    human_issued = _parse_timestamp(human_identity.issued_at)
    human_expires = _parse_timestamp(human_identity.expires_at)
    if human_issued > now or human_expires <= now:
        raise IdentityBindingError("human identity is not valid at context establishment time")

    statement = verify_workload_identity(
        workload_identity,
        trust_bundle=workload_trust_bundle,
        now=established_at,
    )
    if statement.institution_id != agent.institution_id:
        raise IdentityBindingError("workload institution does not match registered agent")
    if statement.agent_id != agent.agent_id:
        raise IdentityBindingError("workload agent id does not match registered agent")
    if statement.human_owner_id != agent.human_owner_id:
        raise IdentityBindingError("workload human owner does not match registered agent")
    if statement.model_provider != agent.model_provider or statement.model_id != agent.model_id:
        raise IdentityBindingError("workload model identity does not match registered agent")

    valid_until = min(human_expires, _parse_timestamp(statement.expires_at))
    if valid_until <= now:
        raise IdentityBindingError("authenticated agent context would already be expired")
    return AuthenticatedAgentIdentity(
        institution_id=agent.institution_id,
        agent_id=agent.agent_id,
        human_owner_id=agent.human_owner_id,
        provider_id=human_identity.provider_id,
        workload_id=statement.workload_id,
        agent_descriptor_digest=digest_artifact(agent),
        human_identity_digest=human_identity.artifact_digest,
        workload_identity_digest=workload_identity.artifact_digest,
        established_at=established_at,
        valid_until=_format_timestamp(valid_until),
    )
