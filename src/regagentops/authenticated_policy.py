from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re

from .authenticated_identity_signature import (
    AuthenticatedIdentitySignatureError,
    SignedAuthenticatedAgentIdentity,
    verify_signed_authenticated_agent_identity,
)
from .identity_models import AuthenticatedAgentIdentity, WorkloadIdentityTrustBundle
from .models import AgentActionEnvelope, AuthorizationDecision, Decision, digest_artifact
from .policy import PolicyBundle, PolicyEngine
from .registry import AgentRegistry, ToolRegistry

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AuthenticatedAuthorizationDecision:
    request_digest: str
    identity_context_digest: str
    authorization: AuthorizationDecision
    identity_verified: bool
    evaluated_at: str
    schema_version: str = "regagentops.authenticated-authorization-decision.v1"

    def __post_init__(self) -> None:
        if not _HEX_64.fullmatch(self.request_digest):
            raise ValueError("request_digest must be a lowercase SHA-256 digest")
        if not _HEX_64.fullmatch(self.identity_context_digest):
            raise ValueError("identity_context_digest must be a lowercase SHA-256 digest")
        if self.authorization.request_digest != self.request_digest:
            raise ValueError("nested authorization must bind the same request digest")
        if self.authorization.evaluated_at != self.evaluated_at:
            raise ValueError("nested authorization must use the same evaluation time")
        if not self.identity_verified and (
            self.authorization.decision is not Decision.DENY
            or self.authorization.human_approval_required
            or self.authorization.policy_permits_execution
        ):
            raise ValueError("unverified identity must produce a non-executable DENY decision")

    @property
    def decision(self) -> Decision:
        return self.authorization.decision

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class AuthenticatedPolicyEngine:
    def __init__(self, agents: AgentRegistry, tools: ToolRegistry) -> None:
        self._agents = agents
        self._base = PolicyEngine(agents, tools)

    def evaluate(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        identity: SignedAuthenticatedAgentIdentity,
        *,
        identity_trust_bundle: WorkloadIdentityTrustBundle,
        evaluated_at: str,
    ) -> AuthenticatedAuthorizationDecision:
        try:
            verified_identity = verify_signed_authenticated_agent_identity(
                identity,
                trust_bundle=identity_trust_bundle,
                now=evaluated_at,
            )
        except AuthenticatedIdentitySignatureError:
            return self._identity_deny(
                request,
                policy,
                identity.artifact_digest,
                evaluated_at,
                "authenticated_identity_context_untrusted_or_expired",
            )

        reason = self._identity_failure_reason(request, verified_identity, evaluated_at)
        if reason is None:
            base = self._base.evaluate(request, policy, evaluated_at=evaluated_at)
            verified = True
        else:
            base = self._denied_authorization(request, policy, evaluated_at, reason)
            verified = False
        return AuthenticatedAuthorizationDecision(
            request_digest=request.artifact_digest,
            identity_context_digest=identity.artifact_digest,
            authorization=base,
            identity_verified=verified,
            evaluated_at=evaluated_at,
        )

    def _identity_deny(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        identity_context_digest: str,
        evaluated_at: str,
        reason: str,
    ) -> AuthenticatedAuthorizationDecision:
        return AuthenticatedAuthorizationDecision(
            request_digest=request.artifact_digest,
            identity_context_digest=identity_context_digest,
            authorization=self._denied_authorization(request, policy, evaluated_at, reason),
            identity_verified=False,
            evaluated_at=evaluated_at,
        )

    @staticmethod
    def _denied_authorization(
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        evaluated_at: str,
        reason: str,
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            request_digest=request.artifact_digest,
            policy_bundle_digest=policy.artifact_digest,
            decision=Decision.DENY,
            matched_rule_ids=(),
            constraints=(),
            reason_codes=(reason,),
            human_approval_required=False,
            policy_permits_execution=False,
            evaluated_at=evaluated_at,
        )

    def _identity_failure_reason(
        self,
        request: AgentActionEnvelope,
        identity: AuthenticatedAgentIdentity,
        evaluated_at: str,
    ) -> str | None:
        if (
            identity.institution_id != request.institution_id
            or identity.agent_id != request.agent_id
            or identity.human_owner_id != request.human_owner_id
        ):
            return "authenticated_identity_context_mismatch"
        try:
            now = datetime.fromisoformat(evaluated_at[:-1] + "+00:00")
            established = datetime.fromisoformat(identity.established_at[:-1] + "+00:00")
            valid_until = datetime.fromisoformat(identity.valid_until[:-1] + "+00:00")
        except (ValueError, TypeError):
            return "authenticated_identity_time_invalid"
        if now < established or now >= valid_until:
            return "authenticated_identity_expired_or_not_yet_valid"
        agent = self._agents.get(request.institution_id, request.agent_id)
        if agent is None or not agent.enabled:
            return "authenticated_identity_agent_not_registered_or_disabled"
        if digest_artifact(agent) != identity.agent_descriptor_digest:
            return "authenticated_identity_agent_registration_changed"
        return None
