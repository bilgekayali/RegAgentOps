from __future__ import annotations

from dataclasses import dataclass

from .models import (
    AgentActionEnvelope,
    AuthorizationDecision,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    digest_artifact,
)
from .registry import AgentRegistry, ToolRegistry


@dataclass(frozen=True, slots=True)
class PolicyRule:
    rule_id: str
    institution_id: str
    agent_id: str
    tool_id: str
    action: str
    business_purposes: tuple[str, ...]
    environments: tuple[Environment, ...]
    data_classifications: tuple[DataClassification, ...]
    risk_tiers: tuple[RiskTier, ...]
    effect: Decision
    constraints: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("rule_id", "institution_id", "agent_id", "tool_id", "action"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{name} must be non-empty bounded text")
        if not self.business_purposes or not self.environments or not self.data_classifications or not self.risk_tiers:
            raise ValueError("policy rule match dimensions must not be empty")
        if len(set(self.business_purposes)) != len(self.business_purposes):
            raise ValueError("business_purposes must be unique")
        if self.effect is Decision.ALLOW_WITH_CONSTRAINTS and not self.constraints:
            raise ValueError("ALLOW_WITH_CONSTRAINTS rules require at least one constraint")
        if self.effect is not Decision.ALLOW_WITH_CONSTRAINTS and self.constraints:
            raise ValueError("constraints are only valid for ALLOW_WITH_CONSTRAINTS rules")

    def matches(self, request: AgentActionEnvelope) -> bool:
        return (
            self.institution_id == request.institution_id
            and self.agent_id == request.agent_id
            and self.tool_id == request.tool_id
            and self.action == request.action
            and request.business_purpose in self.business_purposes
            and request.environment in self.environments
            and request.data_classification in self.data_classifications
            and request.risk_tier in self.risk_tiers
        )


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    institution_id: str
    rules: tuple[PolicyRule, ...]
    schema_version: str = "regagentops.policy-bundle.v1"

    def __post_init__(self) -> None:
        if not self.institution_id.strip():
            raise ValueError("institution_id must not be empty")
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("policy bundle contains duplicate rule ids")
        if any(rule.institution_id != self.institution_id for rule in self.rules):
            raise ValueError("every policy rule must belong to the policy bundle institution")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


class PolicyEngine:
    def __init__(self, agents: AgentRegistry, tools: ToolRegistry) -> None:
        self._agents = agents
        self._tools = tools

    def evaluate(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        *,
        evaluated_at: str,
    ) -> AuthorizationDecision:
        if policy.institution_id != request.institution_id:
            return self._deny(request, policy, evaluated_at, "institution_policy_mismatch")

        agent = self._agents.get(request.institution_id, request.agent_id)
        if agent is None:
            return self._deny(request, policy, evaluated_at, "agent_not_registered")
        if not agent.enabled:
            return self._deny(request, policy, evaluated_at, "agent_disabled")
        if (
            agent.human_owner_id != request.human_owner_id
            or agent.model_provider != request.model_provider
            or agent.model_id != request.model_id
        ):
            return self._deny(request, policy, evaluated_at, "agent_identity_context_mismatch")

        tool = self._tools.get(request.institution_id, request.tool_id, request.action)
        if tool is None:
            return self._deny(request, policy, evaluated_at, "tool_action_not_registered")
        if not tool.enabled:
            return self._deny(request, policy, evaluated_at, "tool_action_disabled")
        if request.data_classification not in tool.allowed_data_classifications:
            return self._deny(request, policy, evaluated_at, "tool_data_classification_not_registered")
        if request.environment is Environment.PRODUCTION and not tool.production_registered:
            return self._deny(request, policy, evaluated_at, "tool_not_registered_for_production")

        matched = tuple(sorted((rule for rule in policy.rules if rule.matches(request)), key=lambda item: item.rule_id))
        if not matched:
            return self._deny(request, policy, evaluated_at, "default_deny_no_matching_rule")

        matched_ids = tuple(rule.rule_id for rule in matched)
        effects = {rule.effect for rule in matched}
        if Decision.DENY in effects:
            return self._decision(
                request, policy, evaluated_at, Decision.DENY, matched_ids, (), ("explicit_deny_rule",)
            )
        if Decision.REQUIRE_HUMAN_APPROVAL in effects:
            return self._decision(
                request,
                policy,
                evaluated_at,
                Decision.REQUIRE_HUMAN_APPROVAL,
                matched_ids,
                (),
                ("human_approval_required_by_policy",),
            )

        constraints = tuple(sorted({value for rule in matched for value in rule.constraints}))
        if constraints:
            return self._decision(
                request,
                policy,
                evaluated_at,
                Decision.ALLOW_WITH_CONSTRAINTS,
                matched_ids,
                constraints,
                ("explicit_policy_allow_with_constraints",),
            )
        return self._decision(
            request,
            policy,
            evaluated_at,
            Decision.ALLOW,
            matched_ids,
            (),
            ("explicit_policy_allow",),
        )

    def _deny(
        self,
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        evaluated_at: str,
        reason: str,
    ) -> AuthorizationDecision:
        return self._decision(request, policy, evaluated_at, Decision.DENY, (), (), (reason,))

    @staticmethod
    def _decision(
        request: AgentActionEnvelope,
        policy: PolicyBundle,
        evaluated_at: str,
        decision: Decision,
        matched_rule_ids: tuple[str, ...],
        constraints: tuple[str, ...],
        reason_codes: tuple[str, ...],
    ) -> AuthorizationDecision:
        return AuthorizationDecision(
            request_digest=request.artifact_digest,
            policy_bundle_digest=policy.artifact_digest,
            decision=decision,
            matched_rule_ids=matched_rule_ids,
            constraints=constraints,
            reason_codes=reason_codes,
            human_approval_required=decision is Decision.REQUIRE_HUMAN_APPROVAL,
            policy_permits_execution=decision in {Decision.ALLOW, Decision.ALLOW_WITH_CONSTRAINTS},
            evaluated_at=evaluated_at,
        )
