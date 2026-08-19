from __future__ import annotations

import argparse
import json

from . import __version__
from . import api as stable_api
from .models import (
    AgentActionEnvelope,
    AgentDescriptor,
    DataClassification,
    Decision,
    Environment,
    RiskTier,
    ToolActionDescriptor,
    canonical_json,
)
from .policy import PolicyBundle, PolicyEngine, PolicyRule
from .registry import AgentRegistry, ToolRegistry


STABLE_CLI_COMMANDS = ("contract-snapshot", "demo-decision")


def _demo_decision() -> dict[str, object]:
    agent = AgentDescriptor(
        institution_id="bank-demo",
        agent_id="ops-assistant",
        human_owner_id="owner-123",
        model_provider="example-provider",
        model_id="example-model",
    )
    tool = ToolActionDescriptor(
        institution_id="bank-demo",
        tool_id="customer-records",
        action="read-summary",
        allowed_data_classifications=(DataClassification.CONFIDENTIAL,),
    )
    request = AgentActionEnvelope(
        request_id="req-demo-001",
        institution_id="bank-demo",
        agent_id=agent.agent_id,
        human_owner_id=agent.human_owner_id,
        model_provider=agent.model_provider,
        model_id=agent.model_id,
        tool_id=tool.tool_id,
        action=tool.action,
        resource="customer/summary",
        data_classification=DataClassification.CONFIDENTIAL,
        business_purpose="customer-support",
        environment=Environment.TEST,
        risk_tier=RiskTier.MODERATE,
        input_digest="0" * 64,
        requested_at="2026-01-01T00:00:00Z",
    )
    policy = PolicyBundle(
        institution_id="bank-demo",
        rules=(
            PolicyRule(
                rule_id="demo-read-with-redaction",
                institution_id="bank-demo",
                agent_id=agent.agent_id,
                tool_id=tool.tool_id,
                action=tool.action,
                business_purposes=("customer-support",),
                environments=(Environment.TEST,),
                data_classifications=(DataClassification.CONFIDENTIAL,),
                risk_tiers=(RiskTier.MODERATE,),
                effect=Decision.ALLOW_WITH_CONSTRAINTS,
                constraints=("redact-sensitive-fields", "read-only"),
            ),
        ),
    )
    decision = PolicyEngine(AgentRegistry((agent,)), ToolRegistry((tool,))).evaluate(
        request,
        policy,
        evaluated_at="2026-01-01T00:00:01Z",
    )
    return {
        "request_digest": request.artifact_digest,
        "policy_bundle_digest": policy.artifact_digest,
        "decision": json.loads(canonical_json(decision)),
        "execution_performed": False,
    }


def _contract_snapshot() -> dict[str, object]:
    return {
        "release_version": __version__,
        "stable_since_version": "1.0.0",
        "stable_python_api_symbols": [f"regagentops.api.{name}" for name in stable_api.__all__],
        "stable_cli_commands": list(STABLE_CLI_COMMANDS),
        "json_schema_compatibility_baseline": "v1",
        "execution_performed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="regagentops",
        description="Offline RegAgentOps stable governed authorization and evidence reference",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser(
        "contract-snapshot",
        help="print the deterministic v1 public API/CLI/schema compatibility boundary",
    )
    subcommands.add_parser(
        "demo-decision",
        help="evaluate a deterministic synthetic authorization request without executing any tool",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "contract-snapshot":
        print(json.dumps(_contract_snapshot(), indent=2, sort_keys=True))
        return 0
    if args.command == "demo-decision":
        print(json.dumps(_demo_decision(), indent=2, sort_keys=True))
        return 0
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
