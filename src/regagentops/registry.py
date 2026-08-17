from __future__ import annotations

from dataclasses import dataclass

from .models import AgentDescriptor, ToolActionDescriptor


@dataclass(frozen=True, slots=True)
class AgentRegistry:
    agents: tuple[AgentDescriptor, ...]

    def __post_init__(self) -> None:
        keys = [(agent.institution_id, agent.agent_id) for agent in self.agents]
        if len(set(keys)) != len(keys):
            raise ValueError("agent registry contains duplicate institution/agent identities")

    def get(self, institution_id: str, agent_id: str) -> AgentDescriptor | None:
        for agent in self.agents:
            if agent.institution_id == institution_id and agent.agent_id == agent_id:
                return agent
        return None


@dataclass(frozen=True, slots=True)
class ToolRegistry:
    actions: tuple[ToolActionDescriptor, ...]

    def __post_init__(self) -> None:
        keys = [(item.institution_id, item.tool_id, item.action) for item in self.actions]
        if len(set(keys)) != len(keys):
            raise ValueError("tool registry contains duplicate institution/tool/action identities")

    def get(self, institution_id: str, tool_id: str, action: str) -> ToolActionDescriptor | None:
        for item in self.actions:
            if item.institution_id == institution_id and item.tool_id == tool_id and item.action == action:
                return item
        return None
