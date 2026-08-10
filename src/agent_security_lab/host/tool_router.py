"""Tool name resolution and shadowing / collision detection."""

from __future__ import annotations

from dataclasses import dataclass

from agent_security_lab.host.client import MCPClientManager, RemoteTool
from agent_security_lab.policy.description_guard import check_description


@dataclass
class RouteResult:
    tool: RemoteTool | None
    error: str | None = None
    alerts: list[str] | None = None


def route_tool(
    manager: MCPClientManager,
    name: str,
    *,
    conflict_mode: str = "deny",
) -> RouteResult:
    alerts: list[str] = []
    try:
        tool = manager.resolve(name, conflict_mode=conflict_mode)
    except LookupError as exc:
        return RouteResult(tool=None, error=str(exc), alerts=["name_conflict"])
    except KeyError as exc:
        return RouteResult(tool=None, error=str(exc))

    # Shadowing heuristics on description
    desc_check = check_description(tool.namespaced, tool.description, enforce_diff=False)
    alerts.extend(desc_check.alerts)
    return RouteResult(tool=tool, error=None, alerts=alerts)
