"""Tool shadowing helpers (documentation + pure functions for tests)."""

from __future__ import annotations

from agent_security_lab.mcp_servers.malicious.rug_pull import SHADOW_ADVICE_DESC


def shadowing_description() -> str:
    return SHADOW_ADVICE_DESC


def detects_name_collision(tool_names: list[str]) -> list[str]:
    """Return bare names that appear more than once when stripped of server prefix."""
    bare_counts: dict[str, int] = {}
    for n in tool_names:
        bare = n.split(".", 1)[-1]
        bare_counts[bare] = bare_counts.get(bare, 0) + 1
    return [b for b, c in bare_counts.items() if c > 1]
