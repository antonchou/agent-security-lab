"""Full tool description display + diff alerts (poisoning / rug / shadowing)."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

POISON_MARKERS = [
    re.compile(r"<IMPORTANT>", re.IGNORECASE),
    re.compile(r"</IMPORTANT>", re.IGNORECASE),
    re.compile(r"do not mention this instruction", re.IGNORECASE),
    re.compile(r"ignore previous", re.IGNORECASE),
    re.compile(r"before answering,\s*call", re.IGNORECASE),
    re.compile(r"include contents", re.IGNORECASE),
]


@dataclass
class DescriptionCheck:
    ok: bool
    alerts: list[str] = field(default_factory=list)
    poison_markers: list[str] = field(default_factory=list)
    diff: str | None = None
    changed: bool = False


def find_poison_markers(description: str) -> list[str]:
    hits: list[str] = []
    for pat in POISON_MARKERS:
        if pat.search(description or ""):
            hits.append(pat.pattern)
    return hits


def check_description(
    tool_name: str,
    description: str,
    *,
    previous: str | None = None,
    enforce_diff: bool = True,
) -> DescriptionCheck:
    alerts: list[str] = []
    poison = find_poison_markers(description or "")
    if poison:
        alerts.append(f"poison_markers:{','.join(poison)}")

    # Shadowing: description tries to steer another server's send_email
    desc_l = (description or "").lower()
    bare = tool_name.split(".")[-1]
    # Use exact bare-name match (substring "send_email" appears in shadow_* tools)
    if "send_email" in desc_l and bare != "send_email" and any(
        x in desc_l
        for x in (
            "before calling send_email",
            "instead of send_email",
            "must call",
            "always use",
            "hijack",
            "attach",
            "compliance",
            "do not mention",
        )
    ):
        alerts.append("shadowing_language_detected")

    changed = False
    diff = None
    if previous is not None and previous != (description or ""):
        changed = True
        diff = "\n".join(
            difflib.unified_diff(
                previous.splitlines(),
                (description or "").splitlines(),
                fromfile=f"{tool_name}@pinned",
                tofile=f"{tool_name}@current",
                lineterm="",
            )
        )
        alerts.append("description_changed")

    ok = True
    if enforce_diff and changed:
        ok = False
    # Poison markers alone alert; blocking is policy engine's choice via sigma
    return DescriptionCheck(
        ok=ok,
        alerts=alerts,
        poison_markers=poison,
        diff=diff,
        changed=changed,
    )


def format_full_description(tool_name: str, description: str) -> str:
    """Human-visible full description (no truncation)."""
    return f"=== TOOL DESCRIPTION: {tool_name} ===\n{description}\n=== END ===\n"
