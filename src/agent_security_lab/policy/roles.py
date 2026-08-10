"""Role / capability matrix (inspired by ai-quant-platform agent roles)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RoleSpec:
    name: str
    can_read_public: bool
    can_read_sensitive: bool
    can_state_change: bool
    description: str


ROLES: dict[str, RoleSpec] = {
    "observer": RoleSpec(
        name="observer",
        can_read_public=True,
        can_read_sensitive=False,
        can_state_change=False,
        description="List/calculate only; no sensitive or outbound actions.",
    ),
    "analyst": RoleSpec(
        name="analyst",
        can_read_public=True,
        can_read_sensitive=True,  # only via approval when Rule of Two fires
        can_state_change=False,
        description="Research role; state change forbidden without upgrade.",
    ),
    "operator": RoleSpec(
        name="operator",
        can_read_public=True,
        can_read_sensitive=True,
        can_state_change=True,
        description="May perform state change with single-use approval token.",
    ),
}


def get_role(name: str) -> RoleSpec:
    key = name.lower()
    if key not in ROLES:
        raise KeyError(f"unknown role: {name}")
    return ROLES[key]
