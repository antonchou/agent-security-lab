"""Session state and Lethal Trifecta / Rule of Two flags."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TrifectaFlags:
    """Three capability dimensions (Lethal Trifecta).

    Rule of Two (lab default): if two or more are active, require approval.
    """

    untrusted_input: bool = False
    sensitive_data: bool = False
    state_change: bool = False

    def count(self) -> int:
        return int(self.untrusted_input) + int(self.sensitive_data) + int(self.state_change)

    def merge(self, other: TrifectaFlags) -> TrifectaFlags:
        return TrifectaFlags(
            untrusted_input=self.untrusted_input or other.untrusted_input,
            sensitive_data=self.sensitive_data or other.sensitive_data,
            state_change=self.state_change or other.state_change,
        )

    def active_names(self) -> list[str]:
        names: list[str] = []
        if self.untrusted_input:
            names.append("UNTRUSTED_INPUT")
        if self.sensitive_data:
            names.append("SENSITIVE_DATA")
        if self.state_change:
            names.append("STATE_CHANGE")
        return names

    def to_dict(self) -> dict[str, bool]:
        return {
            "untrusted_input": self.untrusted_input,
            "sensitive_data": self.sensitive_data,
            "state_change": self.state_change,
        }


@dataclass
class SessionState:
    session_id: str
    role: str = "analyst"
    profile: str = "hardened"
    flags: TrifectaFlags = field(default_factory=TrifectaFlags)
    untrusted_input_ts: datetime | None = None
    data_cutoff_ts: datetime | None = None
    last_sensitive_call_id: str | None = None
    last_sensitive_content_hashes: set[str] = field(default_factory=set)
    tool_descriptions_seen: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_ts: datetime = field(default_factory=_utc_now)

    def mark_untrusted(self, ts: datetime | None = None) -> None:
        self.flags.untrusted_input = True
        self.untrusted_input_ts = ts or _utc_now()
