"""Audit record shape for tool-call mediation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AuditRecord:
    event: str
    source: str
    session_id: str | None = None
    actor: str | None = None
    role: str | None = None
    intent: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    server_id: str | None = None
    tool_name: str | None = None
    dataflow_edges: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    ts: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(),
            "event": self.event,
            "source": self.source,
            "session_id": self.session_id,
            "actor": self.actor,
            "role": self.role,
            "intent": self.intent,
            "policy": self.policy,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "dataflow_edges": self.dataflow_edges,
            "extra": self.extra,
        }
