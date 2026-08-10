"""Immutable tool-call intent (maps to quant-selector OrderRequest / signal_ts)."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON for hashing (sort keys, no whitespace variance)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def intent_hash_from_parts(
    server_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    session_id: str,
    role: str,
) -> str:
    payload = {
        "server_id": server_id,
        "tool_name": tool_name,
        "arguments": dict(arguments),
        "session_id": session_id,
        "role": role,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolCallIntent:
    """Frozen intent object bound to approval tokens via intent_hash.

    ``data_cutoff_ts`` mirrors quant-selector ``signal_ts``: policy may refuse
    using sensitive context that appeared after this cutoff.
    """

    session_id: str
    server_id: str
    tool_name: str  # namespaced, e.g. benign.send_email
    arguments: Mapping[str, Any]
    role: str = "analyst"
    intent_id: str = field(default_factory=lambda: f"intent-{uuid.uuid4().hex[:12]}")
    created_ts: datetime = field(default_factory=_utc_now)
    untrusted_input_ts: datetime | None = None
    data_cutoff_ts: datetime | None = None
    parent_call_id: str | None = None
    intent_hash: str = ""

    def __post_init__(self) -> None:
        # frozendataclass: use object.__setattr__
        args = dict(self.arguments)
        object.__setattr__(self, "arguments", args)
        if not self.intent_hash:
            h = intent_hash_from_parts(
                self.server_id,
                self.tool_name,
                args,
                self.session_id,
                self.role,
            )
            object.__setattr__(self, "intent_hash", h)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d


def intent_hash(intent: ToolCallIntent) -> str:
    return intent.intent_hash
