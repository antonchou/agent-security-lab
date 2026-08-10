"""Cross-server data-flow / taint tracking."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@dataclass
class FlowEdge:
    from_call_id: str
    to_call_id: str
    from_server: str
    to_server: str
    taint_hash: str
    kind: str  # sensitive_to_outbound etc.

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_call_id": self.from_call_id,
            "to_call_id": self.to_call_id,
            "from_server": self.from_server,
            "to_server": self.to_server,
            "taint_hash": self.taint_hash,
            "kind": self.kind,
        }


@dataclass
class DataFlowTracker:
    edges: list[FlowEdge] = field(default_factory=list)
    # session_id -> list of (call_id, server, hash, sensitive)
    _taints: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_output(
        self,
        session_id: str,
        call_id: str,
        server_id: str,
        content: str,
        *,
        sensitive: bool,
    ) -> str:
        h = content_hash(content)
        with self._lock:
            self._taints.setdefault(session_id, []).append(
                {
                    "call_id": call_id,
                    "server_id": server_id,
                    "hash": h,
                    "sensitive": sensitive,
                    "snippet": content[:80],
                }
            )
        return h

    def check_outbound(
        self,
        session_id: str,
        call_id: str,
        server_id: str,
        body: str,
    ) -> list[FlowEdge]:
        """If outbound body contains prior sensitive content hashes/snippets, link edges."""
        found: list[FlowEdge] = []
        with self._lock:
            prior = list(self._taints.get(session_id, []))
        for t in prior:
            if not t.get("sensitive"):
                continue
            snippet = t.get("snippet") or ""
            # Match either full hash marker or overlapping sensitive snippet
            if t["hash"] in body or (len(snippet) >= 12 and snippet in body):
                edge = FlowEdge(
                    from_call_id=t["call_id"],
                    to_call_id=call_id,
                    from_server=t["server_id"],
                    to_server=server_id,
                    taint_hash=t["hash"],
                    kind="sensitive_to_outbound",
                )
                found.append(edge)
        with self._lock:
            self.edges.extend(found)
        return found

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._taints.pop(session_id, None)
