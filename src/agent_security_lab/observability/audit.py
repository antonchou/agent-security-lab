"""Independent tool-call audit trail (adapted from quant-selector audit.py)."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_DEFAULT_PATH: Path | None = None


def set_audit_path(path: Path) -> None:
    global _DEFAULT_PATH
    _DEFAULT_PATH = path


def audit_path(path: Path | None = None) -> Path:
    p = path or _DEFAULT_PATH
    if p is None:
        raise RuntimeError("audit path not configured; call set_audit_path or pass path=")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def write_tool_audit(
    *,
    event: str,
    source: str,
    session_id: str | None = None,
    actor: str | None = None,
    role: str | None = None,
    intent: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    server_id: str | None = None,
    tool_name: str | None = None,
    dataflow_edges: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
    path: Path | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "source": source,
        "session_id": session_id,
        "actor": actor,
        "role": role,
        "intent": intent or {},
        "policy": policy or {},
        "server_id": server_id,
        "tool_name": tool_name,
        "dataflow_edges": dataflow_edges or [],
        "extra": extra or {},
    }
    line = json.dumps(record, default=str, ensure_ascii=False)
    with _LOCK:
        with audit_path(path).open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    return record


def read_tool_audits(limit: int = 200, path: Path | None = None) -> list[dict[str, Any]]:
    p = path or _DEFAULT_PATH
    if p is None or not p.exists():
        return []
    rows: list[dict[str, Any]] = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def clear_audit_file(path: Path | None = None) -> None:
    p = path or _DEFAULT_PATH
    if p is not None and p.exists():
        p.write_text("", encoding="utf-8")
