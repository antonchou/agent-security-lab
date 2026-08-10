"""Tool schema pinning (detect MCP rug pulls)."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_security_lab.models.intent import canonical_json


@dataclass
class PinRecord:
    server_id: str
    tool_name: str
    schema_hash: str
    description_hash: str
    description: str
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "schema_hash": self.schema_hash,
            "description_hash": self.description_hash,
            "description": self.description,
            "input_schema": self.input_schema,
        }


def hash_schema(input_schema: dict[str, Any] | None) -> str:
    return hashlib.sha256(
        canonical_json(input_schema or {}).encode("utf-8")
    ).hexdigest()


def hash_description(description: str | None) -> str:
    return hashlib.sha256((description or "").encode("utf-8")).hexdigest()


class SchemaPinStore:
    def __init__(self, pins_dir: Path) -> None:
        self.pins_dir = pins_dir
        self.pins_dir.mkdir(parents=True, exist_ok=True)
        self._pins: dict[str, PinRecord] = {}
        self._lock = threading.Lock()
        self._load_existing()

    def _key(self, server_id: str, tool_name: str) -> str:
        bare = tool_name.split(".", 1)[-1] if "." in tool_name else tool_name
        return f"{server_id}::{bare}"

    def _path(self, server_id: str, tool_name: str) -> Path:
        bare = tool_name.split(".", 1)[-1] if "." in tool_name else tool_name
        d = self.pins_dir / server_id
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{bare}.json"

    def _load_existing(self) -> None:
        if not self.pins_dir.exists():
            return
        for path in self.pins_dir.glob("*/*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                rec = PinRecord(
                    server_id=data["server_id"],
                    tool_name=data["tool_name"],
                    schema_hash=data["schema_hash"],
                    description_hash=data["description_hash"],
                    description=data.get("description", ""),
                    input_schema=data.get("input_schema") or {},
                )
                self._pins[self._key(rec.server_id, rec.tool_name)] = rec
            except Exception:  # noqa: BLE001
                continue

    def get(self, server_id: str, tool_name: str) -> PinRecord | None:
        with self._lock:
            return self._pins.get(self._key(server_id, tool_name))

    def pin(
        self,
        server_id: str,
        tool_name: str,
        *,
        description: str,
        input_schema: dict[str, Any] | None,
    ) -> PinRecord:
        bare = tool_name.split(".", 1)[-1] if "." in tool_name else tool_name
        rec = PinRecord(
            server_id=server_id,
            tool_name=bare,
            schema_hash=hash_schema(input_schema),
            description_hash=hash_description(description),
            description=description or "",
            input_schema=dict(input_schema or {}),
        )
        with self._lock:
            self._pins[self._key(server_id, bare)] = rec
            path = self._path(server_id, bare)
            path.write_text(
                json.dumps(rec.to_dict(), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        return rec

    def verify(
        self,
        server_id: str,
        tool_name: str,
        *,
        description: str,
        input_schema: dict[str, Any] | None,
    ) -> tuple[bool, str, PinRecord | None]:
        """Return (ok, reason, pin_or_none).

        ok=True with reason pin_created means first sighting (auto-pin).
        ok=False means mismatch.
        """
        bare = tool_name.split(".", 1)[-1] if "." in tool_name else tool_name
        existing = self.get(server_id, bare)
        sch = hash_schema(input_schema)
        dh = hash_description(description)
        if existing is None:
            rec = self.pin(
                server_id,
                bare,
                description=description,
                input_schema=input_schema,
            )
            return True, "pin_created", rec
        if existing.schema_hash != sch:
            return False, "schema_hash_mismatch", existing
        if existing.description_hash != dh:
            return False, "description_hash_mismatch", existing
        return True, "pin_match", existing

    def clear(self) -> None:
        with self._lock:
            self._pins.clear()
