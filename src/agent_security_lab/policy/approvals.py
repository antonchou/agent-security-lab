"""Human-in-the-loop approval with single-use execution tokens.

Pattern adapted from quant-selector approvals.py and ai-quant-platform
ApprovalStore, upgraded with cryptographic single-consumption tokens.
"""

from __future__ import annotations

import json
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_security_lab.config import LabConfig, load_config
from agent_security_lab.models.approval import (
    ApprovalStatus,
    ExecutionToken,
    PendingApproval,
)
from agent_security_lab.models.intent import ToolCallIntent

_STORE: "ApprovalStore | None" = None


class ApprovalStore:
    def __init__(self, path: Path | None = None, token_ttl_seconds: int = 600) -> None:
        self._items: dict[str, PendingApproval] = {}
        self._tokens: dict[str, ExecutionToken] = {}
        self._lock = threading.Lock()
        self.path = path
        self.token_ttl_seconds = token_ttl_seconds

    def create(
        self,
        intent: ToolCallIntent,
        *,
        proposed_by: str = "host",
        reasons: list[str] | None = None,
        force_human: bool = True,
    ) -> PendingApproval:
        item = PendingApproval(
            approval_id=f"appr-{uuid.uuid4().hex[:12]}",
            intent=intent,
            proposed_by=proposed_by,
            reasons=list(reasons or []),
            requires_human=force_human,
        )
        with self._lock:
            self._items[item.approval_id] = item
            self._persist(item)
        return item

    def get(self, approval_id: str) -> PendingApproval | None:
        with self._lock:
            return self._items.get(approval_id)

    def list(
        self,
        status: ApprovalStatus | None = None,
        limit: int = 100,
    ) -> list[PendingApproval]:
        with self._lock:
            items = list(self._items.values())
        if status:
            items = [i for i in items if i.status == status]
        items.sort(key=lambda x: x.created_at, reverse=True)
        return items[:limit]

    def decide(
        self,
        approval_id: str,
        *,
        approve: bool,
        decided_by: str,
        note: str = "",
    ) -> PendingApproval:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                raise KeyError(approval_id)
            if item.status is not ApprovalStatus.PENDING:
                raise ValueError(f"cannot decide approval in status={item.status}")
            now = datetime.now(timezone.utc)
            if approve:
                item.status = ApprovalStatus.APPROVED
                token_str = secrets.token_urlsafe(32)
                tok = ExecutionToken(
                    token=token_str,
                    approval_id=approval_id,
                    intent_hash=item.intent.intent_hash,
                    issued_at=now,
                    expires_at=now + timedelta(seconds=self.token_ttl_seconds),
                )
                item.execution_token = tok
                self._tokens[token_str] = tok
            else:
                item.status = ApprovalStatus.REJECTED
                item.reject_reason = note or "human_rejected"
            item.decided_at = now
            item.decided_by = decided_by
            item.decision_note = note
            self._persist(item)
            return item

    def consume(
        self,
        token: str,
        intent_hash: str,
    ) -> ExecutionToken:
        """Atomically consume a single-use token bound to intent_hash."""
        with self._lock:
            tok = self._tokens.get(token)
            if tok is None:
                raise ValueError("invalid_execution_token")
            if tok.used:
                raise ValueError("execution_token_already_used")
            now = datetime.now(timezone.utc)
            if tok.expires_at is not None and now > tok.expires_at:
                raise ValueError("execution_token_expired")
            if tok.intent_hash != intent_hash:
                raise ValueError("execution_token_intent_mismatch")
            item = self._items.get(tok.approval_id)
            if item is None or item.status is not ApprovalStatus.APPROVED:
                raise ValueError("approval_not_in_approved_state")
            tok.used = True
            tok.used_at = now
            item.status = ApprovalStatus.EXECUTED
            item.execution_call_id = intent_hash[:16]
            self._persist(item)
            return tok

    def mark_blocked(self, approval_id: str, reason: str) -> PendingApproval:
        with self._lock:
            item = self._items[approval_id]
            item.status = ApprovalStatus.BLOCKED
            item.reject_reason = reason
            self._persist(item)
            return item

    def _persist(self, item: PendingApproval) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(item.to_dict(), default=str) + "\n")
        except Exception:  # noqa: BLE001
            pass


def get_approval_store(cfg: LabConfig | None = None) -> ApprovalStore:
    global _STORE
    if _STORE is None:
        c = cfg or load_config()
        _STORE = ApprovalStore(
            path=c.approvals_path,
            token_ttl_seconds=c.token_ttl_seconds,
        )
    return _STORE


def reset_approval_store_for_tests(cfg: LabConfig | None = None) -> ApprovalStore:
    global _STORE
    c = cfg or load_config("baseline")
    _STORE = ApprovalStore(path=None, token_ttl_seconds=c.token_ttl_seconds)
    return _STORE
