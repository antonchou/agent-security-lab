"""Approval queue models (adapted from quant-selector / ai-quant-platform)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from agent_security_lab.models.intent import ToolCallIntent


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


@dataclass
class ExecutionToken:
    """Single-use execution token bound to an intent_hash."""

    token: str
    approval_id: str
    intent_hash: str
    issued_at: datetime = field(default_factory=_utc_now)
    expires_at: datetime | None = None
    used: bool = False
    used_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "approval_id": self.approval_id,
            "intent_hash": self.intent_hash,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "used": self.used,
            "used_at": self.used_at.isoformat() if self.used_at else None,
        }


@dataclass
class PendingApproval:
    approval_id: str
    intent: ToolCallIntent
    proposed_by: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    reasons: list[str] = field(default_factory=list)
    requires_human: bool = True
    created_at: datetime = field(default_factory=_utc_now)
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    reject_reason: str | None = None
    execution_token: ExecutionToken | None = None
    execution_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "status": self.status.value,
            "intent": self.intent.to_dict(),
            "proposed_by": self.proposed_by,
            "reasons": list(self.reasons),
            "requires_human": self.requires_human,
            "created_at": self.created_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decided_by": self.decided_by,
            "decision_note": self.decision_note,
            "reject_reason": self.reject_reason,
            "execution_token": (
                self.execution_token.to_dict() if self.execution_token else None
            ),
            "execution_call_id": self.execution_call_id,
        }
