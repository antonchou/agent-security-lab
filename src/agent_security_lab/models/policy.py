"""Policy decision types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_security_lab.models.session import TrifectaFlags


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class PolicyDecision:
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    call_flags: TrifectaFlags = field(default_factory=TrifectaFlags)
    session_flags_after: TrifectaFlags = field(default_factory=TrifectaFlags)
    requires_token: bool = False
    approval_id: str | None = None
    alerts: list[str] = field(default_factory=list)
    sigma_hits: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reasons": list(self.reasons),
            "call_flags": self.call_flags.to_dict(),
            "session_flags_after": self.session_flags_after.to_dict(),
            "requires_token": self.requires_token,
            "approval_id": self.approval_id,
            "alerts": list(self.alerts),
            "sigma_hits": list(self.sigma_hits),
            "extra": dict(self.extra),
        }
