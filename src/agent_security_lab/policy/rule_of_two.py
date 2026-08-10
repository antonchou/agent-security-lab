"""Rule of Two / Lethal Trifecta runtime check.

Confirmed lab policy: when two or more of the three dimensions are active
in (session ∪ this_call), verdict is require_approval (not silent allow).
"""

from __future__ import annotations

from agent_security_lab.config import LabConfig
from agent_security_lab.models.policy import Verdict
from agent_security_lab.models.session import TrifectaFlags


def evaluate_rule_of_two(
    combined: TrifectaFlags,
    cfg: LabConfig,
) -> tuple[Verdict | None, list[str]]:
    """Return (override_verdict_or_None, reasons).

    None means "no Rule-of-Two override" (other checks may still deny).
    """
    count = combined.count()
    reasons: list[str] = []
    if count < 2:
        return None, reasons

    names = "+".join(combined.active_names())
    mode = _normalize_mode(cfg.policy.rule_of_two_mode)
    if count >= 3:
        mode = _normalize_mode(cfg.policy.lethal_trifecta_mode) or mode
        reasons.append(f"lethal_trifecta:{names}")
    else:
        reasons.append(f"rule_of_two:{names}")

    if mode == "off":
        return None, reasons
    if mode == "block":
        return Verdict.DENY, reasons
    if mode == "require_approval":
        return Verdict.REQUIRE_APPROVAL, reasons
    # unknown mode → safe default
    return Verdict.REQUIRE_APPROVAL, reasons + [f"unknown_mode:{mode}"]


def _normalize_mode(mode: object) -> str:
    """YAML may parse bare `off` as False — accept bools and strings."""
    if mode is False or mode is None:
        return "off"
    if mode is True:
        return "require_approval"
    return str(mode).strip().lower()
