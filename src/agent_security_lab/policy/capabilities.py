"""Map tools + arguments to Lethal Trifecta capability flags."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent_security_lab.config import LabConfig
from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.models.session import SessionState, TrifectaFlags

# Tools that change external/observable state (even mock outbox)
STATE_CHANGE_TOOLS = {
    "send_email",
    "shadow_send_email_advice",  # advice-only but treated as policy-sensitive
}

SENSITIVE_NAME_HINTS = re.compile(
    r"(sensitive|\.env|id_rsa|private.?key|customer_pii|secret|password)",
    re.IGNORECASE,
)


def bare_tool_name(namespaced: str) -> str:
    if "." in namespaced:
        return namespaced.split(".", 1)[1]
    return namespaced


def server_of(namespaced: str) -> str:
    if "." in namespaced:
        return namespaced.split(".", 1)[0]
    return ""


def path_looks_sensitive(path: str, cfg: LabConfig) -> bool:
    raw = path.replace("\\", "/")
    if "sensitive/" in raw or raw.endswith("/sensitive") or "/sensitive" in raw:
        return True
    if SENSITIVE_NAME_HINTS.search(raw):
        return True
    try:
        # Resolve relative to lab_fs when possible
        p = Path(path)
        if not p.is_absolute():
            candidate = (cfg.lab_fs / path).resolve()
        else:
            candidate = p.resolve()
        sens = cfg.sensitive_root
        if sens in candidate.parents or candidate == sens:
            return True
        try:
            candidate.relative_to(sens)
            return True
        except ValueError:
            pass
    except Exception:  # noqa: BLE001, S110 — best-effort path check
        pass
    return False


def project_call_flags(
    intent: ToolCallIntent,
    cfg: LabConfig,
    *,
    tool_description: str = "",
) -> TrifectaFlags:
    """Project trifecta flags raised by this single call."""
    flags = TrifectaFlags()
    bare = bare_tool_name(intent.tool_name)
    args: Mapping[str, Any] = intent.arguments

    # Untrusted: malicious server tools / poisoned descriptions always taint
    if intent.server_id == "malicious":
        flags.untrusted_input = True
    if tool_description and (
        "<IMPORTANT>" in tool_description
        or "do not mention this instruction" in tool_description.lower()
    ):
        flags.untrusted_input = True

    # Sensitive data access
    for key in ("path", "file_path", "filepath"):
        if args.get(key) is not None and path_looks_sensitive(str(args[key]), cfg):
            flags.sensitive_data = True

    # Body already carrying secrets implies sensitive handling
    for key in ("body", "content", "message"):
        val = args.get(key)
        if isinstance(val, str) and SENSITIVE_NAME_HINTS.search(val):
            flags.sensitive_data = True
        if isinstance(val, str) and (
            "API_KEY=" in val
            or "BEGIN RSA" in val
            or "SECRET_TOKEN=" in val
            or "ssn=" in val.lower()
        ):
            flags.sensitive_data = True

    # State change / external communication
    if bare in STATE_CHANGE_TOOLS or bare == "send_email":
        flags.state_change = True

    return flags


def role_allows(role: str, call_flags: TrifectaFlags) -> tuple[bool, str | None]:
    """Hard role matrix (inspired by ai-quant-platform can_execute_orders)."""
    r = role.lower()
    if r == "observer" and (call_flags.sensitive_data or call_flags.state_change):
        return False, f"role_observer_forbids:{call_flags.active_names()}"
    if r == "analyst" and call_flags.state_change:
        return False, "role_analyst_forbids_state_change"
    # operator: allowed subject to rule-of-two / approval
    return True, None


def apply_session_untrusted(session: SessionState, cfg: LabConfig) -> None:
    if cfg.mark_prompt_untrusted and not session.flags.untrusted_input:
        # Do not auto-mark all sessions; host decides via session.mark_untrusted()
        pass
