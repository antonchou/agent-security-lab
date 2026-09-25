"""Lightweight Sigma-style detection rules for tool arguments / metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.models.session import SessionState


@dataclass
class SigmaResult:
    hits: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    deny: bool = False
    require_approval: bool = False
    raise_sensitive: bool = False


@dataclass
class SigmaRule:
    id: str
    title: str
    action: str
    arg_keys: list[str]
    patterns: list[re.Pattern[str]]
    metadata_fields: list[str]
    dataflow: str | None = None


class SigmaEngine:
    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self.rules = rules or []

    @classmethod
    def from_yaml(cls, path: Path) -> SigmaEngine:
        if not path.exists():
            return cls([])
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules: list[SigmaRule] = []
        for raw in data.get("rules") or []:
            match = raw.get("match") or {}
            patterns = [
                re.compile(p, re.IGNORECASE) for p in (match.get("patterns") or [])
            ]
            rules.append(
                SigmaRule(
                    id=str(raw.get("id")),
                    title=str(raw.get("title", "")),
                    action=str(raw.get("action", "alert")),
                    arg_keys=list(match.get("arg_keys") or []),
                    patterns=patterns,
                    metadata_fields=list(match.get("metadata_fields") or []),
                    dataflow=match.get("dataflow"),
                )
            )
        return cls(rules)

    def evaluate(
        self,
        intent: ToolCallIntent,
        *,
        description: str = "",
        session: SessionState | None = None,
    ) -> SigmaResult:
        result = SigmaResult()
        for rule in self.rules:
            matched = False

            if rule.dataflow == "sensitive_then_state_change" and session is not None:
                bare = intent.tool_name.split(".")[-1]
                if (
                    session.flags.sensitive_data
                    and bare == "send_email"
                    and session.last_sensitive_call_id
                ):
                    matched = True

            for key in rule.arg_keys:
                val = intent.arguments.get(key)
                if val is None:
                    continue
                text = str(val)
                for pat in rule.patterns:
                    if pat.search(text):
                        matched = True
                        break

            if "description" in rule.metadata_fields:
                for pat in rule.patterns:
                    if pat.search(description or ""):
                        matched = True
                        break

            if not matched:
                continue

            result.hits.append(rule.id)
            result.alerts.append(f"{rule.id}:{rule.title}")
            if rule.action == "deny":
                result.deny = True
            elif rule.action == "require_approval":
                result.require_approval = True
            elif rule.action == "raise_sensitive":
                result.raise_sensitive = True
            # alert: no hard action
        return result
