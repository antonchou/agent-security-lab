"""Lab configuration loader (YAML profiles under configs/)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Project root: .../agent-security-lab
ROOT = Path(__file__).resolve().parents[2]


def _deep_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = data
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _mode_str(value: Any, default: str = "require_approval") -> str:
    """Normalize policy mode; YAML bare `off` becomes False."""
    if value is False or value is None:
        return "off"
    if value is True:
        return default
    return str(value).strip().lower()


@dataclass
class OpenAIConfig:
    enabled: bool = False
    base_url: str = "http://127.0.0.1:0/v1"
    api_key_env: str = "ASL_OPENAI_API_KEY"
    model: str = "gpt-4o-mini"


@dataclass
class PolicyConfig:
    rule_of_two_mode: str = "require_approval"  # off | require_approval | block
    lethal_trifecta_mode: str = "require_approval"
    schema_pin_enforce: bool = True
    description_diff_enforce: bool = True
    require_approval_for_state_change: bool = True
    always_require_human: bool = True
    name_conflict_mode: str = "deny"  # last_wins | deny
    sigma_enforce: bool = True
    allowlist_enforce: bool = False


@dataclass
class LabConfig:
    profile: str = "hardened"
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    default_role: str = "analyst"
    mark_prompt_untrusted: bool = True
    token_ttl_seconds: int = 600
    approvals_path: Path = field(default_factory=lambda: ROOT / "approvals" / "queue.jsonl")
    audit_path: Path = field(default_factory=lambda: ROOT / "audit" / "tool_calls.jsonl")
    pins_dir: Path = field(default_factory=lambda: ROOT / "pins")
    lab_fs: Path = field(default_factory=lambda: ROOT / "lab_fs")
    outbox: Path = field(default_factory=lambda: ROOT / "outbox")
    sensitive_subdir: str = "sensitive"
    public_subdir: str = "public"
    agent_mode: str = "scripted"
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    rug_pull_after_list_count: int = 2
    sigma_rules_path: Path = field(default_factory=lambda: ROOT / "configs" / "sigma_rules.yaml")
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def sensitive_root(self) -> Path:
        return (self.lab_fs / self.sensitive_subdir).resolve()

    @property
    def public_root(self) -> Path:
        return (self.lab_fs / self.public_subdir).resolve()


def load_config(profile: str | Path | None = None) -> LabConfig:
    """Load lab.baseline.yaml or lab.hardened.yaml (or an explicit path)."""
    if profile is None:
        path = ROOT / "configs" / "lab.hardened.yaml"
    else:
        p = Path(profile)
        if p.suffix in {".yaml", ".yml"} and p.exists():
            path = p
        else:
            name = str(profile)
            if not name.startswith("lab."):
                name = f"lab.{name}"
            if not name.endswith(".yaml"):
                name = f"{name}.yaml"
            path = ROOT / "configs" / name

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    pol = data.get("policy") or {}
    sess = data.get("session") or {}
    appr = data.get("approvals") or {}
    audit = data.get("audit") or {}
    pins = data.get("pins") or {}
    paths = data.get("paths") or {}
    host = data.get("host") or {}
    oai = host.get("openai") or {}
    servers = data.get("servers") or {}
    mal = servers.get("malicious") or {}

    def rel(p: str | None, default: Path) -> Path:
        if not p:
            return default
        pp = Path(p)
        return pp if pp.is_absolute() else (ROOT / pp)

    cfg = LabConfig(
        profile=str(data.get("profile") or path.stem.replace("lab.", "")),
        policy=PolicyConfig(
            rule_of_two_mode=_mode_str(pol.get("rule_of_two_mode", "require_approval")),
            lethal_trifecta_mode=_mode_str(
                pol.get("lethal_trifecta_mode", "require_approval")
            ),
            schema_pin_enforce=bool(pol.get("schema_pin_enforce", True)),
            description_diff_enforce=bool(pol.get("description_diff_enforce", True)),
            require_approval_for_state_change=bool(
                pol.get("require_approval_for_state_change", True)
            ),
            always_require_human=bool(pol.get("always_require_human", True)),
            name_conflict_mode=str(pol.get("name_conflict_mode", "deny")),
            sigma_enforce=bool(pol.get("sigma_enforce", True)),
            allowlist_enforce=bool(pol.get("allowlist_enforce", False)),
        ),
        default_role=str(sess.get("default_role", "analyst")),
        mark_prompt_untrusted=bool(sess.get("mark_prompt_untrusted", True)),
        token_ttl_seconds=int(appr.get("token_ttl_seconds", 600)),
        approvals_path=rel(appr.get("store_path"), ROOT / "approvals" / "queue.jsonl"),
        audit_path=rel(audit.get("path"), ROOT / "audit" / "tool_calls.jsonl"),
        pins_dir=rel(pins.get("dir"), ROOT / "pins"),
        lab_fs=rel(paths.get("lab_fs"), ROOT / "lab_fs"),
        outbox=rel(paths.get("outbox"), ROOT / "outbox"),
        sensitive_subdir=str(paths.get("sensitive_subdir", "sensitive")),
        public_subdir=str(paths.get("public_subdir", "public")),
        agent_mode=str(host.get("agent", "scripted")),
        openai=OpenAIConfig(
            enabled=bool(oai.get("enabled", False)),
            base_url=str(oai.get("base_url", "http://127.0.0.1:0/v1")),
            api_key_env=str(oai.get("api_key_env", "ASL_OPENAI_API_KEY")),
            model=str(oai.get("model", "gpt-4o-mini")),
        ),
        rug_pull_after_list_count=int(mal.get("rug_pull_after_list_count", 2)),
        raw=data,
    )
    return cfg
