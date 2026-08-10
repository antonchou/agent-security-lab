from __future__ import annotations

from agent_security_lab.config import LabConfig


def is_baseline(cfg: LabConfig) -> bool:
    return cfg.profile.lower() == "baseline"


def is_hardened(cfg: LabConfig) -> bool:
    return cfg.profile.lower() == "hardened"
