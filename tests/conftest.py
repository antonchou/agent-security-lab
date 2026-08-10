"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agent_security_lab.config import ROOT, load_config
from agent_security_lab.observability.audit import set_audit_path
from agent_security_lab.policy.approvals import reset_approval_store_for_tests
from agent_security_lab.policy.locks import reset_session_lock_for_tests
from agent_security_lab.policy.schema_pin import SchemaPinStore


@pytest.fixture
def tmp_lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolated pins/audit/approvals directories per test."""
    pins = tmp_path / "pins"
    audit = tmp_path / "audit" / "tool_calls.jsonl"
    approvals = tmp_path / "approvals" / "queue.jsonl"
    pins.mkdir()
    audit.parent.mkdir()
    approvals.parent.mkdir()
    set_audit_path(audit)
    reset_session_lock_for_tests()
    store = reset_approval_store_for_tests()
    return {
        "pins": pins,
        "audit": audit,
        "approvals": approvals,
        "tmp": tmp_path,
        "store": store,
    }


@pytest.fixture
def baseline_cfg(tmp_lab):
    cfg = load_config("baseline")
    cfg.pins_dir = tmp_lab["pins"] / "baseline"
    cfg.pins_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit_path = tmp_lab["audit"]
    cfg.approvals_path = tmp_lab["approvals"]
    set_audit_path(cfg.audit_path)
    return cfg


@pytest.fixture
def hardened_cfg(tmp_lab):
    cfg = load_config("hardened")
    cfg.pins_dir = tmp_lab["pins"] / "hardened"
    cfg.pins_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit_path = tmp_lab["audit"]
    cfg.approvals_path = tmp_lab["approvals"]
    set_audit_path(cfg.audit_path)
    return cfg


@pytest.fixture
def pin_store(tmp_lab) -> SchemaPinStore:
    d = tmp_lab["pins"] / "store"
    d.mkdir(parents=True, exist_ok=True)
    return SchemaPinStore(d)
