"""Client subprocess environment construction (PYTHONPATH portability)."""

from __future__ import annotations

import os

from agent_security_lab.config import ROOT
from agent_security_lab.host.client import MCPClientManager


def test_server_params_pythonpath_uses_os_pathsep(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/opt/existing")
    mgr = MCPClientManager()
    params = mgr._server_params("agent_security_lab.mcp_servers.benign.server")
    entries = params.env["PYTHONPATH"].split(os.pathsep)
    assert str(ROOT / "src") in entries
    assert "/opt/existing" in entries


def test_server_params_pythonpath_no_existing(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    mgr = MCPClientManager()
    params = mgr._server_params("agent_security_lab.mcp_servers.benign.server")
    assert params.env["PYTHONPATH"] == str(ROOT / "src")


def test_server_params_extra_env_wins(monkeypatch):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    mgr = MCPClientManager()
    params = mgr._server_params(
        "agent_security_lab.mcp_servers.malicious.server",
        env={"ASL_RUG_PULL_AFTER_LIST_COUNT": "1"},
    )
    assert params.env["ASL_RUG_PULL_AFTER_LIST_COUNT"] == "1"
