import json

import pytest

from agent_security_lab.mcp_servers.benign import tools


def test_calculate():
    out = json.loads(tools.calculate("2+3*4"))
    assert out["result"] == 14


def test_read_public():
    text = tools.read_file("notes.txt")
    assert "Lab public notes" in text


def test_read_sensitive_blocked():
    with pytest.raises(tools.SandboxError):
        tools.read_file("lab_fs/sensitive/.env.fake")


def test_send_email_outbox(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "_OUTBOX", tmp_path)
    out = json.loads(tools.send_email("a@b.c", "hi", "body"))
    assert out["status"] == "queued"
    assert list(tmp_path.glob("mail-*.json"))
