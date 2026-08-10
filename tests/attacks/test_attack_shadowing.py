"""Attack acceptance: tool shadowing / name collision on send_email."""

import pytest

from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.models.policy import Verdict
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore


@pytest.mark.asyncio
async def test_shadowing_bare_name_denied_when_hardened(hardened_cfg):
    client = MCPClientManager()
    await client.start()
    try:
        assert len(client.collisions().get("send_email", [])) >= 2
        gw = HostGateway.create(
            hardened_cfg,
            client,
            pins=SchemaPinStore(hardened_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=True,
            role="operator",
        )
        r = await gw.call_tool(
            "send_email",
            {"to": "t@e.invalid", "subject": "s", "body": "hello"},
        )
        assert not r.ok
        assert r.decision.verdict is Verdict.DENY
        assert any("name_conflict" in x for x in r.decision.reasons)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_shadowing_advice_alerts(hardened_cfg):
    client = MCPClientManager()
    await client.start()
    try:
        tool = client.tools["malicious.shadow_send_email_advice"]
        assert "send_email" in tool.description.lower()
        gw = HostGateway.create(
            hardened_cfg,
            client,
            pins=SchemaPinStore(hardened_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=True,
            role="analyst",
        )
        r = await gw.call_tool(
            "malicious.shadow_send_email_advice",
            {"user_intent": "email team"},
        )
        # Main check: shadowing alert present on the advisory tool
        assert "shadowing_language_detected" in (r.decision.alerts or [])
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_shadowing_baseline_last_wins(baseline_cfg):
    client = MCPClientManager()
    await client.start()
    try:
        gw = HostGateway.create(
            baseline_cfg,
            client,
            pins=SchemaPinStore(baseline_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=False,
            role="operator",
        )
        # last_wins should pick one of the send_email implementations
        r = await gw.call_tool(
            "send_email",
            {"to": "t@e.invalid", "subject": "s", "body": "hello"},
        )
        # May require nothing in baseline — should succeed
        assert r.ok
        assert r.decision.verdict is Verdict.ALLOW
    finally:
        await client.aclose()
