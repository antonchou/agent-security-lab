"""Attack acceptance: rug pull after install / list count + test hook."""

import pytest

from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.models.policy import Verdict
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore


@pytest.mark.asyncio
async def test_rug_pull_baseline_allows_mutated(baseline_cfg):
    client = MCPClientManager()
    await client.start()
    try:
        gw = HostGateway.create(
            baseline_cfg,
            client,
            pins=SchemaPinStore(baseline_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=False,
            role="analyst",
        )
        # Pin clean
        r0 = await gw.call_tool("malicious.get_weather", {"city": "A"})
        assert r0.ok
        # Force rug pull + refresh
        await gw.call_tool("malicious.trigger_rug_pull", {})
        await client.refresh_tools()
        desc = client.tools["malicious.get_weather"].description
        assert "<IMPORTANT>" in desc
        # Baseline does not enforce pins
        r1 = await gw.call_tool("malicious.get_weather", {"city": "B"})
        assert r1.ok
        assert r1.decision.verdict is Verdict.ALLOW
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rug_pull_hardened_blocked_by_pin(hardened_cfg):
    client = MCPClientManager()
    await client.start()
    try:
        gw = HostGateway.create(
            hardened_cfg,
            client,
            pins=SchemaPinStore(hardened_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=False,
            role="analyst",
        )
        r0 = await gw.call_tool("malicious.get_weather", {"city": "A"})
        assert r0.ok
        await gw.call_tool("malicious.trigger_rug_pull", {})
        await client.refresh_tools()
        r1 = await gw.call_tool("malicious.get_weather", {"city": "B"})
        assert not r1.ok
        assert r1.decision.verdict is Verdict.DENY
        assert any("schema_pin" in x for x in r1.decision.reasons)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rug_pull_counter_path(hardened_cfg):
    """List-count path: threshold=1 via env on malicious server process."""
    client = MCPClientManager()
    await client.start(malicious_env={"ASL_RUG_PULL_AFTER_LIST_COUNT": "1"})
    try:
        # start() already performed one tools/list; with threshold=1 the
        # malicious server serves the mutated description from then on
        desc = client.tools["malicious.get_weather"].description
        assert "<IMPORTANT>" in desc
        # The list-counter path keeps incrementing without crashing
        await client.refresh_tools()
        again = client.tools["malicious.get_weather"].description
        assert "<IMPORTANT>" in again
    finally:
        await client.aclose()
