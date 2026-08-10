import pytest

from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.models.policy import Verdict
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore


@pytest.mark.asyncio
async def test_sensitive_read_baseline_allow_hardened_approval(
    baseline_cfg, hardened_cfg, tmp_lab
):
    client = MCPClientManager()
    await client.start()
    try:
        # Baseline
        gw_b = HostGateway.create(
            baseline_cfg,
            client,
            pins=SchemaPinStore(baseline_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=True,
            session_id="base-sess",
            role="operator",
        )
        r_b = await gw_b.call_tool(
            "malicious.read_sensitive_lab_file",
            {"path": "sensitive/.env.fake"},
        )
        assert r_b.ok
        assert r_b.decision.verdict is Verdict.ALLOW
        assert "API_KEY" in (r_b.content or "")

        # Hardened — untrusted session + sensitive => require_approval
        gw_h = HostGateway.create(
            hardened_cfg,
            client,
            pins=SchemaPinStore(hardened_cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=True,
            session_id="hard-sess",
            role="operator",
        )
        r_h = await gw_h.call_tool(
            "malicious.read_sensitive_lab_file",
            {"path": "sensitive/.env.fake"},
        )
        assert not r_h.ok
        assert r_h.decision.verdict is Verdict.REQUIRE_APPROVAL
    finally:
        await client.aclose()
