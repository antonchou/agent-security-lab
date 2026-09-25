"""Gateway ALLOW-path failure handling: server errors fail closed with audit."""

from __future__ import annotations

import pytest

from agent_security_lab.host.client import MCPClientManager, RemoteTool
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.models.policy import Verdict
from agent_security_lab.observability.audit import read_tool_audits
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore


class _CrashingManager(MCPClientManager):
    """Mimics a connected manager whose server dies mid-call."""

    async def call_raw(self, server_id: str, bare_name: str, arguments: dict) -> str:
        raise RuntimeError("server process crashed")


@pytest.mark.asyncio
async def test_gateway_server_error_fails_closed_and_audits(hardened_cfg):
    mgr = _CrashingManager()
    rt = RemoteTool(
        server_id="benign",
        name="calculate",
        namespaced="benign.calculate",
        description="arithmetic",
        input_schema={"type": "object"},
    )
    mgr.tools["benign.calculate"] = rt
    mgr.bare_index.setdefault("calculate", []).append("benign.calculate")

    gw = HostGateway.create(
        hardened_cfg,
        mgr,
        pins=SchemaPinStore(hardened_cfg.pins_dir),
        approvals=ApprovalStore(path=None),
        mark_untrusted=False,
    )
    result = await gw.call_tool("benign.calculate", {"expression": "1+1"})

    assert not result.ok
    assert result.decision.verdict is Verdict.DENY
    assert any(
        "tool_execution_error" in r for r in result.decision.reasons
    )

    events = read_tool_audits(path=hardened_cfg.audit_path)
    assert any(e.get("event") == "tool_call_error" for e in events)
