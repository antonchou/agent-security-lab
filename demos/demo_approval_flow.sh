#!/usr/bin/env bash
# Programmatic approval flow demo (same process) via a tiny Python snippet.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 <<'PY'
import asyncio
from agent_security_lab.config import load_config, ROOT
from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore

async def main():
    cfg = load_config("hardened")
    cfg.pins_dir = ROOT / "pins" / "demo_approval"
    cfg.pins_dir.mkdir(parents=True, exist_ok=True)
    store = ApprovalStore(path=None)
    client = MCPClientManager()
    await client.start()
    try:
        gw = HostGateway.create(
            cfg, client,
            pins=SchemaPinStore(cfg.pins_dir),
            approvals=store,
            mark_untrusted=True,
            role="operator",
        )
        # calculate alone is fine
        r0 = await gw.call_tool("benign.calculate", {"expression": "1+1"})
        print("calculate:", r0.decision.verdict.value, r0.content)

        # email needs approval (state_change)
        r1 = await gw.call_tool(
            "benign.send_email",
            {"to": "a@example.invalid", "subject": "hi", "body": "hello lab"},
        )
        print("email first:", r1.decision.verdict.value, r1.decision.approval_id)
        assert r1.decision.approval_id
        decided = store.decide(r1.decision.approval_id, approve=True, decided_by="human")
        token = decided.execution_token.token
        print("token issued (single-use)")
        r2 = await gw.call_tool(
            "benign.send_email",
            {"to": "a@example.invalid", "subject": "hi", "body": "hello lab"},
            execution_token=token,
        )
        print("email with token:", r2.decision.verdict.value, "ok=", r2.ok)
        r3 = await gw.call_tool(
            "benign.send_email",
            {"to": "a@example.invalid", "subject": "hi", "body": "hello lab"},
            execution_token=token,
        )
        print("email replay token:", r3.decision.verdict.value, r3.decision.reasons)
    finally:
        await client.aclose()

asyncio.run(main())
PY
