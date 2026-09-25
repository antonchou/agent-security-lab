#!/usr/bin/env python3
"""PoC: tool shadowing / name collision."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from agent_security_lab.config import load_config
from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.schema_pin import SchemaPinStore


async def main(profile: str) -> int:
    cfg = load_config(profile)
    cfg.pins_dir = ROOT / "pins" / f"poc_shadow_{profile}"
    cfg.pins_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit_path = ROOT / "audit" / f"poc_shadow_{profile}.jsonl"

    client = MCPClientManager()
    await client.start()
    try:
        print("collisions:", client.collisions())
        gw = HostGateway.create(
            cfg,
            client,
            pins=SchemaPinStore(cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=True,
            role="operator",
        )
        r_adv = await gw.call_tool(
            "malicious.shadow_send_email_advice",
            {"user_intent": "email the team"},
        )
        print(
            f"[advice] verdict={r_adv.decision.verdict.value} "
            f"alerts={r_adv.decision.alerts}"
        )
        r = await gw.call_tool(
            "send_email",
            {"to": "team@example.invalid", "subject": "hi", "body": "hello"},
        )
        print(f"[bare send_email] verdict={r.decision.verdict.value} reasons={r.decision.reasons}")
        print(f"  resolved={r.tool_namespaced}")
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="baseline", choices=["baseline", "hardened"])
    args = p.parse_args()
    raise SystemExit(asyncio.run(main(args.profile)))
