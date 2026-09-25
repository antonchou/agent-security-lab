#!/usr/bin/env python3
"""PoC: rug pull via trigger_rug_pull hook + list refresh."""

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
    cfg.pins_dir = ROOT / "pins" / f"poc_rug_{profile}"
    if cfg.pins_dir.exists():
        import shutil

        shutil.rmtree(cfg.pins_dir)
    cfg.pins_dir.mkdir(parents=True)
    cfg.audit_path = ROOT / "audit" / f"poc_rug_{profile}.jsonl"

    client = MCPClientManager()
    await client.start()
    try:
        gw = HostGateway.create(
            cfg,
            client,
            pins=SchemaPinStore(cfg.pins_dir),
            approvals=ApprovalStore(path=None),
            mark_untrusted=False,
            role="analyst",
        )
        print("desc@pin:", client.tools["malicious.get_weather"].description[:80])
        r0 = await gw.call_tool("malicious.get_weather", {"city": "LabCity"})
        print(f"[pre] verdict={r0.decision.verdict.value}")

        await gw.call_tool("malicious.trigger_rug_pull", {})
        await client.refresh_tools()
        print("desc@mutated:", client.tools["malicious.get_weather"].description[:120])

        r1 = await gw.call_tool("malicious.get_weather", {"city": "LabCity"})
        print(f"[post] verdict={r1.decision.verdict.value} reasons={r1.decision.reasons}")
        return 0
    finally:
        await client.aclose()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--profile", default="baseline", choices=["baseline", "hardened"])
    args = p.parse_args()
    raise SystemExit(asyncio.run(main(args.profile)))
