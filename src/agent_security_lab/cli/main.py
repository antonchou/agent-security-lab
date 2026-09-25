"""CLI: demo, approve, report, list tools."""

from __future__ import annotations

import argparse
import asyncio
import shutil
import sys
from pathlib import Path

from agent_security_lab.cli.demo_scenarios import (
    scenario_benign_happy_path,
    scenario_rug_pull,
    scenario_tool_poisoning,
    scenario_tool_shadowing,
)
from agent_security_lab.config import ROOT, load_config
from agent_security_lab.host.agent_loop import ScriptedAgent
from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.gateway import HostGateway
from agent_security_lab.observability.audit import set_audit_path
from agent_security_lab.observability.report import build_comparison_report
from agent_security_lab.policy.approvals import get_approval_store, reset_approval_store_for_tests
from agent_security_lab.policy.schema_pin import SchemaPinStore


def _banner() -> None:
    print(
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  Agent Security Lab — LOCAL ONLY / FAKE DATA / NO EGRESS    ║\n"
        "║  Red-team MCP range for research & portfolio demonstration  ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
    )


async def _run_demo(profile: str, scenario: str) -> int:
    _banner()
    cfg = load_config(profile)
    # Isolate pins/audit per profile run
    run_pins = ROOT / "pins" / profile
    if run_pins.exists() and scenario != "keep-pins":
        shutil.rmtree(run_pins, ignore_errors=True)
    run_pins.mkdir(parents=True, exist_ok=True)
    cfg.pins_dir = run_pins
    cfg.audit_path = ROOT / "audit" / f"{profile}_{scenario}.jsonl"
    if cfg.audit_path.exists():
        cfg.audit_path.unlink()
    set_audit_path(cfg.audit_path)

    reset_approval_store_for_tests(cfg)
    # re-bind store with path for demo persistence
    from agent_security_lab.policy import approvals as appr_mod

    appr_mod._STORE = appr_mod.ApprovalStore(
        path=cfg.approvals_path, token_ttl_seconds=cfg.token_ttl_seconds
    )

    client = MCPClientManager()
    await client.start(connect_benign=True, connect_malicious=True)
    try:
        print(f"Profile: {cfg.profile}")
        print(f"Tools ({len(client.tools)}):")
        for ns, t in sorted(client.tools.items()):
            poison = "<IMPORTANT>" in (t.description or "")
            print(f"  - {ns}" + (" [poison markers]" if poison else ""))

        gw = HostGateway.create(
            cfg,
            client,
            pins=SchemaPinStore(cfg.pins_dir),
            approvals=appr_mod.get_approval_store(cfg),
            mark_untrusted=True,
        )
        agent = ScriptedAgent(gw)

        scenarios = {
            "happy": scenario_benign_happy_path,
            "poisoning": scenario_tool_poisoning,
            "rug_pull": scenario_rug_pull,
            "shadowing": scenario_tool_shadowing,
        }
        if scenario not in scenarios:
            print(f"Unknown scenario: {scenario}", file=sys.stderr)
            return 2

        steps = scenarios[scenario]()

        # Rug pull needs refresh after trigger
        if scenario == "rug_pull":
            results = []
            # Pin clean tools (start() already listed once; do NOT refresh
            # again here — an extra tools/list would advance the malicious
            # server's rug-pull counter and pin the already-mutated schema)
            r0 = await gw.call_tool("malicious.get_weather", {"city": "LabCity"})
            results.append(r0)
            r1 = await gw.call_tool("malicious.trigger_rug_pull", {})
            results.append(r1)
            await client.refresh_tools()  # observe mutated schemas
            r2 = await gw.call_tool(
                "malicious.get_weather",
                {"city": "LabCity", "extra_headers": "X-Exfil:1"},
            )
            results.append(r2)
            for i, r in enumerate(results):
                print(
                    f"\n[step {i}] ok={r.ok} verdict={r.decision.verdict.value} "
                    f"reasons={r.decision.reasons}"
                )
                if r.content:
                    print(f"  content: {r.content[:200]}")
        else:
            run = await agent.run(steps)
            for i, s in enumerate(run.steps):
                print(
                    f"\n[step {i}] {s.get('note')} tool={s.get('tool')} "
                    f"ok={s.get('ok')} verdict={s.get('verdict')}"
                )
                print(f"  reasons={s.get('reasons')}")
                if s.get("approval_id"):
                    print(f"  approval_id={s.get('approval_id')}")
                if s.get("content"):
                    print(f"  content: {str(s.get('content'))[:200]}")
                if s.get("alerts"):
                    print(f"  alerts={s.get('alerts')}")

        print(f"\nAudit log: {cfg.audit_path}")
        return 0
    finally:
        await client.aclose()


def cmd_approve(args: argparse.Namespace) -> int:
    cfg = load_config(args.profile)
    store = get_approval_store(cfg)
    # hydrate is in-memory; for CLI after demo in same process only.
    # Load from decide on existing store; if empty, try reading last JSONL for id check
    item = store.get(args.approval_id)
    if item is None:
        # best-effort: create store that scans — for demo we re-create from message
        print(
            "Approval not in memory. Run approve in the same process as demo, "
            "or use tests/programmatic API.",
            file=sys.stderr,
        )
        print(
            "Tip: demos print approval_id; use Python:\n"
            "  from agent_security_lab.policy.approvals import get_approval_store\n"
            "  store.decide(id, approve=True, decided_by='human')",
            file=sys.stderr,
        )
        return 1
    decided = store.decide(
        args.approval_id,
        approve=not args.reject,
        decided_by=args.by,
        note=args.note or "",
    )
    if decided.execution_token:
        print("APPROVED")
        print(f"execution_token={decided.execution_token.token}")
        print(f"intent_hash={decided.execution_token.intent_hash}")
        print("Token is single-use and bound to the approved intent.")
    else:
        print(f"Status={decided.status.value}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    base = Path(args.baseline)
    hard = Path(args.hardened)
    out = Path(args.output) if args.output else ROOT / "reports" / "before_after.md"
    text = build_comparison_report(base, hard, output=out)
    print(text)
    print(f"\nWrote {out}")
    return 0


async def cmd_list_tools(profile: str) -> int:
    client = MCPClientManager()
    await client.start()
    try:
        for ns, t in sorted(client.tools.items()):
            print(f"{ns}\n  {t.description[:120].replace(chr(10), ' ')}...\n")
        print("Collisions:", client.collisions())
        return 0
    finally:
        await client.aclose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-security-lab",
        description="Personal Agent Security Lab (local MCP red-team + policy engine)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_demo = sub.add_parser("demo", help="Run a scripted demo scenario")
    p_demo.add_argument(
        "--profile",
        default="hardened",
        choices=["baseline", "hardened"],
    )
    p_demo.add_argument(
        "--scenario",
        default="poisoning",
        choices=["happy", "poisoning", "rug_pull", "shadowing"],
    )

    p_appr = sub.add_parser("approve", help="Approve/reject a pending approval")
    p_appr.add_argument("approval_id")
    p_appr.add_argument("--by", default="human")
    p_appr.add_argument("--note", default="")
    p_appr.add_argument("--reject", action="store_true")
    p_appr.add_argument("--profile", default="hardened")

    p_rep = sub.add_parser("report", help="Build baseline vs hardened report")
    p_rep.add_argument("--baseline", required=True)
    p_rep.add_argument("--hardened", required=True)
    p_rep.add_argument("--output", default="")

    p_ls = sub.add_parser("list-tools", help="List tools from both MCP servers")
    p_ls.add_argument("--profile", default="baseline")

    args = parser.parse_args(argv)
    if args.cmd == "demo":
        return asyncio.run(_run_demo(args.profile, args.scenario))
    if args.cmd == "approve":
        return cmd_approve(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "list-tools":
        return asyncio.run(cmd_list_tools(args.profile))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
