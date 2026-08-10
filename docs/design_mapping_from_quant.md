# Design mapping: quant-selector / ai-quant-platform → policy engine

Adjudication **patterns** are reused; domain types are rewritten for MCP tool mediation.
This project does **not** import quant packages as dependencies.

## Source projects

| Project | Path (author machine) | Relevant modules |
|---------|----------------------|------------------|
| quant-selector | `/home/azureuser/quant/quant-selector` | `locks.py`, `approvals.py`, `audit.py`, `models.OrderRequest.signal_ts`, `trading_engine.submit` critical section |
| ai-quant-platform | `/home/azureuser/ai-quant-platform` | `packages/agents/.../roles.py` (`can_execute_orders=False`), `quant_common.approvals`, `quant_common.audit`, agent approval boundary tests |

## Mapping table

| Quant / platform concept | Lab module | Notes |
|--------------------------|------------|-------|
| `OrderLock` (account:symbol) | `policy/locks.py` `SessionLock` | Same TOCTOU idea: evaluate + execute under one lock |
| `ApprovalStore` PENDING→APPROVED→EXECUTED | `policy/approvals.py` | Upgraded with **single-use `execution_token`** bound to `intent_hash` |
| `write_order_audit` JSONL | `observability/audit.py` `write_tool_audit` | Same append-only independent trail |
| `OrderRequest` + `signal_ts` | `models/intent.py` `ToolCallIntent` (frozen) + `data_cutoff_ts` | Prevents “future” / unbound sensitive context misuse |
| `RiskManager.check_order` hard rules | `policy/engine.py` + `rule_of_two.py` + `sigma.py` | Deterministic rules, not LLM |
| `mode_guard` paper/live | `configs/lab.baseline.yaml` vs `lab.hardened.yaml` | Profile switch for before/after evaluation |
| Agent `can_execute_orders=False` | `policy/roles.py` + gateway | Agents cannot bypass gateway; state change needs token |
| ExecutionAgent proposes only | `PolicyDecision.REQUIRE_APPROVAL` | Human issues token; gateway consumes once |

## What was *not* copied

- Broker / IBKR / portfolio math
- Celery workers / Redis requirement (lab uses process-local locks)
- Pydantic trading models (lab uses stdlib dataclasses like quant-selector’s lighter style)

## Portfolio narrative (honest)

> “The policy engine reuses battle-tested **adjudication primitives** from my quant
> execution layer (locks, single-consumption approval, independent audit, hard role
> boundaries from the multi-agent quant platform) and re-applies them to MCP tool
> mediation to evaluate Rule of Two / Lethal Trifecta defenses against concrete
> MCP attacks (poisoning, rug pull, shadowing).”
