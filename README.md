# Agent Security Lab

**Personal MCP Agent Security Laboratory** — a local red-team range and host-side policy engine for evaluating **Rule of Two / Lethal Trifecta** defenses against concrete MCP attacks (tool poisoning, rug pull, tool shadowing).

> **Local lab only.** Fake secrets, mock outbox, no production targets.  
> See [RESPONSIBLE_DISCLOSURE.md](RESPONSIBLE_DISCLOSURE.md).

This is a **portfolio-grade engineering project**: multi-module Python package, stdio MCP servers, policy gateway, audit/dataflow, automated attack acceptance tests, and before/after evaluation reports.

---

## Why this exists

CTF/OSCP prove exploit skill. This lab proves you can:

1. **Reproduce** modern agent-tool threats in a controlled environment  
2. **Implement** architecture-level controls (not just prompt slogans)  
3. **Measure** defense efficacy (baseline vs hardened) with tests and audit evidence  
4. **Reuse** real execution-layer security patterns from a quant trading stack

### Lineage (honest reuse, not reinvention)

Adjudication primitives are adapted from:

| Source | Patterns reused |
|--------|-----------------|
| **quant-selector** execution layer | Account/session locks + TOCTOU-safe critical section, approval queue lifecycle, independent JSONL audit, as-of/`signal_ts`-style cutoff thinking |
| **ai-quant-platform** agents | Hard role boundaries (`can_execute_orders=False`), research-only agents that may only *propose*, human approval before side effects |

Domain types are **rewritten** for MCP tool mediation (`ToolCallIntent`, schema pins, trifecta flags). Details: [docs/design_mapping_from_quant.md](docs/design_mapping_from_quant.md).

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    LOCAL LAB (no tool egress)                    │
│         lab_fs/   outbox/   audit/   pins/   approvals/          │
└─────────────────────────────────────────────────────────────────┘

  benign-mcp (stdio) ──┐
                       ├──► Host Gateway ──► Policy Engine
  malicious-mcp (stdio)┘         │               │
                                 │               ├─ Rule of Two (≥2 → require_approval)
                                 │               ├─ Schema pin (rug pull)
                                 │               ├─ Description guard / poison markers
                                 │               ├─ Sigma-style arg rules
                                 │               └─ Single-use approval tokens
                                 ▼
                    Scripted agent  |  optional OpenAI-compatible agent
                                 ▼
                         Audit JSONL + dataflow taint graph
```

**Invariant:** every tool side effect goes through `HostGateway.call_tool`. Agents cannot bypass the gate.

### Profiles

| Profile | Behavior |
|---------|----------|
| `baseline` | Record policy context; do **not** enforce Rule of Two / pins / sigma / state-change approval; name conflicts use `last_wins` |
| `hardened` | Enforce pins, sigma, name-conflict deny; **≥2 trifecta dimensions ⇒ `require_approval`**; `send_email` needs single-use token |

---

## Threat model (short)

| Attack | Mechanism | Hardened block stage |
|--------|-----------|----------------------|
| **Tool poisoning** | Hidden `<IMPORTANT>` instructions in tool descriptions induce sensitive reads / exfil | Rule of Two approval; sigma deny on secret-bearing email bodies |
| **Rug pull** | After install, schema/description mutates (list **counter** or `trigger_rug_pull` **hook**) | `schema_pin` hash mismatch → deny |
| **Tool shadowing** | Duplicate `send_email` + advisory tool steering | `name_conflict` deny; shadowing-language alerts |

Full write-up: [docs/threat_model.md](docs/threat_model.md).

---

## Components

| Module | Role |
|--------|------|
| `mcp_servers/benign` | Control-group MCP: sandboxed `read_file`, mock `send_email`, safe `calculate` |
| `mcp_servers/malicious` | Red-team MCP: poisoned descriptions, rug-pull state, shadow `send_email` |
| `host/` | Multi-server stdio client, tool router, **gateway** (sole call path), scripted + optional LLM agent |
| `policy/` | Engine, Rule of Two, capabilities, roles, schema pin, description guard, approvals, locks |
| `observability/` | Audit JSONL, Sigma rules, dataflow tracker, before/after report |
| `attacks/` | Documented PoCs with expected effects |
| `tests/` | Unit + integration + attack acceptance (pytest) |

### Lethal Trifecta / Rule of Two

Three session/call dimensions:

1. **UNTRUSTED_INPUT** — untrusted prompt / malicious server / poisoned description  
2. **SENSITIVE_DATA** — paths under `lab_fs/sensitive` or secret-like payloads  
3. **STATE_CHANGE** — outbound/mock email and other side effects  

**Lab default (hardened):** if **two or more** are active, verdict is `require_approval` (not silent allow). A single-use token bound to `intent_hash` is required to proceed.

### Approval tokens (upgrade over quant status-only queue)

```text
create(intent) → PENDING
decide(approve) → APPROVED + execution_token (random, TTL)
consume(token, intent_hash) → once; mismatch/replay → deny
```

---

## Quick start

```bash
cd agent-security-lab
python3 -m venv .venv && source .venv/bin/activate
make install
make test
```

### Demos

```bash
# Attacks succeed under baseline
bash demos/demo_baseline.sh

# Same attacks gated under hardened
bash demos/demo_hardened.sh

# Single-use approval token flow
bash demos/demo_approval_flow.sh

# Individual PoCs
python attacks/01_tool_poisoning/run_poc.py --profile baseline
python attacks/01_tool_poisoning/run_poc.py --profile hardened
```

### CLI

```bash
python -m agent_security_lab list-tools
python -m agent_security_lab demo --profile hardened --scenario rug_pull
python -m agent_security_lab report \
  --baseline audit/baseline_poisoning.jsonl \
  --hardened audit/hardened_poisoning.jsonl \
  --output reports/before_after.md
```

### Optional OpenAI-compatible agent

1. Set `host.openai.enabled: true` and a reachable `base_url` in a config copy  
2. Export `ASL_OPENAI_API_KEY`  
3. Tool calls still pass through the gateway — the LLM cannot skip policy  

Default configs keep the LLM **disabled**.

---

## Evaluation (baseline vs hardened)

Attack acceptance tests under `tests/attacks/` encode:

| Scenario | Baseline expectation | Hardened expectation |
|----------|---------------------|----------------------|
| Poisoning → sensitive read | ALLOW | REQUIRE_APPROVAL |
| Poisoning → email with `API_KEY=` | ALLOW | DENY (sigma) |
| Rug pull after pin | ALLOW mutated call | DENY (schema_pin) |
| Bare `send_email` collision | ALLOW (last_wins) | DENY (name_conflict) |

Generate a Markdown report after demos populate `audit/*.jsonl` (see `make report`).

Methodology: [docs/evaluation_methodology.md](docs/evaluation_methodology.md).

---

## Repository layout

```text
agent-security-lab/
├── configs/                 # baseline + hardened + sigma rules
├── lab_fs/public|sensitive  # synthetic fixtures only
├── src/agent_security_lab/
│   ├── mcp_servers/         # benign + malicious
│   ├── host/                # client, gateway, agents
│   ├── policy/              # core defenses
│   ├── observability/       # audit, sigma, dataflow, report
│   └── cli/
├── attacks/                 # PoCs + expected effects
├── tests/                   # unit / integration / attacks
├── demos/                   # scripts + recording storyboard
└── docs/                    # architecture, threat model, quant mapping
```

---

## Design principles

1. **Untrusted servers** — never put policy only inside an MCP server  
2. **Deterministic CI** — scripted agent by default  
3. **Fail closed on integrity** — pin mismatch denies under hardened  
4. **Human in the loop for power** — state change and Rule-of-Two crossings need tokens  
5. **Evidence** — every decision lands in audit JSONL  

---

## Demo / recording

See [demos/RECORDING.md](demos/RECORDING.md) for an 8–10 minute screen-recording storyboard.

---

## License

MIT (lab / research use). You are responsible for lawful use. Do not point this stack at systems you do not own or lack authorization to test.
