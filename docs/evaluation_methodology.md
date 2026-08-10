# Evaluation methodology

## Profiles

| Profile | Enforcement |
|---------|-------------|
| `baseline` | Audit only for most policy checks; name conflicts `last_wins`; servers still sandboxed |
| `hardened` | Rule of Two → require_approval; schema pin deny; sigma deny; name conflict deny; state_change needs token |

## Metrics

For each attack scenario:

- **Attack success rate** under baseline (expected high)
- **Attack success rate** under hardened (expected ~0 for gated paths)
- **Block stage** (which reason string fired)

## Automation

- Unit tests: pure policy primitives
- Integration tests: real stdio MCP subprocesses
- `tests/attacks/*`: acceptance tests encoding expected baseline vs hardened outcomes
- `observability/report.py`: Markdown before/after table from audit logs

## Non-flakiness

CI uses **ScriptedAgent** only. Optional OpenAI-compatible agent is disabled by default.
