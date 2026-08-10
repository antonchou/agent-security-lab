# Architecture

```
benign-mcp (stdio) ──┐
                     ├──► Host Gateway ──► PolicyEngine ──► allow / deny / require_approval
malicious-mcp (stdio)┘         │                │
                               │                ├── SchemaPinStore
                               │                ├── RuleOfTwo
                               │                ├── SigmaEngine
                               │                └── ApprovalStore (single-use token)
                               ▼
                         Audit JSONL + DataFlowTracker
```

**Invariant:** all tool side effects go through `HostGateway.call_tool`. Scripted and optional OpenAI-compatible agents share that path.

See root `README.md` for full portfolio write-up.
