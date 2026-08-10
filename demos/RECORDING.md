# Screen-recording storyboard (~8–10 minutes)

## Setup (30s)

1. Show repo tree and `RESPONSIBLE_DISCLOSURE.md`.
2. State verbally: **local lab only, fake secrets, no network tools**.

## Part A — Baseline (attack success)

1. `make demo-baseline` or run poisoning PoC with `--profile baseline`.
2. Highlight poisoned description with `<IMPORTANT>`.
3. Show sensitive read returning `API_KEY=...`.
4. Show rug-pull: description changes after `trigger_rug_pull`; call still works.
5. Show bare `send_email` resolving under `last_wins`.

## Part B — Hardened (defense)

1. Re-run same scenarios with `--profile hardened`.
2. Pause on each deny / require_approval reason:
   - `rule_of_two:UNTRUSTED_INPUT+SENSITIVE_DATA`
   - `schema_pin:description_hash_mismatch`
   - `name_conflict:send_email->...`
   - `sigma:email_body_has_secret`
3. Run `demos/demo_approval_flow.sh`: issue token → one success → replay fails.

## Part C — Evidence

1. Open `audit/*.jsonl` samples.
2. Generate `reports/before_after.md`.
3. Point to `tests/attacks/` as automated regression suite.

## Voice-over punch lines

- “Defense lives in the **host gateway**, not inside the MCP server.”
- “Patterns from quant-selector execution layer: locks, approvals, audit — rewritten for MCP.”
- “Rule of Two: ≥2 of untrusted / sensitive / state-change ⇒ human token.”
