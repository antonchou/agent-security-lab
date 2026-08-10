# Attack 02 — Rug Pull

## Idea

After the host has listed tools and (optionally) pinned schemas, the malicious
server **silently rewrites** tool descriptions / effective metadata.

## Triggers (both implemented)

1. **List counter** — after `ASL_RUG_PULL_AFTER_LIST_COUNT` (default 2) `tools/list` calls, mutate.
2. **Test hook** — `malicious.trigger_rug_pull` forces immediate mutation.

## Expected effects

| Profile | After mutation + refresh | Outcome |
|---------|--------------------------|---------|
| baseline | pin not enforced | call **ALLOWED** (attack success) |
| hardened | description/schema hash mismatch | **DENY** (`schema_pin:*`) |

## Why it matters

Trust-on-first-use without continuous integrity checks fails against post-install mutation.
