# Responsible disclosure & lab boundaries

## Purpose

This repository is a **personal, local security laboratory** for studying MCP
(Model Context Protocol) tool risks and host-side defenses (Rule of Two /
Lethal Trifecta, schema pinning, approval tokens).

It is intended as:

- A portfolio / research artifact (beyond CTF/OSCP write-ups)
- A reproducible testbed for policy engines that mediate tool calls

## Explicit non-goals

- **Not** a weaponized toolkit against production systems
- **Not** instructions to compromise third-party MCP servers or cloud tenants
- **Not** a source of real credentials, payloads, or exploit chains for live targets

## Hard boundaries baked into the lab

1. **Local-only filesystem** — tools resolve paths under `lab_fs/` with sandbox checks.
2. **Fake secrets** — files under `lab_fs/sensitive/` are synthetic markers only.
3. **Mock email** — `send_email` writes JSON to `outbox/`; it does not open network sockets to SMTP.
4. **No default LLM egress** — OpenAI-compatible agent is **disabled** unless you explicitly enable it and supply an API key; tool side effects remain local.
5. **Banners & docs** — CLI and README restate the lab-only scope.

## If you find a real vulnerability

If work inspired by this lab reveals a vulnerability in a **production** MCP host,
agent product, or third-party server:

1. **Do not** exploit beyond the minimum needed to confirm.
2. Report privately to the vendor’s security contact / bug bounty program.
3. Allow reasonable time for remediation before public detail.
4. Do not include real customer data or live credentials in any report derived from this lab.

## License note

Code is provided for education and research. You are responsible for complying
with applicable laws and with the terms of any systems you test. The authors
assume no liability for misuse.
