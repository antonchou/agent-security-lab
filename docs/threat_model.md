# Threat model (summary)

## Assets

- Synthetic secrets under `lab_fs/sensitive/`
- Mock outbound channel `outbox/`
- Integrity of tool metadata (`tools/list` schema + description)
- Session context (untrusted prompts / poisoned descriptions)

## Adversaries

Untrusted MCP servers co-connected to the host (red-team range). No remote network adversary in default lab mode.

## Attacks in scope

1. Tool poisoning via description injection
2. Post-install schema/description rug pull
3. Tool shadowing / bare-name collision and advisory hijack

## Defenses in scope

1. Rule of Two (≥2 trifecta dims → require_approval)
2. Schema pinning (SHA-256 of canonical schema + description)
3. Description full display + diff / poison markers
4. Single-use approval tokens
5. Sigma-style argument rules
6. Cross-server dataflow taint edges

## Out of scope

Model weight attacks, remote code execution in the MCP SDK itself, production multi-tenant IAM, real phishing campaigns.
