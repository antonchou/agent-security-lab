#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== HARDENED demos (attacks expected to be gated) ==="
python3 -m agent_security_lab demo --profile hardened --scenario poisoning
python3 -m agent_security_lab demo --profile hardened --scenario rug_pull
python3 -m agent_security_lab demo --profile hardened --scenario shadowing
