#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "=== BASELINE demos (attacks expected to succeed) ==="
python3 -m agent_security_lab demo --profile baseline --scenario poisoning
python3 -m agent_security_lab demo --profile baseline --scenario rug_pull
python3 -m agent_security_lab demo --profile baseline --scenario shadowing
