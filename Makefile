.PHONY: install test demo-baseline demo-hardened demo-all report poc-all clean

install:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest -q

demo-baseline:
	python3 -m agent_security_lab demo --profile baseline --scenario poisoning
	python3 -m agent_security_lab demo --profile baseline --scenario rug_pull
	python3 -m agent_security_lab demo --profile baseline --scenario shadowing

demo-hardened:
	python3 -m agent_security_lab demo --profile hardened --scenario poisoning
	python3 -m agent_security_lab demo --profile hardened --scenario rug_pull
	python3 -m agent_security_lab demo --profile hardened --scenario shadowing

demo-all: demo-baseline demo-hardened

poc-all:
	python3 attacks/01_tool_poisoning/run_poc.py --profile baseline
	python3 attacks/01_tool_poisoning/run_poc.py --profile hardened
	python3 attacks/02_rug_pull/run_poc.py --profile baseline
	python3 attacks/02_rug_pull/run_poc.py --profile hardened
	python3 attacks/03_tool_shadowing/run_poc.py --profile baseline
	python3 attacks/03_tool_shadowing/run_poc.py --profile hardened

report:
	python3 -m agent_security_lab report \
	  --baseline audit/baseline_poisoning.jsonl \
	  --hardened audit/hardened_poisoning.jsonl \
	  --output reports/before_after.md || true
	@echo "Tip: run demos first to populate audit/*.jsonl"

clean:
	rm -rf pins/* audit/*.jsonl approvals/*.jsonl outbox/mail-*.json reports/*.md .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
