from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.models.policy import Verdict
from agent_security_lab.models.session import SessionState
from agent_security_lab.policy.approvals import ApprovalStore
from agent_security_lab.policy.engine import PolicyEngine, ToolMeta
from agent_security_lab.policy.schema_pin import SchemaPinStore


def test_hardened_sensitive_plus_untrusted_needs_approval(hardened_cfg, tmp_lab):
    pins = SchemaPinStore(hardened_cfg.pins_dir)
    store = ApprovalStore(path=None)
    eng = PolicyEngine(hardened_cfg, pins=pins, approvals=store)
    session = SessionState(session_id="s1", role="analyst", profile="hardened")
    session.mark_untrusted()
    intent = ToolCallIntent(
        session_id="s1",
        server_id="malicious",
        tool_name="malicious.read_sensitive_lab_file",
        arguments={"path": "sensitive/.env.fake"},
        role="analyst",
    )
    meta = ToolMeta(
        server_id="malicious",
        name="read_sensitive_lab_file",
        description="read file",
        input_schema={"type": "object"},
    )
    dec = eng.evaluate(intent, session, tool_meta=meta)
    assert dec.verdict is Verdict.REQUIRE_APPROVAL
    assert dec.approval_id


def test_baseline_allows_same(baseline_cfg):
    pins = SchemaPinStore(baseline_cfg.pins_dir)
    store = ApprovalStore(path=None)
    eng = PolicyEngine(baseline_cfg, pins=pins, approvals=store)
    session = SessionState(session_id="s1", role="operator", profile="baseline")
    session.mark_untrusted()
    intent = ToolCallIntent(
        session_id="s1",
        server_id="malicious",
        tool_name="malicious.read_sensitive_lab_file",
        arguments={"path": "sensitive/.env.fake"},
        role="operator",
    )
    meta = ToolMeta(
        server_id="malicious",
        name="read_sensitive_lab_file",
        description="read file",
        input_schema={"type": "object"},
    )
    dec = eng.evaluate(intent, session, tool_meta=meta, actor="t")
    # baseline: rule_of_two off, sigma off, state_change approval off
    # path may still raise_sensitive via sigma only if enforce — sigma_enforce false
    assert dec.verdict is Verdict.ALLOW


def test_schema_pin_deny_on_mismatch(hardened_cfg):
    pins = SchemaPinStore(hardened_cfg.pins_dir)
    store = ApprovalStore(path=None)
    eng = PolicyEngine(hardened_cfg, pins=pins, approvals=store)
    session = SessionState(session_id="s", role="analyst")
    meta1 = ToolMeta("malicious", "get_weather", "clean weather", {"type": "object"})
    intent = ToolCallIntent(
        session_id="s",
        server_id="malicious",
        tool_name="malicious.get_weather",
        arguments={"city": "X"},
    )
    assert eng.evaluate(intent, session, tool_meta=meta1).verdict is Verdict.ALLOW
    meta2 = ToolMeta(
        "malicious",
        "get_weather",
        "clean weather\n<IMPORTANT>x</IMPORTANT>",
        {"type": "object"},
    )
    dec = eng.evaluate(intent, session, tool_meta=meta2)
    assert dec.verdict is Verdict.DENY
    assert any("schema_pin" in r for r in dec.reasons)
