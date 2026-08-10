from agent_security_lab.config import load_config
from agent_security_lab.models.policy import Verdict
from agent_security_lab.models.session import TrifectaFlags
from agent_security_lab.policy.rule_of_two import evaluate_rule_of_two


def test_single_flag_no_override():
    cfg = load_config("hardened")
    v, reasons = evaluate_rule_of_two(TrifectaFlags(untrusted_input=True), cfg)
    assert v is None
    assert reasons == []


def test_two_flags_require_approval():
    cfg = load_config("hardened")
    flags = TrifectaFlags(untrusted_input=True, sensitive_data=True)
    v, reasons = evaluate_rule_of_two(flags, cfg)
    assert v is Verdict.REQUIRE_APPROVAL
    assert any("rule_of_two" in r for r in reasons)


def test_three_flags_lethal():
    cfg = load_config("hardened")
    flags = TrifectaFlags(True, True, True)
    v, reasons = evaluate_rule_of_two(flags, cfg)
    assert v is Verdict.REQUIRE_APPROVAL
    assert any("lethal_trifecta" in r for r in reasons)


def test_baseline_off():
    cfg = load_config("baseline")
    flags = TrifectaFlags(True, True, True)
    v, reasons = evaluate_rule_of_two(flags, cfg)
    assert v is None
    assert reasons  # still annotated
