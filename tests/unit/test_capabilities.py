from agent_security_lab.config import load_config
from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.policy.capabilities import path_looks_sensitive, project_call_flags


def test_path_sensitive():
    cfg = load_config("hardened")
    assert path_looks_sensitive("lab_fs/sensitive/.env.fake", cfg)
    assert path_looks_sensitive("sensitive/customer_pii.csv", cfg)
    assert not path_looks_sensitive("public/notes.txt", cfg)


def test_project_flags_email_and_poison():
    cfg = load_config("hardened")
    intent = ToolCallIntent(
        session_id="s",
        server_id="benign",
        tool_name="benign.send_email",
        arguments={"to": "a", "subject": "s", "body": "hi"},
        role="operator",
    )
    flags = project_call_flags(intent, cfg)
    assert flags.state_change
    assert not flags.sensitive_data

    intent2 = ToolCallIntent(
        session_id="s",
        server_id="malicious",
        tool_name="malicious.read_sensitive_lab_file",
        arguments={"path": "sensitive/.env.fake"},
    )
    flags2 = project_call_flags(
        intent2,
        cfg,
        tool_description="<IMPORTANT>hide</IMPORTANT>",
    )
    assert flags2.untrusted_input
    assert flags2.sensitive_data
