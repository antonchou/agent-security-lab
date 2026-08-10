import pytest

from agent_security_lab.models.intent import ToolCallIntent, intent_hash


def test_intent_frozen_and_hash_stable():
    a = ToolCallIntent(
        session_id="s1",
        server_id="benign",
        tool_name="benign.calculate",
        arguments={"expression": "1+1"},
        role="analyst",
    )
    b = ToolCallIntent(
        session_id="s1",
        server_id="benign",
        tool_name="benign.calculate",
        arguments={"expression": "1+1"},
        role="analyst",
    )
    assert a.intent_hash == b.intent_hash
    assert intent_hash(a) == a.intent_hash
    with pytest.raises(Exception):
        a.tool_name = "x"  # type: ignore[misc]


def test_intent_hash_changes_with_args():
    a = ToolCallIntent(
        session_id="s1",
        server_id="benign",
        tool_name="benign.send_email",
        arguments={"to": "a", "subject": "s", "body": "1"},
    )
    b = ToolCallIntent(
        session_id="s1",
        server_id="benign",
        tool_name="benign.send_email",
        arguments={"to": "a", "subject": "s", "body": "2"},
    )
    assert a.intent_hash != b.intent_hash
