import pytest

from agent_security_lab.models.approval import ApprovalStatus
from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.policy.approvals import ApprovalStore


def _intent(body: str = "hi") -> ToolCallIntent:
    return ToolCallIntent(
        session_id="s",
        server_id="benign",
        tool_name="benign.send_email",
        arguments={"to": "a@b.c", "subject": "s", "body": body},
        role="operator",
    )


def test_single_use_token_lifecycle():
    store = ApprovalStore(path=None, token_ttl_seconds=600)
    intent = _intent()
    item = store.create(intent, proposed_by="test")
    assert item.status is ApprovalStatus.PENDING
    decided = store.decide(item.approval_id, approve=True, decided_by="human")
    assert decided.status is ApprovalStatus.APPROVED
    assert decided.execution_token is not None
    tok = decided.execution_token.token
    store.consume(tok, intent.intent_hash)
    assert store.get(item.approval_id).status is ApprovalStatus.EXECUTED
    with pytest.raises(ValueError, match="already_used"):
        store.consume(tok, intent.intent_hash)


def test_token_intent_mismatch():
    store = ApprovalStore(path=None)
    intent = _intent("a")
    other = _intent("b")
    item = store.create(intent, proposed_by="test")
    decided = store.decide(item.approval_id, approve=True, decided_by="h")
    with pytest.raises(ValueError, match="intent_mismatch"):
        store.consume(decided.execution_token.token, other.intent_hash)


def test_reject():
    store = ApprovalStore(path=None)
    item = store.create(_intent(), proposed_by="test")
    store.decide(item.approval_id, approve=False, decided_by="h", note="nope")
    assert store.get(item.approval_id).status is ApprovalStatus.REJECTED
