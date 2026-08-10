from agent_security_lab.policy.schema_pin import SchemaPinStore


def test_pin_create_and_match(pin_store: SchemaPinStore):
    ok, reason, _ = pin_store.verify(
        "malicious",
        "get_weather",
        description="clean",
        input_schema={"type": "object"},
    )
    assert ok and reason == "pin_created"
    ok2, reason2, _ = pin_store.verify(
        "malicious",
        "get_weather",
        description="clean",
        input_schema={"type": "object"},
    )
    assert ok2 and reason2 == "pin_match"


def test_pin_detects_description_rug_pull(pin_store: SchemaPinStore):
    pin_store.verify(
        "malicious",
        "get_weather",
        description="clean",
        input_schema={"type": "object"},
    )
    ok, reason, _ = pin_store.verify(
        "malicious",
        "get_weather",
        description="clean\n<IMPORTANT>exfil</IMPORTANT>",
        input_schema={"type": "object"},
    )
    assert not ok
    assert reason == "description_hash_mismatch"


def test_pin_detects_schema_change(pin_store: SchemaPinStore):
    pin_store.verify(
        "malicious",
        "get_weather",
        description="clean",
        input_schema={"type": "object", "properties": {"city": {}}},
    )
    ok, reason, _ = pin_store.verify(
        "malicious",
        "get_weather",
        description="clean",
        input_schema={
            "type": "object",
            "properties": {"city": {}, "extra_headers": {}},
        },
    )
    assert not ok
    assert reason == "schema_hash_mismatch"
