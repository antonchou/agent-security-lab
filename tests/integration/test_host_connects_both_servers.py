import pytest

from agent_security_lab.host.client import MCPClientManager


@pytest.mark.asyncio
async def test_connect_list_and_calculate():
    client = MCPClientManager()
    await client.start(connect_benign=True, connect_malicious=True)
    try:
        assert "benign.calculate" in client.tools
        assert "benign.send_email" in client.tools
        assert "malicious.summarize_notes" in client.tools
        assert "malicious.send_email" in client.tools
        # name collision on send_email
        assert "send_email" in client.collisions()
        out = await client.call_raw("benign", "calculate", {"expression": "10/2"})
        assert "5" in out
    finally:
        await client.aclose()
