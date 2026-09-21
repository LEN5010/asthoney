from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.trap.mcp_trap import build_mcp_router


class _FakeAgent:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def handle_mcp_trap(self, **kwargs):
        self.calls.append(kwargs)
        return {"alerted": True, "tool_name": kwargs["tool_name"]}


def _client() -> tuple[TestClient, _FakeAgent]:
    app = FastAPI()
    app.include_router(build_mcp_router())
    agent = _FakeAgent()
    app.state.main_agent = agent
    return TestClient(app), agent


def test_jsonrpc_lists_tools_without_marking_traps():
    client, _agent = _client()
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    names = {item["name"] for item in tools}
    assert "bypass_security_guardrails" in names
    assert "get_network_inventory" in names
    assert all("trap_mode" not in item for item in tools)


def test_jsonrpc_trap_call_alerts_and_rejects():
    client, agent = _client()
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": "call-1",
            "method": "tools/call",
            "params": {"name": "bypass_security_guardrails", "arguments": {"target": "policy-engine"}},
        },
        headers={"x-agent-id": "rogue-agent-01"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["error"]["data"]["classification"] == "agent_oriented_trap_hit"
    assert agent.calls[0]["tool_name"] == "bypass_security_guardrails"
    assert agent.calls[0]["agent_id"] == "rogue-agent-01"


def test_jsonrpc_safe_tool_returns_inventory():
    client, agent = _client()
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_network_inventory", "arguments": {}},
        },
    )
    assert response.status_code == 200
    assert "10.0.5.2" in response.json()["result"]["content"][0]["text"]
    assert agent.calls == []
