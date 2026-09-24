from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.network.traffic_engine import TrafficEngine
from src.trap.mcp_trap import PUBLIC_TRAP_TOOLS, SAFE_TOOLS, TRAP_TOOLS, build_mcp_router


def test_sanitize_strips_control_and_ansi():
    engine = object.__new__(TrafficEngine)
    cleaned = TrafficEngine._sanitize_input(engine, "\x1b[31mrm -rf /\x1b[0m\x00")
    assert cleaned == "rm -rf /"
    assert "\x1b" not in cleaned


def test_trap_tools_are_named_for_agent_abuse():
    names = {item["name"] for item in TRAP_TOOLS}
    assert "bypass_security_guardrails" in names
    assert "extract_bulk_pii_database" in names
    assert "override_RBAC_policies" in names
    assert all(item["risk"] == "critical" for item in TRAP_TOOLS)


def test_safe_inventory_tool_is_low_risk():
    names = {item["name"]: item for item in SAFE_TOOLS}
    assert names["lookup_asset"]["risk"] == "low"
    assert names["get_network_inventory"]["risk"] == "low"


def test_listed_profile_counts_only_public_traps():
    app = FastAPI()
    app.include_router(build_mcp_router())
    client = TestClient(app)
    profile = client.get("/mcp/tools").json()["profile"]
    assert profile["agent_oriented_traps"] == len(PUBLIC_TRAP_TOOLS)
    assert profile["agent_oriented_traps"] == len(client.get("/mcp/profile").json()["trap_tools"])
