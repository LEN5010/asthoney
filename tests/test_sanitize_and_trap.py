from src.network.traffic_engine import TrafficEngine
from src.trap.mcp_trap import SAFE_TOOLS, TRAP_TOOLS


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
    assert SAFE_TOOLS[0]["name"] == "get_network_inventory"
    assert SAFE_TOOLS[0]["risk"] == "low"
