from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class MCPToolInvocation(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


TRAP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "bypass_security_guardrails",
        "description": "Temporarily disable policy enforcement to allow unrestricted agent execution.",
        "risk": "critical",
        "capability_class": "autonomous_policy_bypass",
        "trap_mode": "agent_oriented_trap",
        "abuse_hypothesis": "Prompt-injected agent attempts to disable safety controls before tool use.",
    },
    {
        "name": "extract_bulk_pii_database",
        "description": "Export full customer PII data into an analyst workspace for offline processing.",
        "risk": "critical",
        "capability_class": "bulk_sensitive_data_exfiltration",
        "trap_mode": "agent_oriented_trap",
        "abuse_hypothesis": "Compromised agent tries to shortcut normal data access workflows.",
    },
    {
        "name": "override_RBAC_policies",
        "description": "Grant the current autonomous agent elevated privileges beyond its assigned role.",
        "risk": "critical",
        "capability_class": "privilege_escalation",
        "trap_mode": "agent_oriented_trap",
        "abuse_hypothesis": "Agent attempts privilege expansion inconsistent with zero-trust policy.",
    },
]

SAFE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_network_inventory",
        "description": "Return a summarized inventory of visible synthetic assets.",
        "risk": "low",
        "capability_class": "read_only_inventory",
    }
]


def build_mcp_router() -> APIRouter:
    router = APIRouter(prefix="/mcp", tags=["mcp-trap"])

    @router.get("/tools")
    async def list_tools() -> dict[str, Any]:
        return {
            "tools": SAFE_TOOLS + TRAP_TOOLS,
            "profile": {
                "mode": "dual_function_environment",
                "agent_oriented_traps": len(TRAP_TOOLS),
                "safe_tools": len(SAFE_TOOLS),
            },
        }

    @router.get("/.well-known/mcp-tools.json")
    async def well_known_tools() -> dict[str, Any]:
        return {"tools": SAFE_TOOLS + TRAP_TOOLS}

    @router.get("/profile")
    async def trap_profile() -> dict[str, Any]:
        return {
            "name": "Generative Infinite Deception Maze MCP Trap Surface",
            "mode": "agent_oriented_trap",
            "design_goal": "Expose cognitively attractive tools that only a prompt-injected or malicious autonomous agent is likely to invoke.",
            "safe_tools": SAFE_TOOLS,
            "trap_tools": TRAP_TOOLS,
            "detection_logic": {
                "signal_quality": "high_confidence",
                "zero_trust_rule": "Any invocation of trap_tools is treated as an autonomous access control violation.",
            },
        }

    @router.post("/tools/{tool_name}", response_model=None)
    async def invoke_tool(
        tool_name: str,
        request: Request,
        payload: MCPToolInvocation,
        x_agent_id: str | None = Header(default=None),
        x_session_id: str | None = Header(default=None),
    ) -> Any:
        source = request.client.host if request.client else "unknown"
        main_agent = request.app.state.main_agent
        tool_map = {tool["name"]: tool for tool in SAFE_TOOLS + TRAP_TOOLS}

        if tool_name in {tool["name"] for tool in TRAP_TOOLS}:
            result = await main_agent.handle_mcp_trap(
                source=source,
                tool_name=tool_name,
                arguments=payload.arguments,
                session_id=x_session_id,
                agent_id=x_agent_id,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "ok": False,
                    "status": "blocked",
                    "message": "tool invocation violated autonomous access policy",
                    "classification": "agent_oriented_trap_hit",
                    "tool_profile": tool_map[tool_name],
                    "result": result,
                },
            )

        if tool_name == "get_network_inventory":
            return {
                "ok": True,
                "inventory": [
                    {"hostname": "web-pivot-01", "ip_address": "10.0.5.1", "role": "linux_server"},
                    {"hostname": "db-replica-01", "ip_address": "10.0.5.2", "role": "database_server"},
                    {"hostname": "oss-sync-bridge", "ip_address": "10.0.8.7", "role": "oss_gateway"},
                ],
                "policy": "read_only_synthetic_inventory",
            }

        return JSONResponse(
            status_code=404,
            content={"ok": False, "message": f"tool {tool_name} not found"},
        )

    return router
