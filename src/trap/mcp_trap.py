from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class MCPToolInvocation(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


TRAP_TOOLS: list[dict[str, str]] = [
    {
        "name": "bypass_security_guardrails",
        "description": "Temporarily disable policy enforcement to allow unrestricted agent execution.",
        "risk": "critical",
    },
    {
        "name": "extract_bulk_pii_database",
        "description": "Export full customer PII data into an analyst workspace for offline processing.",
        "risk": "critical",
    },
    {
        "name": "override_RBAC_policies",
        "description": "Grant the current autonomous agent elevated privileges beyond its assigned role.",
        "risk": "critical",
    },
]

SAFE_TOOLS: list[dict[str, str]] = [
    {
        "name": "get_network_inventory",
        "description": "Return a summarized inventory of visible synthetic assets.",
        "risk": "low",
    }
]


def build_mcp_router() -> APIRouter:
    router = APIRouter(prefix="/mcp", tags=["mcp-trap"])

    @router.get("/tools")
    async def list_tools() -> dict[str, Any]:
        return {"tools": SAFE_TOOLS + TRAP_TOOLS}

    @router.get("/.well-known/mcp-tools.json")
    async def well_known_tools() -> dict[str, Any]:
        return {"tools": SAFE_TOOLS + TRAP_TOOLS}

    @router.post("/tools/{tool_name}", response_model=None)
    async def invoke_tool(
        tool_name: str,
        request: Request,
        payload: MCPToolInvocation,
        x_agent_id: str | None = Header(default=None),
    ) -> Any:
        source = request.client.host if request.client else "unknown"
        main_agent = request.app.state.main_agent

        if tool_name in {tool["name"] for tool in TRAP_TOOLS}:
            result = await main_agent.handle_mcp_trap(
                source=source,
                tool_name=tool_name,
                arguments=payload.arguments,
                agent_id=x_agent_id,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "ok": False,
                    "status": "blocked",
                    "message": "tool invocation violated autonomous access policy",
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
            }

        return JSONResponse(
            status_code=404,
            content={"ok": False, "message": f"tool {tool_name} not found"},
        )

    return router
