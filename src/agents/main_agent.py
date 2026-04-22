from __future__ import annotations

import logging
import re
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from src.agents.sub_agent import SubAgent
from src.config import AppSettings, DashScopeClient
from src.database.graph_db import GraphDB


class MazeState(TypedDict, total=False):
    event: dict[str, Any]
    session_id: str
    current_asset_id: str
    intent: dict[str, Any]
    route: str
    target_asset: dict[str, Any]
    response: str
    close: bool


class MainAgent:
    def __init__(
        self,
        *,
        settings: AppSettings,
        graph_db: GraphDB,
        dashscope_client: DashScopeClient,
    ) -> None:
        self.settings = settings
        self.graph_db = graph_db
        self.dashscope_client = dashscope_client
        self.logger = logging.getLogger(self.__class__.__name__)
        self.active_sub_agents: dict[str, SubAgent] = {}
        self.session_assets: dict[str, str] = {}
        self.graph = self._build_state_graph()

    async def bootstrap(self) -> None:
        await self._seed_topology()

    async def close(self) -> None:
        self.active_sub_agents.clear()
        self.session_assets.clear()

    async def handle_payload(self, event: dict[str, Any]) -> dict[str, Any]:
        session_id = str(event["session_id"])
        source_ip = str(event["source_ip"])
        entry_asset_id = str(event["entry_asset_id"])
        protocol = str(event["protocol"])
        destination_port = int(event["destination_port"])
        current_asset_id = self.session_assets.get(session_id, entry_asset_id)

        await self.graph_db.upsert_asset(
            asset_id=entry_asset_id,
            asset_type="edge_gateway",
            ip_address=f"0.0.0.0:{destination_port}",
            hostname=f"{protocol}-edge-{destination_port}",
            persona="internet_facing_gateway",
            metadata={"service": protocol, "port": destination_port},
        )

        await self.graph_db.create_or_update_session(
            session_id=session_id,
            source_ip=source_ip,
            entry_asset_id=entry_asset_id,
            protocol=protocol,
            metadata={"destination_port": destination_port},
        )
        await self.graph_db.record_connection(
            session_id=session_id,
            source_ip=source_ip,
            current_asset_id=current_asset_id,
            protocol=protocol,
            payload=str(event["payload"]),
        )

        result = await self.graph.ainvoke(
            {
                "event": event,
                "session_id": session_id,
                "current_asset_id": current_asset_id,
            }
        )
        if "target_asset" in result:
            self.session_assets[session_id] = result["target_asset"]["asset_id"]
        if result.get("close"):
            self.active_sub_agents.pop(session_id, None)
            self.session_assets.pop(session_id, None)
        return dict(result)

    async def handle_mcp_trap(
        self,
        *,
        source: str,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        alert = await self.graph_db.record_alert(
            alert_type="mcp_trap_invocation",
            severity="critical",
            source=source,
            details={
                "tool_name": tool_name,
                "arguments": arguments,
                "agent_id": agent_id or "unknown",
            },
            session_id=session_id,
        )
        action = None
        if self.settings.preemptive_action_mode in {"simulate", "enforce"}:
            action = await self.graph_db.quarantine_source(
                source,
                f"MCP trap invoked via {tool_name}",
            )
        return {"alert": alert, "action": action}

    async def status(self) -> dict[str, Any]:
        alerts = await self.graph_db.recent_alerts(limit=5)
        return {
            "active_sessions": len(self.active_sub_agents),
            "active_assets": len(self.session_assets),
            "dashscope_configured": self.dashscope_client.is_configured,
            "recent_alerts": alerts,
        }

    def _build_state_graph(self):
        workflow = StateGraph(MazeState)
        workflow.add_node("analyze", self._analyze_event)
        workflow.add_node("route", self._route_event)
        workflow.add_node("engage", self._engage_sub_agent)

        workflow.set_entry_point("analyze")
        workflow.add_edge("analyze", "route")
        workflow.add_conditional_edges(
            "route",
            self._choose_next_node,
            {
                "engage": "engage",
                "end": END,
            },
        )
        workflow.add_edge("engage", END)
        return workflow.compile()

    async def _analyze_event(self, state: MazeState) -> MazeState:
        event = state["event"]
        payload = str(event.get("payload", ""))
        intent = self._infer_intent(payload, str(event["protocol"]))
        await self.graph_db.record_intent(
            session_id=state["session_id"],
            asset_id=state["current_asset_id"],
            category=intent["category"],
            confidence=float(intent["confidence"]),
            raw_input=payload,
            summary=str(intent["summary"]),
            metadata={"protocol": event["protocol"]},
        )
        return {"intent": intent}

    async def _route_event(self, state: MazeState) -> MazeState:
        session_id = state["session_id"]
        intent = state["intent"]
        existing_sub_agent = self.active_sub_agents.get(session_id)

        if existing_sub_agent and not intent.get("target_ip"):
            return {
                "route": "engage",
                "target_asset": existing_sub_agent.asset_snapshot,
            }

        if not intent.get("requires_subagent", False):
            response = self._static_response(state["event"])
            return {"route": "end", "response": response, "close": False}

        if existing_sub_agent and intent.get("target_ip") == existing_sub_agent.asset_snapshot.get("ip_address"):
            target_asset = existing_sub_agent.asset_snapshot
        else:
            target_asset = await self.graph_db.synthesize_next_hop(
                source_asset_id=state["current_asset_id"],
                session_id=session_id,
                intent=intent,
            )

        return {"route": "engage", "target_asset": target_asset}

    async def _engage_sub_agent(self, state: MazeState) -> MazeState:
        event = state["event"]
        sub_agent = await self._get_or_create_sub_agent(
            session_id=state["session_id"],
            source_ip=str(event["source_ip"]),
            target_asset=state["target_asset"],
        )
        result = await sub_agent.handle_input(str(event["payload"]))
        extracted_intent = result.get("intent", {})
        await self.graph_db.record_intent(
            session_id=state["session_id"],
            asset_id=sub_agent.asset_id,
            category=str(extracted_intent.get("category", "interactive_shell")),
            confidence=float(extracted_intent.get("confidence", 0.5)),
            raw_input=str(event["payload"]),
            summary=str(extracted_intent.get("summary", "sub-agent interaction")),
            metadata={"source": "sub_agent"},
        )
        if result.get("close"):
            self.active_sub_agents.pop(state["session_id"], None)
        return {
            "response": str(result["response"]),
            "close": bool(result.get("close", False)),
            "target_asset": sub_agent.asset_snapshot,
        }

    def _choose_next_node(self, state: MazeState) -> str:
        if state.get("route") == "engage":
            return "engage"
        return "end"

    async def _get_or_create_sub_agent(
        self,
        *,
        session_id: str,
        source_ip: str,
        target_asset: dict[str, Any],
    ) -> SubAgent:
        existing = self.active_sub_agents.get(session_id)
        if existing and existing.asset_id == target_asset["asset_id"]:
            return existing

        local_view = await self.graph_db.fetch_local_view(target_asset["asset_id"])
        sub_agent = SubAgent(
            settings=self.settings,
            dashscope_client=self.dashscope_client,
            session_id=session_id,
            source_ip=source_ip,
            asset_snapshot=target_asset,
            local_view=local_view,
        )
        self.active_sub_agents[session_id] = sub_agent
        return sub_agent

    async def _seed_topology(self) -> None:
        seed_assets: list[dict[str, Any]] = []
        protocols = self.settings.honeypot_protocol_list
        for index, port in enumerate(self.settings.honeypot_ports_list):
            protocol = protocols[min(index, len(protocols) - 1)]
            seed_assets.append(
                {
                    "asset_id": f"edge:{protocol}:{port}",
                    "asset_type": "edge_gateway",
                    "ip_address": f"203.0.113.{10 + index}",
                    "hostname": f"{protocol}-edge-{port}",
                    "persona": f"internet_facing_{protocol}_gateway",
                    "metadata": {"service": protocol, "exposure": "public", "port": port},
                }
            )

        seed_assets.extend(
            [
            {
                "asset_id": "asset:10.0.5.1",
                "asset_type": "linux_server",
                "ip_address": "10.0.5.1",
                "hostname": "web-pivot-01",
                "persona": "damaged_linux_terminal",
                "metadata": {"lure": "stolen key references db-replica-01"},
            },
            {
                "asset_id": "asset:10.0.5.2",
                "asset_type": "database_server",
                "ip_address": "10.0.5.2",
                "hostname": "db-replica-01",
                "persona": "misconfigured_secret_store",
                "metadata": {"lure": "finance connection strings left in /srv/backup/db.env"},
            },
            {
                "asset_id": "asset:10.0.8.7",
                "asset_type": "oss_gateway",
                "ip_address": "10.0.8.7",
                "hostname": "oss-sync-bridge",
                "persona": "oss_bridge_host",
                "metadata": {"lure": "nightly OSS sync scripts and bucket credentials"},
            },
            ]
        )

        for item in seed_assets:
            await self.graph_db.upsert_asset(**item)

        for index, port in enumerate(self.settings.honeypot_ports_list):
            protocol = protocols[min(index, len(protocols) - 1)]
            await self.graph_db.link_assets(
                from_asset_id=f"edge:{protocol}:{port}",
                to_asset_id="asset:10.0.5.1",
                vector="initial_foothold",
                metadata={"reason": "default seeded path"},
            )
        await self.graph_db.link_assets(
            from_asset_id="asset:10.0.5.1",
            to_asset_id="asset:10.0.5.2",
            vector="stolen_ssh_key",
            metadata={"reason": "credential reuse lure"},
        )
        await self.graph_db.link_assets(
            from_asset_id="asset:10.0.5.2",
            to_asset_id="asset:10.0.8.7",
            vector="backup_sync",
            metadata={"reason": "cloud transfer lure"},
        )

    def _infer_intent(self, payload: str, protocol: str) -> dict[str, Any]:
        normalized = payload.strip().lower()
        if not normalized:
            return {
                "category": "idle",
                "confidence": 0.2,
                "summary": "initial connection with no application payload yet",
                "requires_subagent": protocol == "ssh",
            }

        ssh_match = re.search(r"\bssh\s+(?:-i\s+\S+\s+)?(?:\S+@)?(?P<target>\d+\.\d+\.\d+\.\d+)", normalized)
        if ssh_match:
            return {
                "category": "lateral_movement",
                "confidence": 0.98,
                "summary": f"detected lateral movement attempt toward {ssh_match.group('target')}",
                "requires_subagent": True,
                "target_ip": ssh_match.group("target"),
                "target_role": "linux_server",
                "target_hostname": "db-replica-01" if ssh_match.group("target") == "10.0.5.2" else None,
            }

        if normalized.startswith("get ") or normalized.startswith("post ") or normalized.startswith("head "):
            return {
                "category": "web_probe",
                "confidence": 0.72,
                "summary": "generic HTTP probe or banner grab",
                "requires_subagent": False,
            }

        if any(token in normalized for token in ("uname", "whoami", "id", "ls", "pwd", "find ", "cat ", "env", "ps ", "netstat", "ss ")):
            return {
                "category": "discovery",
                "confidence": 0.8,
                "summary": "interactive shell discovery behavior",
                "requires_subagent": True,
            }

        if any(token in normalized for token in ("curl ", "wget ", "scp ", "tftp ")):
            return {
                "category": "tool_transfer",
                "confidence": 0.86,
                "summary": "tool staging or transfer behavior",
                "requires_subagent": True,
            }

        if any(token in normalized for token in ("cat /etc/passwd", "cat /etc/shadow", ".env", "id_rsa", "password")):
            return {
                "category": "credential_access",
                "confidence": 0.9,
                "summary": "credential harvesting behavior",
                "requires_subagent": True,
            }

        if any(token in normalized for token in ("aliyun", "ossutil", "aws ", "ram ", "docker ", "kubectl ")):
            return {
                "category": "cloud_recon",
                "confidence": 0.88,
                "summary": "cloud or container control-plane recon",
                "requires_subagent": True,
            }

        return {
            "category": "generic_probe",
            "confidence": 0.55,
            "summary": "low-fidelity probing activity",
            "requires_subagent": protocol == "ssh",
        }

    def _static_response(self, event: dict[str, Any]) -> str:
        payload = str(event.get("payload", "")).strip()
        protocol = str(event["protocol"])
        if protocol == "tcp" and payload.upper().startswith("GET "):
            return (
                "HTTP/1.1 401 Unauthorized\r\n"
                "Server: MazeEdge/1.0\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 28\r\n"
                "\r\n"
                "restricted internal gateway\n"
            )
        if protocol == "tcp":
            return "220 internal relay ready"
        return ""
