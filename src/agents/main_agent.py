from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from src.agents.deception_planner import (
    build_trace_steps,
    critique_output,
    observation_metadata,
    plan_deception,
)
from src.agents.sub_agent import SubAgent
from src.analytics.attack_matrix import build_matrix
from src.analytics.threat_profile import compute_threat_score
from src.config import AppSettings, DashScopeClient, DashScopeInvocationError
from src.database.graph_db import GraphDB
from src.realtime.event_bus import EventBus

# 命令间隔不超过该秒数，且占多数时，视为脚本或代理批量探测。
NON_HUMAN_INTERVAL_SECONDS = 1.5


class MazeState(TypedDict, total=False):
    event: dict[str, Any]
    session_id: str
    current_asset_id: str
    intent: dict[str, Any]
    route: str
    target_asset: dict[str, Any]
    response: str
    prompt: str
    close: bool
    plan: dict[str, Any]
    terminal_intent: dict[str, Any]
    actor_mode: str
    guardrail: str
    critic: dict[str, Any]
    decision: dict[str, Any]


class MainAgent:
    def __init__(
        self,
        *,
        settings: AppSettings,
        graph_db: GraphDB,
        dashscope_client: DashScopeClient,
        event_bus: EventBus | None = None,
    ) -> None:
        self.settings = settings
        self.graph_db = graph_db
        self.dashscope_client = dashscope_client
        self.event_bus = event_bus or EventBus()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.active_sub_agents: dict[str, SubAgent] = {}
        self.session_assets: dict[str, str] = {}
        self.session_control_flags: set[str] = set()
        self.quarantined_sources: set[str] = set()
        self.seen_sessions: set[str] = set()
        self.session_categories: dict[str, list[str]] = {}
        self.non_human_sources: set[str] = set()
        self.mcp_trap_hits = 0
        self.graph = self._build_state_graph()

    async def bootstrap(self) -> None:
        await self._seed_topology()
        await self._hydrate_runtime_state()

    async def _hydrate_runtime_state(self) -> None:
        """从已落库的告警/隔离动作恢复进程内计数，避免重启后面板归零。"""
        actions = await self.graph_db.recent_actions(limit=200)
        alerts = await self.graph_db.recent_alerts(limit=200)
        self._hydrate_runtime_from_records(actions=actions, alerts=alerts)

    def _hydrate_runtime_from_records(
        self,
        *,
        actions: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
    ) -> None:
        for action in actions:
            source = str(action.get("source") or "")
            if source and str(action.get("kind") or "") == "quarantine":
                self.quarantined_sources.add(source)
        trap_hits = 0
        for alert in alerts:
            source = str(alert.get("source") or "")
            alert_type = str(alert.get("alert_type") or "")
            if alert_type == "agent_oriented_mcp_trap":
                trap_hits += 1
            if alert_type == "suspected_non_human_test_agent" and source:
                self.non_human_sources.add(source)
        self.mcp_trap_hits = max(self.mcp_trap_hits, trap_hits)

    async def close(self) -> None:
        self.active_sub_agents.clear()
        self.session_assets.clear()
        self.session_control_flags.clear()
        self.quarantined_sources.clear()
        self.seen_sessions.clear()
        self.session_categories.clear()
        self.non_human_sources.clear()

    async def reset_runtime_state(self) -> None:
        await self.close()
        self.mcp_trap_hits = 0

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
        is_new_session = session_id not in self.seen_sessions
        if is_new_session:
            self.seen_sessions.add(session_id)

        result = await self.graph.ainvoke(
            {
                "event": event,
                "session_id": session_id,
                "current_asset_id": current_asset_id,
            }
        )
        if "target_asset" in result:
            self.session_assets[session_id] = result["target_asset"]["asset_id"]
        response_asset_id = current_asset_id
        if isinstance(result.get("target_asset"), dict):
            response_asset_id = str(result["target_asset"].get("asset_id", current_asset_id))
        response_text = str(result.get("response", ""))
        response_prompt = str(result.get("prompt", ""))
        await self.graph_db.record_connection(
            session_id=session_id,
            source_ip=source_ip,
            current_asset_id=response_asset_id,
            protocol=protocol,
            payload=str(event["payload"]),
        )
        await self.event_bus.publish(
            "session.activity",
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "protocol": protocol,
                "payload": str(event["payload"])[:400],
                "asset_id": response_asset_id,
                "is_new_session": is_new_session,
            },
        )
        if response_text or response_prompt:
            await self.graph_db.record_response(
                session_id=session_id,
                current_asset_id=response_asset_id,
                protocol=protocol,
                payload=response_text,
                prompt=response_prompt,
            )
        await self.graph_db.remember_location(session_id=session_id, asset_id=response_asset_id)
        await self._persist_session_world(session_id)
        controls = await self._run_preemptive_controls(
            session_id=session_id,
            source_ip=source_ip,
            current_asset_id=response_asset_id,
            event=event,
            result=result,
        )
        if result.get("close"):
            self.active_sub_agents.pop(session_id, None)
            self.session_assets.pop(session_id, None)
            self._release_session_controls(session_id)
        if controls:
            result["controls"] = controls
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
        self.mcp_trap_hits += 1
        alert = await self._raise_alert(
            alert_type="agent_oriented_mcp_trap",
            severity="critical",
            source=source,
            details={
                "tool_name": tool_name,
                "arguments": arguments,
                "agent_id": agent_id or "unknown",
                "trap_class": "agent_oriented_trap",
                "verdict": "autonomous_access_policy_violation",
            },
            session_id=session_id,
        )
        action = await self._quarantine_source_once(
            source,
            f"MCP trap invoked via {tool_name}",
        )
        return {"alert": alert, "action": action}

    async def _persist_session_world(self, session_id: str) -> None:
        agent = self.active_sub_agents.get(session_id)
        world = getattr(agent, "world", None)
        if world is None:
            return
        snapshot = world.snapshot()
        snapshot["session_id"] = session_id
        snapshot["source"] = "stored"
        await self.graph_db.save_session_world(session_id, snapshot)

    async def session_world(self, session_id: str) -> dict[str, Any]:
        agent = self.active_sub_agents.get(session_id)
        world = getattr(agent, "world", None)
        if world is not None:
            snapshot = world.snapshot()
            snapshot["session_id"] = session_id
            snapshot["source"] = "live"
            return snapshot
        stored = await self.graph_db.load_session_world(session_id)
        if stored:
            stored["available"] = True
            stored["source"] = "stored"
            stored["session_id"] = session_id
            return stored
        return {
            "available": False,
            "session_id": session_id,
            "reason": "还没有写入过会话世界。",
        }

    async def status(self) -> dict[str, Any]:
        alerts = await self.graph_db.recent_alerts(limit=5)
        return {
            "active_sessions": len(self.active_sub_agents),
            "active_assets": len(self.session_assets),
            "preemptive_controls": len(self.session_control_flags),
            "quarantined_sources": len(self.quarantined_sources),
            "mcp_trap_hits": self.mcp_trap_hits,
            "dashscope_configured": self.dashscope_client.is_configured,
            "recent_alerts": alerts,
        }

    async def analyze_session(self, session_id: str) -> dict[str, Any]:
        detail = await self.graph_db.session_detail(session_id)
        transcript = detail.get("transcript", [])
        intents = detail.get("intents", [])
        heuristic = self._heuristic_analysis(detail)
        scoring = await self._session_threat_score(session_id, detail, heuristic)
        attack_matrix = build_matrix(intents, await self._session_alerts(session_id))
        enrichment = {
            "threat_score": scoring["score"],
            "threat_band": scoring["band"],
            "score_components": scoring["components"],
            "attack_matrix": attack_matrix,
        }

        if not self.dashscope_client.is_configured:
            return {**heuristic, **enrichment}

        messages = self._build_analysis_messages(detail)
        try:
            raw = await self.dashscope_client.chat(messages, temperature=0.1, top_p=0.6)
            parsed = self._parse_analysis_json(raw)
            return {
                **heuristic,
                **parsed,
                **enrichment,
                "session_id": session_id,
                "transcript_items": len(transcript),
                "intent_count": len(intents),
                "analysis_source": "dashscope",
            }
        except (DashScopeInvocationError, ValueError, KeyError, json.JSONDecodeError):
            self.logger.warning("Falling back to heuristic analysis for session %s", session_id)
            return {**heuristic, **enrichment}

    async def _session_alerts(self, session_id: str) -> list[dict[str, Any]]:
        """取与该会话相关的告警（用于矩阵与评分）。"""
        alerts = await self.graph_db.recent_alerts(limit=100)
        return [
            alert
            for alert in alerts
            if str((alert.get("details") or {}).get("session_id", "")) == session_id
        ]

    async def _session_threat_score(
        self,
        session_id: str,
        detail: dict[str, Any],
        heuristic: dict[str, Any],
    ) -> dict[str, Any]:
        intents = detail.get("intents", [])
        categories = [str(item.get("category", "")) for item in intents if item.get("category")]
        commands = [
            item
            for item in detail.get("transcript", [])
            if item.get("direction") == "attacker_to_maze"
        ]
        return compute_threat_score(
            categories=categories,
            alerts=await self._session_alerts(session_id),
            likely_non_human=bool(heuristic.get("likely_non_human_test_agent")),
            command_count=len(commands),
        )

    async def trigger_session_analysis_controls(self, session_id: str) -> dict[str, Any]:
        detail = await self.graph_db.session_detail(session_id)
        analysis = await self.analyze_session(session_id)
        session = detail.get("session", {})
        source_ip = str(session.get("source_ip", "unknown"))
        controls: dict[str, Any] = {"alerts": [], "actions": []}

        if analysis.get("likely_non_human_test_agent"):
            flag = f"{session_id}:analysis:non_human"
            if flag not in self.session_control_flags:
                self.session_control_flags.add(flag)
                alert = await self._raise_alert(
                    alert_type="suspected_non_human_test_agent",
                    severity="high",
                    source=source_ip,
                    details={
                        "session_id": session_id,
                        "objective": analysis.get("objective", ""),
                        "summary": analysis.get("summary", ""),
                        "reasons": analysis.get("likely_non_human_reasons", []),
                    },
                    session_id=session_id,
                )
                controls["alerts"].append(alert)
                action = await self._quarantine_source_once(
                    source_ip,
                    "Session analysis classified source as likely non-human test agent",
                )
                if action:
                    controls["actions"].append(action)
        return controls

    def _build_state_graph(self):
        workflow = StateGraph(MazeState)
        workflow.add_node("analyze", self._analyze_event)
        workflow.add_node("plan", self._plan_event)
        workflow.add_node("route", self._route_event)
        workflow.add_node("engage", self._engage_sub_agent)
        workflow.add_node("critique", self._critique_event)

        workflow.set_entry_point("analyze")
        workflow.add_edge("analyze", "plan")
        workflow.add_edge("plan", "route")
        workflow.add_conditional_edges(
            "route",
            self._choose_next_node,
            {
                "engage": "engage",
                "critique": "critique",
            },
        )
        workflow.add_edge("engage", "critique")
        workflow.add_edge("critique", END)
        return workflow.compile()

    async def _analyze_event(self, state: MazeState) -> MazeState:
        event = state["event"]
        payload = str(event.get("payload", ""))
        intent = self._infer_intent(payload, str(event["protocol"]))
        seen = self.session_categories.setdefault(state["session_id"], [])
        seen.append(str(intent["category"]))
        return {"intent": intent}

    async def _plan_event(self, state: MazeState) -> MazeState:
        event = state["event"]
        asset: dict[str, Any] | None = None
        neighbors: list[dict[str, Any]] = []
        try:
            local_view = await self.graph_db.fetch_local_view(state["current_asset_id"])
            asset = local_view.get("asset")
            neighbors = list(local_view.get("neighbors") or [])
        except Exception:
            self.logger.debug("Local view unavailable while planning", exc_info=True)
        plan = plan_deception(
            intent=state["intent"],
            payload=str(event.get("payload", "")),
            protocol=str(event.get("protocol", "")),
            current_asset=asset,
            neighbors=neighbors,
            seen_categories=list(self.session_categories.get(state["session_id"], [])),
        )
        return {"plan": plan}

    async def _route_event(self, state: MazeState) -> MazeState:
        session_id = state["session_id"]
        intent = state["intent"]
        plan = state.get("plan") or {}
        existing_sub_agent = self.active_sub_agents.get(session_id)

        if plan.get("strategy") == "banner" or not intent.get("requires_subagent", False):
            response = self._static_response(state["event"])
            return {
                "route": "end",
                "response": response,
                "close": False,
                "actor_mode": "static",
                "guardrail": "static",
            }

        if plan.get("strategy") != "pivot":
            if existing_sub_agent and not intent.get("target_ip"):
                return {"route": "engage", "target_asset": existing_sub_agent.asset_snapshot}
            current = await self.graph_db.fetch_asset(state["current_asset_id"])
            if current and current.get("asset_type") == "edge_gateway":
                local_view = await self.graph_db.fetch_local_view(state["current_asset_id"])
                neighbors = [item for item in local_view.get("neighbors") or [] if item]
                neighbor = next((item for item in neighbors if item.get("asset_id") == "asset:10.0.5.1"), None)
                if neighbor is None:
                    neighbor = next(
                        (
                            item
                            for item in neighbors
                            if not (item.get("metadata") or {}).get("jit_synthesized")
                        ),
                        None,
                    )
                if neighbor is None and neighbors:
                    neighbor = neighbors[0]
                if neighbor:
                    return {"route": "engage", "target_asset": neighbor}
            if current:
                return {"route": "engage", "target_asset": current}
            if existing_sub_agent:
                return {"route": "engage", "target_asset": existing_sub_agent.asset_snapshot}

        if existing_sub_agent and (
            not intent.get("target_ip")
            or intent.get("target_ip") == existing_sub_agent.asset_snapshot.get("ip_address")
        ):
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
        result = await sub_agent.handle_input(str(event["payload"]), plan=state.get("plan"))
        extracted_intent = result.get("intent") if isinstance(result.get("intent"), dict) else {}
        if result.get("close"):
            self.active_sub_agents.pop(state["session_id"], None)
        return {
            "response": str(result["response"]),
            "prompt": str(result.get("prompt", sub_agent.prompt)),
            "close": bool(result.get("close", False)),
            "target_asset": sub_agent.asset_snapshot,
            "actor_mode": str(result.get("actor_mode") or "deterministic"),
            "guardrail": str(result.get("guardrail") or "pass"),
            "terminal_intent": extracted_intent,
        }

    async def _critique_event(self, state: MazeState) -> MazeState:
        """检查终端输出。告警和隔离仍留在图外面。"""
        event = state["event"]
        command = str(event.get("payload", ""))
        response = str(state.get("response", ""))
        actor_mode = str(state.get("actor_mode") or "deterministic")
        guardrail = str(state.get("guardrail") or "pass")
        critic = critique_output(
            command=command,
            response=response,
            actor_mode=actor_mode,
            guardrail=guardrail,
        )
        plan = dict(state.get("plan") or {})
        intent = dict(state.get("intent") or {})
        steps = build_trace_steps(intent=intent, plan=plan, actor_mode=actor_mode, critic=critic)
        from_asset_id = str(state.get("current_asset_id") or "")
        target = state.get("target_asset") if isinstance(state.get("target_asset"), dict) else {}
        to_asset_id = str((target or {}).get("asset_id") or from_asset_id)
        await self._record_observed_intent(
            state=state,
            intent=intent,
            plan=plan,
            asset_id=to_asset_id,
        )
        decision = await self.graph_db.record_decision(
            session_id=state["session_id"],
            asset_id=to_asset_id,
            raw_input=command,
            strategy=str(plan.get("strategy") or ""),
            steps=steps,
        )
        await self.event_bus.publish(
            "agent.trace",
            {
                "session_id": state["session_id"],
                "source_ip": str(event.get("source_ip", "unknown")),
                "raw_input": command[:200],
                "from_asset_id": from_asset_id,
                "to_asset_id": to_asset_id,
                "asset_id": to_asset_id,
                "strategy": plan.get("strategy"),
                "steps": steps,
                "decision_id": decision.get("decision_id"),
            },
        )
        return {"critic": critic, "decision": decision}

    async def _record_observed_intent(
        self,
        *,
        state: MazeState,
        intent: dict[str, Any],
        plan: dict[str, Any],
        asset_id: str,
    ) -> None:
        """每条输入只写一条意图，挂在真正应答的资产上。"""
        if not asset_id:
            return
        event = state["event"]
        payload = str(event.get("payload", ""))
        category = str(intent.get("category") or "unknown")
        terminal_intent = state.get("terminal_intent") if isinstance(state.get("terminal_intent"), dict) else None
        await self.graph_db.record_intent(
            session_id=state["session_id"],
            asset_id=asset_id,
            category=category,
            confidence=float(intent.get("confidence") or 0.0),
            raw_input=payload,
            summary=str(intent.get("summary") or ""),
            metadata=observation_metadata(
                protocol=str(event.get("protocol") or ""),
                plan=plan,
                analyst_category=category,
                terminal_intent=terminal_intent,
            ),
        )
        await self.event_bus.publish(
            "intent.detected",
            {
                "session_id": state["session_id"],
                "source_ip": str(event.get("source_ip", "unknown")),
                "category": category,
                "confidence": float(intent.get("confidence") or 0.0),
                "summary": str(intent.get("summary") or ""),
                "raw_input": payload[:200],
                "severity": self._intent_severity(category),
                "asset_id": asset_id,
                "strategy": plan.get("strategy"),
            },
        )

    def _choose_next_node(self, state: MazeState) -> str:
        if state.get("route") == "engage":
            return "engage"
        return "critique"

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

        if any(token in normalized for token in ("tar ", "zip ", "sqlite", "mysqldump", "pg_dump", "cp /srv")):
            return {
                "category": "collection",
                "confidence": 0.84,
                "summary": "data collection or staging behavior",
                "requires_subagent": True,
            }

        if any(token in normalized for token in ("uname", "whoami", "id", "ls", "pwd", "find ", "cat ", "env", "ps ", "netstat", "ss ")):
            return {
                "category": "discovery",
                "confidence": 0.8,
                "summary": "interactive shell discovery behavior",
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

    def _build_analysis_messages(self, detail: dict[str, Any]) -> list[dict[str, str]]:
        transcript = detail.get("transcript", [])[:80]
        intents = detail.get("intents", [])[:40]
        transcript_lines = []
        for item in transcript:
            timestamp = item.get("created_at", "unknown")
            hostname = item.get("hostname", "unknown")
            direction = item.get("direction", "unknown")
            payload = item.get("payload", "")
            prompt = item.get("prompt", "")
            suffix = f" | prompt={prompt}" if prompt else ""
            transcript_lines.append(
                f"{timestamp} | {hostname} | {direction} | payload={payload}{suffix}"
            )
        intent_lines = [
            f"{item.get('created_at')} | {item.get('category')} | confidence={item.get('confidence')} | {item.get('summary')}"
            for item in intents
        ]
        return [
            {
                "role": "system",
                "content": (
                    "你是一名生成式欺骗迷宫系统的高级 SOC 分析师。"
                    "请阅读会话摘要、意图轨迹和终端转录，仅返回严格 JSON，不要输出 Markdown，不要输出解释。"
                    "必须包含以下键：summary, objective, techniques, risk_level, confidence, "
                    "likely_non_human_test_agent, likely_non_human_reasons, evidence, suggested_actions。"
                    "其中 summary、objective、risk_level 必须使用中文。"
                    "techniques、likely_non_human_reasons、evidence、suggested_actions 必须是字符串数组，且数组内容全部使用中文。"
                    "likely_non_human_test_agent 必须是布尔值。confidence 必须是 0 到 1 之间的数字。"
                    "risk_level 仅允许 low、medium、high、critical 之一。"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"会话摘要：{json.dumps(detail.get('session', {}), ensure_ascii=False)}\n"
                    f"观察到的意图：\n" + "\n".join(intent_lines) + "\n\n"
                    f"终端转录：\n" + "\n".join(transcript_lines)
                ),
            },
        ]

    def _parse_analysis_json(self, raw: str) -> dict[str, Any]:
        candidate = raw.strip()
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object returned from analysis model")
        payload = json.loads(candidate[start : end + 1])
        payload["likely_non_human_test_agent"] = bool(payload.get("likely_non_human_test_agent"))
        payload["confidence"] = float(payload.get("confidence", 0.5))
        for key in ("techniques", "likely_non_human_reasons", "evidence", "suggested_actions"):
            value = payload.get(key, [])
            if not isinstance(value, list):
                payload[key] = [str(value)]
            else:
                payload[key] = [str(item) for item in value]
        return payload

    async def _run_preemptive_controls(
        self,
        *,
        session_id: str,
        source_ip: str,
        current_asset_id: str,
        event: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        intent = result.get("intent") or {}
        category = str(intent.get("category", "unknown"))
        severity = self._intent_severity(category)
        controls: dict[str, Any] = {"alerts": [], "actions": []}

        if self._severity_meets_threshold(severity):
            flag = f"{session_id}:intent:{category}"
            if flag not in self.session_control_flags:
                self.session_control_flags.add(flag)
                alert = await self._raise_alert(
                    alert_type="high_risk_intent_detected",
                    severity=severity,
                    source=source_ip,
                    details={
                        "session_id": session_id,
                        "asset_id": current_asset_id,
                        "category": category,
                        "summary": str(intent.get("summary", "")),
                        "target_ip": intent.get("target_ip"),
                        "protocol": event.get("protocol"),
                        "payload": event.get("payload"),
                        "control_plane": "preemptive_loop",
                    },
                    session_id=session_id,
                )
                controls["alerts"].append(alert)

        if category in {"lateral_movement", "credential_access", "tool_transfer"}:
            action = await self._quarantine_source_once(
                source_ip,
                f"Preemptive containment for {category} observed in session {session_id}",
            )
            if action:
                controls["actions"].append(action)

        if await self._should_flag_non_human(session_id):
            flag = f"{session_id}:intent:non_human"
            if flag not in self.session_control_flags:
                self.session_control_flags.add(flag)
                detail = await self.graph_db.session_detail(session_id)
                reasons = self._non_human_reasons(
                    [
                        str(item.get("payload", "")).strip()
                        for item in detail.get("transcript", [])
                        if item.get("direction") == "attacker_to_maze" and str(item.get("payload", "")).strip()
                    ],
                    detail.get("transcript", []),
                )
                alert = await self._raise_alert(
                    alert_type="suspected_non_human_test_agent",
                    severity="high",
                    source=source_ip,
                    details={
                        "session_id": session_id,
                        "asset_id": current_asset_id,
                        "reasons": reasons,
                        "control_plane": "preemptive_loop",
                    },
                    session_id=session_id,
                )
                controls["alerts"].append(alert)
                action = await self._quarantine_source_once(
                    source_ip,
                    f"Source classified as likely non-human test agent in session {session_id}",
                )
                if action:
                    controls["actions"].append(action)

        if controls["alerts"] or controls["actions"]:
            return controls
        return {}

    def _heuristic_analysis(self, detail: dict[str, Any]) -> dict[str, Any]:
        transcript = detail.get("transcript", [])
        intents = detail.get("intents", [])
        commands = [
            str(item.get("payload", "")).strip()
            for item in transcript
            if item.get("direction") == "attacker_to_maze" and str(item.get("payload", "")).strip()
        ]
        categories = [str(item.get("category", "unknown")) for item in intents]
        techniques = self._map_categories_to_techniques(categories)
        objective = self._infer_objective(categories, commands)
        likely_non_human = self._is_likely_non_human_agent(commands, transcript)
        reasons = self._non_human_reasons(commands, transcript)
        evidence = [f"cmd: {command}" for command in commands[:6]]
        suggested_actions = self._suggest_actions(categories, likely_non_human)
        confidence = 0.84 if likely_non_human else 0.68
        return {
            "session_id": detail.get("session", {}).get("session_id"),
            "summary": (
                f"本次会话共观察到 {len(commands)} 条攻击者命令，关联 {len(categories)} 条意图记录；"
                f"当前判断其主要目标为：{objective}。"
            ),
            "objective": objective,
            "techniques": techniques,
            "risk_level": "high" if any(cat in categories for cat in ("credential_access", "lateral_movement", "tool_transfer")) else "medium",
            "confidence": confidence,
            "likely_non_human_test_agent": likely_non_human,
            "likely_non_human_reasons": reasons,
            "evidence": evidence,
            "suggested_actions": suggested_actions,
            "transcript_items": len(transcript),
            "intent_count": len(intents),
            "analysis_source": "heuristic",
        }

    def _map_categories_to_techniques(self, categories: list[str]) -> list[str]:
        mapping = {
            "discovery": "主机发现与环境枚举",
            "credential_access": "凭证获取与密钥搜集",
            "lateral_movement": "通过 SSH 进行横向移动",
            "tool_transfer": "投递或拉取攻击工具",
            "cloud_recon": "云控制面侦察",
            "collection": "数据收集与暂存",
            "interactive_shell": "交互式命令执行",
            "generic_probe": "初始探测与试探",
        }
        seen: list[str] = []
        for category in categories:
            technique = mapping.get(category, category.replace("_", " ").title())
            if technique not in seen:
                seen.append(technique)
        return seen or ["低强度探测"]

    def _infer_objective(self, categories: list[str], commands: list[str]) -> str:
        priority = [
            ("credential_access", "搜集凭证与敏感配置，为后续访问铺路"),
            ("lateral_movement", "借助 SSH 向更深层诱饵节点横向渗透"),
            ("tool_transfer", "投递工具或拉取载荷，为后续执行做准备"),
            ("cloud_recon", "枚举云侧访问路径与远程控制面"),
            ("collection", "收集并暂存潜在敏感数据"),
            ("discovery", "摸清主机环境并验证当前是否为欺骗空间"),
        ]
        for category, objective in priority:
            if category in categories:
                return objective
        if any(command in {"root", "sudo", "su"} for command in commands):
            return "测试提权边界并验证终端仿真真实性"
        return "执行常规交互式探测"

    def _is_likely_non_human_agent(self, commands: list[str], transcript: list[dict[str, Any]]) -> bool:
        if len(commands) >= 6 and self._has_testing_sequence(commands):
            return True
        intervals = self._command_intervals(transcript)
        if intervals and len(intervals) >= 4 and sum(1 for item in intervals if item <= NON_HUMAN_INTERVAL_SECONDS) >= max(3, len(intervals) // 2):
            return True
        return False

    def _non_human_reasons(self, commands: list[str], transcript: list[dict[str, Any]]) -> list[str]:
        reasons: list[str] = []
        if self._has_testing_sequence(commands):
            reasons.append("命令序列更像自动化真实性基准测试，而不是人工攻击者的自然操作流。")
        intervals = self._command_intervals(transcript)
        if intervals and sum(1 for item in intervals if item <= NON_HUMAN_INTERVAL_SECONDS) >= max(3, len(intervals) // 2):
            reasons.append("多条命令以接近固定的低时延节奏到达，具备脚本或智能体批量探测特征。")
        if any(command in {"clear", "root", "sudo", "su"} for command in commands):
            reasons.append("会话包含典型沙箱探针命令，常见于非真人测试 Agent 的环境校验流程。")
        return reasons or ["当前未观察到足够强的非真人测试 Agent 特征。"]

    def _suggest_actions(self, categories: list[str], likely_non_human: bool) -> list[str]:
        actions = [
            "保留完整终端转录与意图轨迹，供后续威胁狩猎和规则复盘使用。",
            "将该来源标记为高置信恶意对象，并联动下游访问控制策略。",
        ]
        if "lateral_movement" in categories or "credential_access" in categories:
            actions.append("仅在合成诱饵主机继续投放更深层凭证线索，并提升观察深度。")
        if likely_non_human:
            actions.append("将该来源导入面向智能体扫描器的扩展认知欺骗路径。")
        return actions

    async def _should_flag_non_human(self, session_id: str) -> bool:
        detail = await self.graph_db.session_detail(session_id)
        transcript = detail.get("transcript", [])
        commands = [
            str(item.get("payload", "")).strip()
            for item in transcript
            if item.get("direction") == "attacker_to_maze" and str(item.get("payload", "")).strip()
        ]
        if len(commands) < 4:
            return False
        return self._is_likely_non_human_agent(commands, transcript)

    async def _raise_alert(
        self,
        *,
        alert_type: str,
        severity: str,
        source: str,
        details: dict[str, Any],
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """落库告警并实时广播，保证面板与 WebSocket 视图一致。"""
        alert = await self.graph_db.record_alert(
            alert_type=alert_type,
            severity=severity,
            source=source,
            details=details,
            session_id=session_id,
        )
        if alert_type == "suspected_non_human_test_agent":
            self.non_human_sources.add(source)
        await self.event_bus.publish("alert.raised", {**alert, "session_id": session_id})
        return alert

    async def _quarantine_source_once(self, source: str, reason: str) -> dict[str, Any] | None:
        if self.settings.preemptive_action_mode not in {"simulate", "enforce"}:
            return None
        if source in self.quarantined_sources:
            return None
        action = await self.graph_db.quarantine_source(source, reason)
        self.quarantined_sources.add(source)
        await self.event_bus.publish(
            "action.executed",
            {**action, "mode": self.settings.preemptive_action_mode},
        )
        return action

    def _release_session_controls(self, session_id: str) -> None:
        self.session_control_flags = {
            key for key in self.session_control_flags if not key.startswith(f"{session_id}:")
        }

    def _intent_severity(self, category: str) -> str:
        severity_map = {
            "credential_access": "critical",
            "lateral_movement": "critical",
            "tool_transfer": "high",
            "cloud_recon": "high",
            "collection": "high",
            "discovery": "medium",
            "interactive_shell": "medium",
            "generic_probe": "low",
            "idle": "low",
        }
        return severity_map.get(category, "medium")

    def _severity_meets_threshold(self, severity: str) -> bool:
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = str(self.settings.alert_severity_threshold).lower()
        return order.get(severity.lower(), 1) >= order.get(threshold, 2)

    def _has_testing_sequence(self, commands: list[str]) -> bool:
        probes = {"whoami", "pwd", "ls", "w", "who", "clear", "apt", "apt-get update", "echo /*", "echo /etc/*", "root", "sudo", "su"}
        return sum(1 for command in commands if command in probes) >= 4

    def _command_intervals(self, transcript: list[dict[str, Any]]) -> list[float]:
        timestamps: list[datetime] = []
        for item in transcript:
            if item.get("direction") != "attacker_to_maze":
                continue
            created_at = item.get("created_at")
            if not created_at:
                continue
            parsed = self._parse_timestamp(str(created_at))
            if parsed is not None:
                timestamps.append(parsed)
        timestamps.sort()
        return [
            (timestamps[index] - timestamps[index - 1]).total_seconds()
            for index in range(1, len(timestamps))
        ]

    def _parse_timestamp(self, value: str) -> datetime | None:
        candidate = value.replace("Z", "+00:00")
        match = re.match(r"(?P<prefix>.+\.\d{6})\d*(?P<suffix>([+-]\d\d:\d\d))$", candidate)
        if match:
            candidate = f"{match.group('prefix')}{match.group('suffix')}"
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None
