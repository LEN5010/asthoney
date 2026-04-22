from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from src.agents.sub_agent import SubAgent
from src.config import AppSettings, DashScopeClient, DashScopeInvocationError
from src.database.graph_db import GraphDB


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
        response_asset_id = current_asset_id
        if isinstance(result.get("target_asset"), dict):
            response_asset_id = str(result["target_asset"].get("asset_id", current_asset_id))
        response_text = str(result.get("response", ""))
        response_prompt = str(result.get("prompt", ""))
        if response_text or response_prompt:
            await self.graph_db.record_response(
                session_id=session_id,
                current_asset_id=response_asset_id,
                protocol=protocol,
                payload=response_text,
                prompt=response_prompt,
            )
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

    async def analyze_session(self, session_id: str) -> dict[str, Any]:
        detail = await self.graph_db.session_detail(session_id)
        transcript = detail.get("transcript", [])
        intents = detail.get("intents", [])
        heuristic = self._heuristic_analysis(detail)

        if not self.dashscope_client.is_configured:
            return heuristic

        messages = self._build_analysis_messages(detail)
        try:
            raw = await self.dashscope_client.chat(messages, temperature=0.1, top_p=0.6)
            parsed = self._parse_analysis_json(raw)
            return {
                **heuristic,
                **parsed,
                "session_id": session_id,
                "transcript_items": len(transcript),
                "intent_count": len(intents),
                "analysis_source": "dashscope",
            }
        except (DashScopeInvocationError, ValueError, KeyError, json.JSONDecodeError):
            self.logger.warning("Falling back to heuristic analysis for session %s", session_id)
            return heuristic

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
            "prompt": str(result.get("prompt", sub_agent.prompt)),
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
                    "You are a senior SOC analyst for an AI deception maze. "
                    "Read the session transcript and return strict JSON only. "
                    "Required keys: summary, objective, techniques, risk_level, confidence, "
                    "likely_non_human_test_agent, likely_non_human_reasons, evidence, suggested_actions. "
                    "techniques, likely_non_human_reasons, evidence, suggested_actions must be arrays of strings. "
                    "likely_non_human_test_agent must be boolean. confidence must be a number between 0 and 1."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Session summary: {json.dumps(detail.get('session', {}), ensure_ascii=True)}\n"
                    f"Observed intents:\n" + "\n".join(intent_lines) + "\n\n"
                    f"Transcript:\n" + "\n".join(transcript_lines)
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
                f"Observed {len(commands)} attacker commands across {len(categories)} classified intents; "
                f"dominant objective appears to be {objective}."
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
            "discovery": "Host Discovery / Environment Enumeration",
            "credential_access": "Credential Access / Secrets Harvesting",
            "lateral_movement": "Lateral Movement via SSH",
            "tool_transfer": "Ingress Tool Transfer",
            "cloud_recon": "Cloud Control-Plane Reconnaissance",
            "collection": "Data Collection / Staging",
            "interactive_shell": "Interactive Command Execution",
            "generic_probe": "Initial Foothold Probing",
        }
        seen: list[str] = []
        for category in categories:
            technique = mapping.get(category, category.replace("_", " ").title())
            if technique not in seen:
                seen.append(technique)
        return seen or ["Low-fidelity probing"]

    def _infer_objective(self, categories: list[str], commands: list[str]) -> str:
        priority = [
            ("credential_access", "harvest credentials and secrets for follow-on access"),
            ("lateral_movement", "pivot deeper into internal nodes through SSH lateral movement"),
            ("tool_transfer", "stage tooling or fetch payloads for execution"),
            ("cloud_recon", "enumerate cloud access paths and remote control surfaces"),
            ("collection", "collect and stage data for later exfiltration"),
            ("discovery", "map the host and validate the deception environment"),
        ]
        for category, objective in priority:
            if category in categories:
                return objective
        if any(command in {"root", "sudo", "su"} for command in commands):
            return "test privilege escalation boundaries and shell realism"
        return "perform generic interactive probing"

    def _is_likely_non_human_agent(self, commands: list[str], transcript: list[dict[str, Any]]) -> bool:
        if len(commands) >= 6 and self._has_testing_sequence(commands):
            return True
        intervals = self._command_intervals(transcript)
        if intervals and len(intervals) >= 4 and sum(1 for item in intervals if item <= 1.5) >= max(3, len(intervals) // 2):
            return True
        return False

    def _non_human_reasons(self, commands: list[str], transcript: list[dict[str, Any]]) -> list[str]:
        reasons: list[str] = []
        if self._has_testing_sequence(commands):
            reasons.append("Command sequence resembles an automated realism benchmark rather than an operator workflow.")
        intervals = self._command_intervals(transcript)
        if intervals and sum(1 for item in intervals if item <= 1.5) >= max(3, len(intervals) // 2):
            reasons.append("Multiple commands arrived at near-uniform sub-second or low-latency cadence.")
        if any(command in {"clear", "root", "sudo", "su"} for command in commands):
            reasons.append("Session includes sandbox-evaluation commands commonly used by non-human test agents.")
        return reasons or ["No strong indicators of a non-human testing agent were observed."]

    def _suggest_actions(self, categories: list[str], likely_non_human: bool) -> list[str]:
        actions = [
            "Preserve the full transcript and correlated intents for threat hunting.",
            "Tag the source identity as high-confidence malicious for downstream controls.",
        ]
        if "lateral_movement" in categories or "credential_access" in categories:
            actions.append("Seed deeper lure credentials only on synthetic hosts and increase observation depth.")
        if likely_non_human:
            actions.append("Route the source into extended cognitive-deception flows tailored for agentic scanners.")
        return actions

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
