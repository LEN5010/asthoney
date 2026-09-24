"""真 SSH 会话穿过主智能体，落到内存里的图快照。

不启动 Neo4j。图接口和正式 GraphDB 一样被主智能体调用，用来确认跳主机之后两台世界都还在。
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import asyncssh

from src.agents.main_agent import MainAgent
from src.config import AppSettings, DashScopeClient
from src.network.ssh_honeypot import SSH_USERNAME
from src.network.traffic_engine import TrafficEngine


class MemoryGraph:
    def __init__(self) -> None:
        self.assets: dict[str, dict[str, Any]] = {}
        self.links: list[tuple[str, str]] = []
        self.sessions: dict[str, dict[str, Any]] = {}
        self.transcripts: dict[str, list[dict[str, Any]]] = {}
        self.decisions: list[dict[str, Any]] = []
        self.worlds: dict[str, dict[str, Any]] = {}
        self.alerts: list[dict[str, Any]] = []

    async def upsert_asset(self, *, asset_id: str, asset_type: str, ip_address: str, hostname: str, persona: str, exposure_level: str = "medium", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        asset = {
            "asset_id": asset_id,
            "asset_type": asset_type,
            "ip_address": ip_address,
            "hostname": hostname,
            "persona": persona,
            "exposure_level": exposure_level,
            "metadata": dict(metadata or {}),
        }
        self.assets[asset_id] = asset
        return asset

    async def link_assets(self, *, from_asset_id: str, to_asset_id: str, vector: str, confidence: float = 0.7, metadata: dict[str, Any] | None = None) -> None:
        self.links.append((from_asset_id, to_asset_id))

    async def fetch_asset(self, asset_id: str) -> dict[str, Any] | None:
        asset = self.assets.get(asset_id)
        return dict(asset) if asset else None

    async def fetch_local_view(self, asset_id: str) -> dict[str, Any]:
        neighbors = []
        for source, target in self.links:
            if source == asset_id and target in self.assets:
                neighbors.append(dict(self.assets[target]))
        asset = self.assets.get(asset_id)
        return {"asset": dict(asset) if asset else None, "neighbors": neighbors}

    async def synthesize_next_hop(self, *, source_asset_id: str, session_id: str, intent: dict[str, Any]) -> dict[str, Any]:
        target_ip = str(intent.get("target_ip") or "10.9.9.9")
        asset_id = f"asset:{target_ip}"
        existing = self.assets.get(asset_id)
        if existing is None:
            existing = await self.upsert_asset(
                asset_id=asset_id,
                asset_type="linux_server",
                ip_address=target_ip,
                hostname=f"node-{target_ip.replace('.', '-')}",
                persona="jit",
                metadata={"jit_synthesized": True},
            )
        self.links.append((source_asset_id, asset_id))
        return dict(existing)

    async def create_or_update_session(self, *, session_id: str, source_ip: str, entry_asset_id: str, protocol: str, metadata: dict[str, Any] | None = None) -> None:
        self.sessions.setdefault(session_id, {"session_id": session_id, "source_ip": source_ip, "protocol": protocol})
        self.transcripts.setdefault(session_id, [])

    async def record_connection(self, *, session_id: str, source_ip: str, current_asset_id: str, protocol: str, payload: str) -> None:
        self.transcripts.setdefault(session_id, []).append(
            {
                "direction": "attacker_to_maze",
                "payload": payload,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "asset_id": current_asset_id,
            }
        )

    async def record_response(self, *, session_id: str, current_asset_id: str, protocol: str, payload: str, prompt: str = "") -> None:
        self.transcripts.setdefault(session_id, []).append(
            {
                "direction": "maze_to_attacker",
                "payload": payload,
                "prompt": prompt,
                "asset_id": current_asset_id,
            }
        )

    async def remember_location(self, *, session_id: str, asset_id: str) -> None:
        session = self.sessions.setdefault(session_id, {"session_id": session_id})
        asset = self.assets.get(asset_id) or {}
        session["current_asset_id"] = asset_id
        session["current_hostname"] = asset.get("hostname")

    async def save_session_world(self, session_id: str, snapshot: dict[str, Any]) -> None:
        self.worlds[session_id] = snapshot

    async def load_session_world(self, session_id: str) -> dict[str, Any] | None:
        return self.worlds.get(session_id)

    async def record_intent(self, **kwargs: Any) -> None:
        return None

    async def record_decision(self, **kwargs: Any) -> dict[str, Any]:
        decision = {"decision_id": f"d{len(self.decisions)}", **kwargs}
        self.decisions.append(decision)
        return decision

    async def record_alert(self, *, alert_type: str, severity: str, source: str, details: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        alert = {"alert_id": f"a{len(self.alerts)}", "alert_type": alert_type, "severity": severity, "source": source, "details": details}
        self.alerts.append(alert)
        return alert

    async def quarantine_source(self, source: str, reason: str) -> dict[str, Any]:
        return {"action_id": "q1", "kind": "quarantine", "source": source, "reason": reason}

    async def session_detail(self, session_id: str) -> dict[str, Any]:
        return {"session": self.sessions.get(session_id, {}), "transcript": self.transcripts.get(session_id, []), "intents": []}

    async def recent_actions(self, limit: int = 20) -> list[dict[str, Any]]:
        return []

    async def recent_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        return []


def test_real_ssh_session_keeps_both_hosts_in_the_graph(tmp_path: Path) -> None:
    asyncio.run(_exercise(tmp_path))


async def _exercise(tmp_path: Path) -> None:
    from src.network.ssh_honeypot import ensure_ssh_material

    graph = MemoryGraph()
    settings = AppSettings(
        honeypot_bind_host="127.0.0.1",
        honeypot_ports="0",
        honeypot_protocols="ssh",
        dashscope_api_key="",
        dashscope_base_url="",
    )
    agent = MainAgent(settings=settings, graph_db=graph, dashscope_client=DashScopeClient(settings))  # type: ignore[arg-type]
    await agent.bootstrap()
    material = ensure_ssh_material(tmp_path / "ssh")
    engine = TrafficEngine(settings=settings, main_agent=agent)
    engine.ssh_material = material
    acceptor = await engine._start_ssh(0)
    engine.ssh_acceptors.append(acceptor)
    port = acceptor.sockets[0].getsockname()[1]
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port,
            username=SSH_USERNAME,
            client_keys=[], agent_path=None,
            known_hosts=None,
        ) as conn:
            process = await conn.create_process(term_type="xterm")
            output = await _read_until_prompt(process)
            commands = [
                "cat /srv/backup/export-2026-04-18.tar.gz",
                "touch /tmp/from-pivot",
                "cat /etc/passwd",
                "ssh admin@10.0.5.2",
                "cat /srv/backup/db.env",
                "cat /srv/backup/archive-sync.sh",
                "ssh -i ~/.ssh/archive_ed25519 -o ConnectTimeout=3 -p 22 svc-backup@oss-sync-bridge",
                "cat /srv/oss/manifest.txt",
                "exit",
                "hostname",
            ]
            for command in commands:
                process.stdin.write(command + "\n")
                output += await _read_until_prompt(process)
            process.stdin.write_eof()
            process.close()
            await conn.run("ssh svc-backup@10.0.5.1", check=True)
            assert "from-pivot" in (await conn.run("ls /tmp", check=True)).stdout
            remote = await conn.run('ssh -i /srv/backup/id_rsa -o ConnectTimeout=3 svc-backup@db-replica-01 "cat /srv/backup/db.env"', check=True)
            assert "DB_PASS=" in remote.stdout
            assert (await conn.run("hostname", check=True)).stdout.strip() == "web-pivot-01"
            await conn.run("cd /tmp", check=True)
            assert (await conn.run("pwd", check=True)).stdout.strip() == "/tmp"
        async with asyncssh.connect("127.0.0.1", port, username=SSH_USERNAME,
                                    client_keys=[], agent_path=None, known_hosts=None) as fresh:
            assert "No such file" in (await fresh.run("cat /tmp/from-pivot", check=True)).stdout
    finally:
        acceptor.close()
        await acceptor.wait_closed()

    text = output.replace("\r\n", "\n")
    assert "finance-export.tar" in text
    assert "\r\r\n" not in output
    assert "Authenticated to 10.0.8.7" in text
    assert "Connection to 10.0.8.7 closed." in text
    assert "finance-2026-09-22.sql.gz" in text
    assert "Authenticated to 10.0.5.2" in text
    assert "using publickey" not in text
    assert "DB_PASS=Sync-2026-Apr" in text
    assert len(graph.sessions) == 2
    session_id = next(iter(graph.sessions))
    snapshot = graph.worlds[session_id]
    hostnames = {item["hostname"] for item in snapshot["hosts"]}
    assert {"web-pivot-01", "db-replica-01"} <= hostnames
    assert snapshot["hostname"] == "web-pivot-01"
    pivot = next(item for item in snapshot["hosts"] if item["hostname"] == "web-pivot-01")
    assert "/tmp/from-pivot" in pivot["created"]
    passwd = next(item for item in graph.decisions if item["raw_input"] == "cat /etc/passwd")
    assert passwd["strategy"] == "deepen"
    hop = next(item for item in graph.decisions if item["raw_input"].startswith("ssh "))
    assert hop["strategy"] == "pivot"



async def _read_until_prompt(process: Any) -> str:
    chunks: list[str] = []
    while True:
        piece = await asyncio.wait_for(process.stdout.read(512), timeout=8)
        if not piece:
            break
        chunks.append(piece)
        combined = "".join(chunks).replace("\r\n", "\n")
        if combined.rstrip().endswith("$"):
            break
    return "".join(chunks)
