import asyncio

from src.agents.main_agent import MainAgent
from src.config import AppSettings, DashScopeClient


class _Graph:
    """按 (Session)-[:RAISED]->(Alert) 边语义记录告警的内存替身。"""

    def __init__(self) -> None:
        self.alerts: list[dict] = []
        self.raised: dict[str, list[dict]] = {}

    async def record_alert(self, *, alert_type: str, severity: str, source: str, details: dict, session_id: str | None = None) -> dict:
        alert = {
            "alert_id": f"a{len(self.alerts)}",
            "alert_type": alert_type,
            "severity": severity,
            "source": source,
            "details": details,
        }
        self.alerts.append(alert)
        if session_id:
            self.raised.setdefault(session_id, []).append(alert)
        return alert

    async def session_alerts(self, session_id: str, limit: int = 100) -> list[dict]:
        return list(self.raised.get(session_id, []))

    async def session_detail(self, session_id: str) -> dict | None:
        if session_id not in {"s-trap", "s-quiet"}:
            return None
        return {
            "session": {"session_id": session_id, "source_ip": "198.51.100.9"},
            "transcript": [],
            "intents": [],
        }

    async def quarantine_source(self, source: str, reason: str) -> dict:
        return {"action_id": "q1", "kind": "quarantine", "source": source, "reason": reason}


def _agent(graph: _Graph) -> MainAgent:
    settings = AppSettings(dashscope_api_key="")
    return MainAgent(
        settings=settings,
        graph_db=graph,  # type: ignore[arg-type]
        dashscope_client=DashScopeClient(settings),
    )


def _technique_ids(analysis: dict) -> set[str]:
    return {
        technique["id"]
        for column in analysis["attack_matrix"]["tactics"]
        for technique in column["techniques"]
    }


def test_mcp_trap_alert_surfaces_in_session_analysis():
    graph = _Graph()
    agent = _agent(graph)
    asyncio.run(
        agent.handle_mcp_trap(
            source="198.51.100.9",
            tool_name="export_customer_table",
            arguments={"table": "customers"},
            session_id="s-trap",
            agent_id="rogue-agent-01",
        )
    )
    # MCP 陷阱告警的 details 本就不带 session_id，关联只能靠 RAISED 边。
    assert "session_id" not in graph.alerts[0]["details"]

    analysis = asyncio.run(agent.analyze_session("s-trap"))
    assert analysis is not None
    assert "T1068" in _technique_ids(analysis)
    alert_component = next(item for item in analysis["score_components"] if item["key"] == "alert")
    assert alert_component["score"] > 0

    quiet = asyncio.run(agent.analyze_session("s-quiet"))
    assert quiet is not None
    assert "T1068" not in _technique_ids(quiet)


def test_analysis_timeout_returns_heuristic_without_hanging(monkeypatch):
    import src.agents.main_agent as module
    class SlowModel:
        is_configured = True
        cancelled = False
        async def chat(self, *args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True
    async def run():
        agent = _agent(_Graph())
        model = SlowModel()
        agent.dashscope_client = model
        result = await agent.analyze_session('s-quiet')
        assert model.cancelled
        assert result['analysis_source'] == 'heuristic'
    monkeypatch.setattr(module, 'ANALYSIS_TIMEOUT_SECONDS', 0.01)
    asyncio.run(run())
