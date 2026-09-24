from fastapi.testclient import TestClient

from main import app
from src.agents.main_agent import MainAgent
from src.config import AppSettings, DashScopeClient


class _FakeGraph:
    def __init__(self) -> None:
        self.known_detail = {
            "session": {"session_id": "s-known", "source_ip": "198.51.100.9"},
            "transcript": [],
            "intents": [],
        }

    async def session_detail(self, session_id: str) -> dict | None:
        if session_id == "s-known":
            return self.known_detail
        return None

    async def session_decisions(self, session_id: str) -> list[dict]:
        return [{"decision_id": "d1", "session_id": session_id}]

    async def load_session_world(self, session_id: str) -> dict | None:
        return None

    async def session_alerts(self, session_id: str, limit: int = 100) -> list[dict]:
        return []

    async def purge_history(self) -> dict:
        return {"sessions": 0}


def _client() -> TestClient:
    settings = AppSettings(dashscope_api_key="")
    graph = _FakeGraph()
    app.state.settings = settings
    app.state.graph_db = graph
    app.state.main_agent = MainAgent(
        settings=settings,
        graph_db=graph,  # type: ignore[arg-type]
        dashscope_client=DashScopeClient(settings),
    )
    return TestClient(app)


def test_unknown_session_returns_404_on_detail_and_children():
    client = _client()
    assert client.get("/sessions/s-missing").status_code == 404
    assert client.get("/sessions/s-missing/decisions").status_code == 404
    assert client.get("/sessions/s-missing/world").status_code == 404
    assert client.get("/sessions/s-missing/analysis").status_code == 404
    response = client.post(
        "/sessions/s-missing/analysis/controls",
    )
    assert response.status_code == 404


def test_known_session_routes_still_work():
    client = _client()
    detail = client.get("/sessions/s-known")
    assert detail.status_code == 200
    assert detail.json()["session"]["session_id"] == "s-known"
    decisions = client.get("/sessions/s-known/decisions")
    assert decisions.status_code == 200
    assert decisions.json()["decisions"][0]["decision_id"] == "d1"
    world = client.get("/sessions/s-known/world")
    assert world.status_code == 200
    assert world.json()["available"] is False
    analysis = client.get("/sessions/s-known/analysis")
    assert analysis.status_code == 200
    assert analysis.json()["session_id"] == "s-known"
    controls = client.post(
        "/sessions/s-known/analysis/controls",
    )
    assert controls.status_code == 200


def test_local_actions_and_world_need_no_login():
    client = _client()
    assert client.post("/history/purge", json={"confirm": False}).status_code == 200
    world = client.get("/sessions/s-known/world")
    assert world.status_code == 200
    assert "redacted" not in world.json()


def test_reset_clears_state_between_stopping_and_starting_listeners():
    from unittest.mock import AsyncMock
    from src.realtime.event_bus import EventBus
    client = _client()
    order = []

    def action(name):
        async def run():
            order.append(name)
            return {"sessions": 2} if name == "purge" else None
        return run

    app.state.graph_db.purge_history = action("purge")
    app.state.main_agent.reset_runtime_state = action("runtime")
    app.state.main_agent.bootstrap = action("seed")
    app.state.traffic_engine = AsyncMock()
    app.state.traffic_engine.stop.side_effect = action("stop")
    app.state.traffic_engine.start.side_effect = action("start")
    app.state.background_tasks = set()
    app.state.event_bus = EventBus()
    app.state.theater_running = True
    app.state.resetting = False
    assert not client.post("/history/purge", json={"confirm": False}).json()["ok"]
    assert order == []
    response = client.post("/history/purge", json={"confirm": True})
    assert response.json() == {"ok": True, "purged": {"sessions": 2}}
    assert order == ["stop", "purge", "runtime", "seed", "start"]
    assert not app.state.resetting and not app.state.theater_running
    assert [e["type"] for e in app.state.event_bus.replay_buffer()] == ["history.purged"]
