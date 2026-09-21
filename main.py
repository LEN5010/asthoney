from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

import asyncio

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.agents.main_agent import NON_HUMAN_INTERVAL_SECONDS, MainAgent
from src.analytics.attack_matrix import build_matrix
from src.analytics.threat_profile import build_attacker_profiles
from src.config import DashScopeClient, configure_logging, get_settings
from src.database.graph_db import GraphDB
from src.network.traffic_engine import TrafficEngine
from src.realtime.event_bus import EventBus
from src.trap.mcp_trap import build_mcp_router


class SimulateRequest(BaseModel):
    payload: str = Field(..., description="Inbound attacker payload")
    protocol: str = Field(default="ssh", description="Protocol label such as ssh or tcp")
    source_ip: str = Field(default="198.51.100.9", description="Attacker source IP")
    destination_port: int = Field(default=2222, description="Synthetic destination port")
    session_id: str | None = Field(default=None, description="Optional synthetic session identifier")


class PurgeHistoryRequest(BaseModel):
    confirm: bool = Field(default=False, description="Safety confirmation flag")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = logging.getLogger("main")

    graph_db = GraphDB(settings)
    await graph_db.connect()
    await graph_db.init_schema()

    dashscope_client = DashScopeClient(settings)
    event_bus = EventBus()
    main_agent = MainAgent(
        settings=settings,
        graph_db=graph_db,
        dashscope_client=dashscope_client,
        event_bus=event_bus,
    )
    await main_agent.bootstrap()

    traffic_engine = TrafficEngine(settings=settings, main_agent=main_agent)
    await traffic_engine.start()

    app.state.settings = settings
    app.state.graph_db = graph_db
    app.state.main_agent = main_agent
    app.state.traffic_engine = traffic_engine
    app.state.event_bus = event_bus
    app.state.theater_running = False

    logger.info("%s is ready on %s:%s", settings.app_name, settings.api_host, settings.api_port)
    try:
        yield
    finally:
        await traffic_engine.stop()
        await main_agent.close()
        await graph_db.close()
        logger.info("Shutdown complete")


async def require_admin_token(
    request: Request,
    x_admin_token: str | None = Header(default=None),
) -> None:
    """SR-02: 未认证请求不得调用 /simulate、/history/purge 及会话研判控制接口。"""
    expected = request.app.state.settings.admin_api_token
    if not expected:
        raise HTTPException(status_code=503, detail="ADMIN_API_TOKEN is not configured")
    if x_admin_token != expected:
        raise HTTPException(status_code=401, detail="valid X-Admin-Token header is required")


app = FastAPI(
    title="Generative Infinite Deception Maze",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(build_mcp_router())
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=FileResponse)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/sessions/view", response_class=FileResponse)
async def sessions_view() -> FileResponse:
    return FileResponse(STATIC_DIR / "sessions.html")


@app.get("/session/view", response_class=FileResponse)
async def session_view() -> FileResponse:
    return FileResponse(STATIC_DIR / "session.html")


@app.get("/attack/view", response_class=FileResponse)
async def attack_view() -> FileResponse:
    return FileResponse(STATIC_DIR / "attack.html")


@app.get("/profiles/view", response_class=FileResponse)
async def profiles_view() -> FileResponse:
    return FileResponse(STATIC_DIR / "profiles.html")


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    """实时事件流。连接后先补发回放缓冲，再持续推送增量事件。"""
    await websocket.accept()
    bus: EventBus = websocket.app.state.event_bus
    queue = await bus.subscribe()
    try:
        await websocket.send_json(
            {
                "type": "stream.ready",
                "data": {
                    "replay": bus.replay_buffer(limit=40),
                    "subscribers": bus.subscriber_count,
                },
            }
        )
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=25.0)
            except asyncio.TimeoutError:
                # 心跳：让中间代理不至于判定连接空闲而断开。
                await websocket.send_json({"type": "stream.heartbeat", "data": {}})
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.getLogger("main").debug("WebSocket stream closed", exc_info=True)
    finally:
        await bus.unsubscribe(queue)


@app.get("/timeline")
async def timeline(request: Request, limit: int = 120) -> dict[str, Any]:
    items = await request.app.state.graph_db.activity_timeline(limit=min(limit, 300))
    return {"timeline": items}


@app.get("/attack/matrix")
async def attack_matrix(request: Request) -> dict[str, Any]:
    graph_db = request.app.state.graph_db
    intents = await graph_db.all_intents(limit=500)
    alerts = await graph_db.recent_alerts(limit=100)
    return build_matrix(intents, alerts)


@app.get("/profiles")
async def profiles(request: Request) -> dict[str, Any]:
    graph_db = request.app.state.graph_db
    main_agent = request.app.state.main_agent
    sessions_list = await graph_db.recent_sessions(limit=100)
    intents = await graph_db.all_intents(limit=500)
    alerts = await graph_db.recent_alerts(limit=100)
    actions = await graph_db.recent_actions(limit=100)

    intents_by_session: dict[str, list[dict[str, Any]]] = {}
    for intent in intents:
        intents_by_session.setdefault(str(intent.get("session_id", "")), []).append(intent)

    items = build_attacker_profiles(
        sessions=sessions_list,
        intents_by_session=intents_by_session,
        alerts=alerts,
        actions=actions,
        non_human_sources=main_agent.non_human_sources,
    )
    return {
        "profiles": items,
        "total": len(items),
        "quarantined": sum(1 for item in items if item["quarantined"]),
    }


@app.get("/healthz")
async def healthz(request: Request) -> dict[str, Any]:
    graph_ok = await request.app.state.graph_db.healthcheck()
    return {
        "status": "ok" if graph_ok else "degraded",
        "graph_db": graph_ok,
        "listeners": request.app.state.traffic_engine.listener_summary(),
    }


@app.get("/status")
async def status(request: Request) -> dict[str, Any]:
    main_agent_status = await request.app.state.main_agent.status()
    honeypot_assets = await request.app.state.graph_db.asset_count()
    return {
        **main_agent_status,
        **request.app.state.traffic_engine.metrics_snapshot(),
        **request.app.state.traffic_engine.ssh_public_status(),
        "honeypot_assets": honeypot_assets,
        "stream_subscribers": request.app.state.event_bus.subscriber_count,
    }


@app.get("/alerts")
async def alerts(request: Request) -> dict[str, Any]:
    recent_alerts = await request.app.state.graph_db.recent_alerts(limit=20)
    return {"alerts": recent_alerts}


@app.get("/actions")
async def actions(request: Request) -> dict[str, Any]:
    recent_actions = await request.app.state.graph_db.recent_actions(limit=20)
    return {"actions": recent_actions}


@app.get("/payloads")
async def payloads(request: Request) -> dict[str, Any]:
    recent_payloads = await request.app.state.graph_db.recent_payloads(limit=20)
    return {"payloads": recent_payloads}


@app.get("/graph/overview")
async def graph_overview(request: Request) -> dict[str, Any]:
    return await request.app.state.graph_db.graph_overview()


@app.get("/sessions")
async def sessions(request: Request) -> dict[str, Any]:
    ssh_sessions = await request.app.state.graph_db.recent_sessions(protocol="ssh", limit=50)
    return {"sessions": ssh_sessions}


@app.get("/sessions/{session_id}")
async def session_detail(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.graph_db.session_detail(session_id)


@app.get("/sessions/{session_id}/transcript")
async def session_transcript(request: Request, session_id: str) -> dict[str, Any]:
    return {"transcript": await request.app.state.graph_db.session_transcript(session_id)}


@app.get("/sessions/{session_id}/intents")
async def session_intents(request: Request, session_id: str) -> dict[str, Any]:
    return {"intents": await request.app.state.graph_db.session_intents(session_id)}


@app.get("/sessions/{session_id}/world")
async def session_world(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.main_agent.session_world(session_id)


@app.get("/sessions/{session_id}/decisions")
async def session_decisions(request: Request, session_id: str) -> dict[str, Any]:
    return {"decisions": await request.app.state.graph_db.session_decisions(session_id)}


@app.get("/sessions/{session_id}/analysis")
async def session_analysis(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.main_agent.analyze_session(session_id)


@app.post("/sessions/{session_id}/analysis/controls", dependencies=[Depends(require_admin_token)])
async def session_analysis_controls(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.main_agent.trigger_session_analysis_controls(session_id)


@app.post("/history/purge", dependencies=[Depends(require_admin_token)])
async def purge_history(request: Request, body: PurgeHistoryRequest) -> dict[str, Any]:
    if not body.confirm:
        return {"ok": False, "message": "confirm=true is required"}
    summary = await request.app.state.graph_db.purge_history()
    await request.app.state.main_agent.reset_runtime_state()
    bus: EventBus = request.app.state.event_bus
    bus.clear_replay()
    await bus.publish("history.purged", {"purged": summary})
    return {"ok": True, "purged": summary}


THEATER_STEPS: list[tuple[str, str]] = [
    ("whoami", "主机枚举"),
    ("ls /srv", "目录枚举"),
    ("cat /etc/passwd", "账户枚举"),
    ("ssh admin@10.0.5.2", "横向移动"),
    ("cat /srv/backup/db.env", "读取凭据文件"),
]
THEATER_SOURCE_IP = "198.51.100.23"
# 比非人间隔阈值再慢 0.3 秒，避免播放剧本把自己判成自动化代理。
THEATER_STEP_SECONDS = NON_HUMAN_INTERVAL_SECONDS + 0.3


@app.post("/demo/theater", dependencies=[Depends(require_admin_token)])
async def demo_theater(request: Request) -> dict[str, Any]:
    """按固定剧本走真实诱捕管道，供答辩时一键播放。"""
    if request.app.state.theater_running:
        raise HTTPException(status_code=409, detail="theater already running")

    run_id = uuid4().hex[:8]
    session_id = f"theater-{run_id}"
    request.app.state.theater_running = True
    main_agent = request.app.state.main_agent
    bus: EventBus = request.app.state.event_bus
    graph_db = request.app.state.graph_db

    async def _run() -> None:
        try:
            for payload, stage in THEATER_STEPS:
                await bus.publish(
                    "demo.stage",
                    {
                        "run_id": run_id,
                        "session_id": session_id,
                        "stage": stage,
                        "payload": payload,
                        "done": False,
                    },
                )
                await main_agent.handle_payload(
                    {
                        "session_id": session_id,
                        "source_ip": THEATER_SOURCE_IP,
                        "destination_port": 2222,
                        "protocol": "ssh",
                        "payload": payload,
                        "entry_asset_id": "edge:ssh:2222",
                    }
                )
                await asyncio.sleep(THEATER_STEP_SECONDS)

            await bus.publish(
                "demo.stage",
                {
                    "run_id": run_id,
                    "session_id": session_id,
                    "stage": "MCP 工具拦截",
                    "payload": "bypass_security_guardrails",
                    "done": False,
                },
            )
            await main_agent.handle_mcp_trap(
                source=THEATER_SOURCE_IP,
                tool_name="bypass_security_guardrails",
                arguments={"target": "policy-engine", "mode": "off"},
                session_id=session_id,
                agent_id="theater-demo",
            )
            trap_steps = [
                {
                    "role": "analyst",
                    "title": "意图分析",
                    "detail": "自主代理调用了高风险工具 bypass_security_guardrails",
                    "evidence": "工具名在陷阱清单中",
                    "confidence": 0.99,
                    "category": "agent_oriented_mcp_trap",
                },
                {
                    "role": "planner",
                    "title": "欺骗规划",
                    "detail": "陷阱工具不提供成功结果，调用本身就是告警。",
                    "strategy": "stall",
                    "planted_clue": "",
                    "technique": "T1068",
                },
                {
                    "role": "actor",
                    "title": "终端仿真",
                    "detail": "MCP 工具面直接拒绝",
                    "mode": "static",
                },
                {
                    "role": "critic",
                    "title": "输出护栏",
                    "detail": "调用即视为违规，返回拒绝",
                    "verdict": "blocked",
                },
            ]
            await graph_db.record_decision(
                session_id=session_id,
                asset_id="mcp:trap",
                raw_input="tools/call bypass_security_guardrails",
                strategy="stall",
                steps=trap_steps,
            )
            await bus.publish(
                "agent.trace",
                {
                    "session_id": session_id,
                    "source_ip": THEATER_SOURCE_IP,
                    "raw_input": "tools/call bypass_security_guardrails",
                    "from_asset_id": "",
                    "to_asset_id": "",
                    "asset_id": "",
                    "strategy": "stall",
                    "steps": trap_steps,
                },
            )
            await bus.publish(
                "demo.stage",
                {
                    "run_id": run_id,
                    "session_id": session_id,
                    "stage": "序列结束",
                    "payload": "",
                    "done": True,
                },
            )
        except Exception:
            logging.getLogger("main").exception("Theater run %s failed", run_id)
            await bus.publish(
                "demo.stage",
                {
                    "run_id": run_id,
                    "session_id": session_id,
                    "stage": "序列中断",
                    "payload": "",
                    "done": True,
                },
            )
        finally:
            request.app.state.theater_running = False

    asyncio.create_task(_run())
    return {"ok": True, "run_id": run_id, "session_id": session_id, "source_ip": THEATER_SOURCE_IP}


@app.post("/simulate", dependencies=[Depends(require_admin_token)])
async def simulate(request: Request, body: SimulateRequest) -> dict[str, Any]:
    session_id = body.session_id or f"simulate-{uuid4()}"
    result = await request.app.state.main_agent.handle_payload(
        {
            "session_id": session_id,
            "source_ip": body.source_ip,
            "destination_port": body.destination_port,
            "protocol": body.protocol,
            "payload": body.payload,
            "entry_asset_id": f"edge:{body.protocol}:{body.destination_port}",
        }
    )
    return result
