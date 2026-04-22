from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.agents.main_agent import MainAgent
from src.config import DashScopeClient, configure_logging, get_settings
from src.database.graph_db import GraphDB
from src.network.traffic_engine import TrafficEngine
from src.trap.mcp_trap import build_mcp_router


class SimulateRequest(BaseModel):
    payload: str = Field(..., description="Inbound attacker payload")
    protocol: str = Field(default="ssh", description="Protocol label such as ssh or tcp")
    source_ip: str = Field(default="198.51.100.9", description="Attacker source IP")
    destination_port: int = Field(default=2222, description="Synthetic destination port")
    session_id: str | None = Field(default=None, description="Optional synthetic session identifier")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = logging.getLogger("main")

    graph_db = GraphDB(settings)
    await graph_db.connect()
    await graph_db.init_schema()

    dashscope_client = DashScopeClient(settings)
    main_agent = MainAgent(
        settings=settings,
        graph_db=graph_db,
        dashscope_client=dashscope_client,
    )
    await main_agent.bootstrap()

    traffic_engine = TrafficEngine(settings=settings, main_agent=main_agent)
    await traffic_engine.start()

    app.state.settings = settings
    app.state.graph_db = graph_db
    app.state.main_agent = main_agent
    app.state.traffic_engine = traffic_engine

    logger.info("%s is ready on %s:%s", settings.app_name, settings.api_host, settings.api_port)
    try:
        yield
    finally:
        await traffic_engine.stop()
        await main_agent.close()
        await graph_db.close()
        logger.info("Shutdown complete")


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
        "honeypot_assets": honeypot_assets,
    }


@app.get("/alerts")
async def alerts(request: Request) -> dict[str, Any]:
    recent_alerts = await request.app.state.graph_db.recent_alerts(limit=20)
    return {"alerts": recent_alerts}


@app.get("/payloads")
async def payloads(request: Request) -> dict[str, Any]:
    recent_payloads = await request.app.state.graph_db.recent_payloads(limit=20)
    return {"payloads": recent_payloads}


@app.get("/sessions")
async def sessions(request: Request) -> dict[str, Any]:
    ssh_sessions = await request.app.state.graph_db.recent_sessions(protocol="ssh", limit=50)
    return {"sessions": ssh_sessions}


@app.get("/sessions/{session_id}")
async def session_detail(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.graph_db.session_detail(session_id)


@app.get("/sessions/{session_id}/analysis")
async def session_analysis(request: Request, session_id: str) -> dict[str, Any]:
    return await request.app.state.main_agent.analyze_session(session_id)


@app.post("/simulate")
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
