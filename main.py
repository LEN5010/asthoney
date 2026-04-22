from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
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
    return await request.app.state.main_agent.status()


@app.get("/alerts")
async def alerts(request: Request) -> dict[str, Any]:
    recent_alerts = await request.app.state.graph_db.recent_alerts(limit=20)
    return {"alerts": recent_alerts}


@app.post("/simulate")
async def simulate(request: Request, body: SimulateRequest) -> dict[str, Any]:
    result = await request.app.state.main_agent.handle_payload(
        {
            "session_id": "simulate-session",
            "source_ip": body.source_ip,
            "destination_port": body.destination_port,
            "protocol": body.protocol,
            "payload": body.payload,
            "entry_asset_id": f"edge:{body.protocol}:{body.destination_port}",
        }
    )
    return result

