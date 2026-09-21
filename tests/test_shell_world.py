import asyncio

from src.agents.sub_agent import SubAgent
from src.config import AppSettings, DashScopeClient


def _agent(asset_type: str = "linux_server", hostname: str = "web-pivot-01") -> SubAgent:
    settings = AppSettings(dashscope_api_key="")
    return SubAgent(
        settings=settings,
        dashscope_client=DashScopeClient(settings),
        session_id="world-session",
        source_ip="198.51.100.9",
        asset_snapshot={
            "asset_id": "asset:test",
            "hostname": hostname,
            "ip_address": "10.0.5.1",
            "asset_type": asset_type,
            "persona": asset_type,
            "metadata": {},
        },
        local_view={"neighbors": []},
    )


def test_cd_then_ls_stays_in_the_session_world():
    agent = _agent()
    entered = asyncio.run(agent.handle_input("cd /srv"))
    assert entered["response"] == ""
    listing = asyncio.run(agent.handle_input("ls"))
    assert "backup" in listing["response"]
    assert agent.world.cwd == "/srv"


def test_missing_cd_does_not_move():
    agent = _agent()
    before = agent.world.cwd
    missing = asyncio.run(agent.handle_input("cd /no/such"))
    assert "No such file" in missing["response"]
    assert agent.world.cwd == before


def test_touch_is_visible_and_rm_does_not_delete_it():
    agent = _agent()
    created = asyncio.run(agent.handle_input("touch /tmp/note"))
    assert created["response"] == ""
    listing = asyncio.run(agent.handle_input("ls /tmp"))
    assert "note" in listing["response"]
    denied = asyncio.run(agent.handle_input("rm /tmp/note"))
    assert "Permission denied" in denied["response"]
    still = asyncio.run(agent.handle_input("ls /tmp"))
    assert "note" in still["response"]
    assert "/tmp/note" in agent.world.snapshot()["created"]


def test_database_secret_stays_off_the_pivot():
    pivot = asyncio.run(_agent().handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in pivot["response"]
    assert "DB_PASS" not in pivot["response"]
    replica = asyncio.run(_agent("database_server", "db-replica-01").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS=Sync-2026-Apr" in replica["response"]
    oss = asyncio.run(_agent("oss_gateway", "oss-sync-bridge").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS" not in oss["response"]
