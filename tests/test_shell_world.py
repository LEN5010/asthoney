import asyncio

from src.agents.main_agent import MainAgent
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


def test_listed_file_can_be_named_but_not_entered():
    agent = _agent()
    listed = asyncio.run(agent.handle_input("ls /etc/passwd"))
    assert listed["response"] == "passwd"
    rejected = asyncio.run(agent.handle_input("cd /etc/passwd"))
    assert "Not a directory" in rejected["response"]
    assert agent.world.cwd != "/etc/passwd"


def test_find_on_empty_directory_is_not_missing():
    agent = _agent()
    created = asyncio.run(agent.handle_input("mkdir /tmp/emptybin"))
    assert created["response"] == ""
    found = asyncio.run(agent.handle_input("find /tmp/emptybin"))
    assert "No such file" not in found["response"]


def test_closed_session_world_reads_the_stored_snapshot():
    agent = object.__new__(MainAgent)
    agent.active_sub_agents = {}

    class _Store:
        async def load_session_world(self, session_id: str) -> dict:
            assert session_id == "s1"
            return {"cwd": "/srv", "hostname": "web-pivot-01", "files": []}

    agent.graph_db = _Store()
    result = asyncio.run(agent.session_world("s1"))
    assert result["source"] == "stored"
    assert result["available"] is True
    assert result["cwd"] == "/srv"


def test_uname_uses_the_host_in_the_world():
    result = asyncio.run(_agent(hostname="web-pivot-01").handle_input("uname -a"))
    assert result["actor_mode"] == "interpreter"
    assert "web-pivot-01" in result["response"]
    assert "Linux" in result["response"]


def test_database_secret_stays_off_the_pivot():
    pivot = asyncio.run(_agent().handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in pivot["response"]
    assert "DB_PASS" not in pivot["response"]
    replica = asyncio.run(_agent("database_server", "db-replica-01").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS=Sync-2026-Apr" in replica["response"]
    oss = asyncio.run(_agent("oss_gateway", "oss-sync-bridge").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS" not in oss["response"]
