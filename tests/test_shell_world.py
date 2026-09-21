import asyncio

from src.agents.main_agent import MainAgent
from src.agents.shell_world import present_world
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


def test_listed_archive_can_be_read():
    result = asyncio.run(_agent().handle_input("cat /srv/backup/export-2026-04-18.tar.gz"))
    assert result["actor_mode"] == "interpreter"
    assert "simulated archive" in result["response"]


def test_pipe_grep_head_and_redirect_stay_in_the_world():
    agent = _agent()
    piped = asyncio.run(agent.handle_input("echo DB_HOST=10.0.5.2 | grep DB_HOST"))
    assert piped["response"] == "DB_HOST=10.0.5.2"
    headed = asyncio.run(agent.handle_input("head -n 1 /etc/passwd"))
    assert headed["response"].startswith("root:")
    chained = asyncio.run(agent.handle_input("cd /srv && ls"))
    assert "backup" in chained["response"]
    assert agent.world.cwd == "/srv"
    written = asyncio.run(agent.handle_input("echo hello > /tmp/out.txt"))
    assert written["response"] == ""
    read_back = asyncio.run(agent.handle_input("cat /tmp/out.txt"))
    assert read_back["response"] == "hello"
    denied = asyncio.run(agent.handle_input("echo no > /srv/backup/db.env"))
    assert "Permission denied" in denied["response"]
    secret = asyncio.run(agent.handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in secret["response"]
    wrapped = asyncio.run(agent.handle_input("bash -c 'grep DB_HOST /srv/backup/db.env'"))
    assert "DB_HOST=10.0.5.2" in wrapped["response"]
    long_listing = asyncio.run(agent.handle_input("ls -l /etc/passwd"))
    assert "passwd" in long_listing["response"]
    assert "-rw-r--r--" in long_listing["response"]
    found = asyncio.run(agent.handle_input("find /srv -name db.env"))
    assert found["response"] == "/srv/backup/db.env"


def test_public_world_redacts_the_replica_password():
    agent = _agent("database_server", "db-replica-01")
    asyncio.run(agent.handle_input("cat /srv/backup/db.env"))
    hidden = present_world(agent.world.snapshot(), reveal=False)
    preview = next(item["preview"] for item in hidden["files"] if item["path"] == "/srv/backup/db.env")
    assert "Sync-2026-Apr" not in preview
    assert "[redacted]" in preview
    revealed = present_world(agent.world.snapshot(), reveal=True)
    full = next(item["preview"] for item in revealed["files"] if item["path"] == "/srv/backup/db.env")
    assert "Sync-2026-Apr" in full
    assert revealed["redacted"] is False


def test_database_secret_stays_off_the_pivot():
    pivot = asyncio.run(_agent().handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in pivot["response"]
    assert "DB_PASS" not in pivot["response"]
    replica = asyncio.run(_agent("database_server", "db-replica-01").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS=Sync-2026-Apr" in replica["response"]
    oss = asyncio.run(_agent("oss_gateway", "oss-sync-bridge").handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS" not in oss["response"]
