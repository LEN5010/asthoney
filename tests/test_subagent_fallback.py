import asyncio

from src.agents.sub_agent import SubAgent
from src.config import AppSettings, DashScopeClient


def _agent() -> SubAgent:
    settings = AppSettings(dashscope_api_key="")
    return SubAgent(
        settings=settings,
        dashscope_client=DashScopeClient(settings),
        session_id="test-session",
        source_ip="198.51.100.9",
        asset_snapshot={
            "asset_id": "asset:10.0.5.1",
            "hostname": "web-pivot-01",
            "ip_address": "10.0.5.1",
            "persona": "damaged_linux_terminal",
            "metadata": {"lure": "stolen key references db-replica-01"},
        },
        local_view={"neighbors": []},
    )


def test_exit_closes_session():
    result = asyncio.run(_agent().handle_input("exit"))
    assert result["close"] is True
    assert "closed" in result["response"].lower()


def test_unconfigured_model_uses_fallback_whoami():
    result = asyncio.run(_agent().handle_input("whoami"))
    assert result["close"] is False
    assert result["intent"]["category"] == "discovery"
    assert "svc-backup" in result["response"] or result["response"]


def test_dangerous_rm_does_not_claim_success_wipe():
    result = asyncio.run(_agent().handle_input("rm -rf /"))
    text = result["response"].lower()
    assert "permission denied" in text or "dangerous" in text or "cannot" in text
    assert result["actor_mode"] == "interpreter"


def test_ls_places_clue_filename_without_comment():
    plan = {
        "strategy": "deepen",
        "planted_clue": "/srv/backup/handoff.txt 指向 10.0.5.2",
    }
    result = asyncio.run(_agent().handle_input("ls /srv/backup", plan=plan))
    assert "handoff.txt" in result["response"]
    assert "db.env" in result["response"]
    assert "#" not in result["response"]
    assert "指向" not in result["response"]
    assert result["guardrail"] == "world"


def _typed_agent(asset_type: str, hostname: str) -> SubAgent:
    settings = AppSettings(dashscope_api_key="")
    return SubAgent(
        settings=settings,
        dashscope_client=DashScopeClient(settings),
        session_id="test-session",
        source_ip="198.51.100.9",
        asset_snapshot={
            "asset_id": f"asset:{hostname}",
            "hostname": hostname,
            "ip_address": "10.0.5.2",
            "asset_type": asset_type,
            "persona": asset_type,
            "metadata": {},
        },
        local_view={"neighbors": []},
    )


def test_database_host_is_not_the_web_pivot_tree():
    agent = _typed_agent("database_server", "db-replica-01")
    listing = asyncio.run(agent.handle_input("ls /srv"))
    assert "postgres" in listing["response"]
    assert "sync-oss.sh" not in listing["response"]
    secret = asyncio.run(agent.handle_input("cat /srv/backup/db.env"))
    assert "DB_PASS=Sync-2026-Apr" in secret["response"]
    assert "pg_hba.conf" in asyncio.run(agent.handle_input("ls /srv/postgres"))["response"]


def test_pivot_db_env_is_only_a_pointer():
    agent = _typed_agent("linux_server", "web-pivot-01")
    secret = asyncio.run(agent.handle_input("cat /srv/backup/db.env"))
    assert "DB_HOST=10.0.5.2" in secret["response"]
    assert "DB_PASS" not in secret["response"]
    assert "sync-oss.sh" in asyncio.run(agent.handle_input("ls /srv/backup"))["response"]


def test_oss_host_has_no_postgres_or_db_password():
    agent = _typed_agent("oss_gateway", "oss-sync-bridge")
    listing = asyncio.run(agent.handle_input("ls /srv"))
    assert "oss" in listing["response"]
    config = asyncio.run(agent.handle_input("cat /srv/oss/config"))
    assert "corp-finance-archive" in config["response"]
    assert "DB_PASS" not in config["response"]
    missing = asyncio.run(agent.handle_input("ls /srv/postgres"))
    assert "No such file" in missing["response"]
    assert "pg_hba.conf" not in missing["response"]


def test_id_does_not_claim_sudo_group():
    result = asyncio.run(_agent().handle_input("id"))
    assert "svc-backup" in result["response"]
    assert "sudo" not in result["response"]


def test_unhandled_probe_reaches_model_without_category_denial():
    class Model:
        is_configured = True
        async def chat(self, messages, **kwargs):
            return "root pts/1 10.0.5.1"
    agent = _agent()
    agent.dashscope_client = Model()
    result = asyncio.run(agent.handle_input("vmstat 1 1"))
    assert result["actor_mode"] == "model"
    assert result["response"] == "root pts/1 10.0.5.1"


def test_basic_terminal_commands_never_call_model():
    class NoModel:
        is_configured = True
        async def chat(self, *args, **kwargs):
            raise AssertionError("Basic terminal command called the model")
    agent = _agent()
    agent.dashscope_client = NoModel()
    for command, expected in (("clear", "\033[2J"), ("reset", "\033[2J"),
                              ("sudo", "usage: sudo"), ("sudo --help", "usage: sudo"),
                              ("sudo -V", "Sudo version")):
        result = asyncio.run(agent.handle_input(command))
        assert expected in result["response"]
        assert result["actor_mode"] == "interpreter"
    assert asyncio.run(agent.handle_input("rm logs"))["response"] == ""
    assert "logs" not in asyncio.run(agent.handle_input("ls"))["response"].split()


def test_interactive_model_timeout_cancels_request_and_allows_next_command(monkeypatch):
    import src.agents.sub_agent as module
    class SlowModel:
        is_configured = True
        cancelled = False
        async def chat(self, *args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True
    async def exercise():
        agent = _agent()
        slow = SlowModel()
        agent.dashscope_client = slow
        result = await agent.handle_input("vmstat 1 1")
        assert result["guardrail"] == "model_timeout"
        assert slow.cancelled
        assert (await agent.handle_input("pwd"))["actor_mode"] == "interpreter"
    monkeypatch.setattr(module, "INTERACTIVE_MODEL_TIMEOUT_SECONDS", 0.01)
    asyncio.run(exercise())
