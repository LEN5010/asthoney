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
