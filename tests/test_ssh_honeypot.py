import asyncio
from pathlib import Path

import asyncssh

from src.config import AppSettings
from src.network.ssh_honeypot import SSH_USERNAME, ensure_ssh_material
from src.network.traffic_engine import TrafficEngine


class _FakeAgent:
    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def handle_payload(self, event: dict) -> dict:
        self.payloads.append(str(event["payload"]))
        return {"response": "svc-backup", "prompt": "maze$ ", "close": False}


def test_lure_key_opens_real_ssh_and_reaches_shell(tmp_path: Path) -> None:
    asyncio.run(_exercise(tmp_path))


async def _exercise(tmp_path: Path) -> None:
    material = ensure_ssh_material(tmp_path / "ssh")
    settings = AppSettings(
        honeypot_bind_host="127.0.0.1",
        honeypot_ports="0",
        honeypot_protocols="ssh",
        honeypot_ssh_password="honeypot",
        dashscope_api_key="",
    )
    agent = _FakeAgent()
    engine = TrafficEngine(settings=settings, main_agent=agent)  # type: ignore[arg-type]
    engine.ssh_material = material
    acceptor = await engine._start_ssh(0)
    engine.ssh_acceptors.append(acceptor)
    port = acceptor.sockets[0].getsockname()[1]
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port,
            username=SSH_USERNAME,
            client_keys=[str(material["lure_private_key"])],
            known_hosts=None,
        ) as conn:
            result = await conn.run("whoami", check=False)
        assert result.exit_status == 0
        assert "svc-backup" in (result.stdout or "")
        assert agent.payloads == ["whoami"]

        wrong = asyncssh.generate_private_key("ssh-ed25519")
        wrong_path = tmp_path / "wrong"
        wrong.write_private_key(str(wrong_path))
        denied = False
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port,
                username=SSH_USERNAME,
                client_keys=[str(wrong_path)],
                known_hosts=None,
            ):
                pass
        except (asyncssh.PermissionDenied, asyncssh.DisconnectError):
            denied = True
        assert denied
        assert agent.payloads == ["whoami"]
    finally:
        acceptor.close()
        await acceptor.wait_closed()
