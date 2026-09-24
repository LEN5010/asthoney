import asyncio
from pathlib import Path
import asyncssh
from src.config import AppSettings
from src.network.ssh_honeypot import SSH_USERNAME, ensure_ssh_material
from src.network.traffic_engine import TrafficEngine


class _FakeAgent:
    def __init__(self):
        self.events = []
        self.released = []

    async def handle_payload(self, event):
        self.events.append(event)
        return {"response": "svc-backup", "prompt": "maze$ ", "close": False}

    def release_session(self, session_id):
        self.released.append(session_id)


def test_passwordless_ssh_shares_channels_but_not_connections(tmp_path: Path):
    asyncio.run(_exercise(tmp_path))


async def _exercise(tmp_path):
    material = ensure_ssh_material(tmp_path / "ssh")
    assert set(material) == {"host_key_path", "host_fingerprint"}
    settings = AppSettings(_env_file=None, honeypot_bind_host="127.0.0.1", honeypot_ports="0", honeypot_protocols="ssh")
    agent = _FakeAgent()
    engine = TrafficEngine(settings=settings, main_agent=agent)
    engine.ssh_material = material
    acceptor = await engine._start_ssh(0)
    port = acceptor.sockets[0].getsockname()[1]
    try:
        async with asyncssh.connect("127.0.0.1", port, username=SSH_USERNAME,
                                    client_keys=[], agent_path=None, known_hosts=None) as conn:
            for command in ("whoami", "pwd"):
                result = await conn.run(command, check=True)
                assert "svc-backup" in result.stdout
            assert engine.active_connection_count == 1
        async with asyncssh.connect("127.0.0.1", port, username=SSH_USERNAME,
                                    client_keys=[], agent_path=None, known_hosts=None) as conn:
            await conn.run("whoami", check=True)
        assert agent.events[0]["session_id"] == agent.events[1]["session_id"]
        assert agent.events[2]["session_id"] != agent.events[0]["session_id"]
    finally:
        acceptor.close()
        await acceptor.wait_closed()


def test_stop_disconnects_active_ssh_before_reset(tmp_path):
    async def run():
        agent = _FakeAgent()
        settings = AppSettings(_env_file=None, honeypot_bind_host="127.0.0.1", honeypot_ports="0", honeypot_protocols="ssh")
        engine = TrafficEngine(settings=settings, main_agent=agent)
        engine.ssh_material = ensure_ssh_material(tmp_path / "reset-key")
        await engine.start()
        port = engine.ssh_acceptors[0].sockets[0].getsockname()[1]
        conn = await asyncssh.connect("127.0.0.1", port, username=SSH_USERNAME,
                                     client_keys=[], agent_path=None, known_hosts=None)
        await conn.run("whoami")
        await engine.stop()
        await asyncio.wait_for(conn.wait_closed(), timeout=2)
        assert engine.active_connection_count == 0
        assert not engine.ssh_connections and not engine.client_tasks
        assert agent.released
        await engine.start()
        assert engine.ssh_acceptors
        await engine.stop()
    asyncio.run(run())


def test_ssh_exec_stdin_script_is_not_dropped(tmp_path):
    async def run():
        agent = _FakeAgent()
        settings = AppSettings(_env_file=None, honeypot_bind_host='127.0.0.1', honeypot_ports='0', honeypot_protocols='ssh')
        engine = TrafficEngine(settings=settings, main_agent=agent)
        engine.ssh_material = ensure_ssh_material(tmp_path/'stdin-key')
        await engine.start()
        port = engine.ssh_acceptors[0].sockets[0].getsockname()[1]
        try:
            async with asyncssh.connect('127.0.0.1',port,username=SSH_USERNAME,client_keys=[],agent_path=None,known_hosts=None) as conn:
                await conn.run('/bin/bash -s',input='id -u\nhostname\n',check=True)
                assert agent.events[-1]['payload'] == 'id -u\nhostname'
        finally: await engine.stop()
    asyncio.run(run())
