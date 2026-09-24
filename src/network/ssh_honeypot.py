"""真实 SSH 接入：免登录凭据，一个连接对应一个连续的虚拟主机会话。"""
from __future__ import annotations

import asyncio
import logging
import re
import shlex
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

import asyncssh

SSH_USERNAME = "svc-backup"
logger = logging.getLogger(__name__)


def key_dir(root: Path | None = None) -> Path:
    return (root or Path(__file__).resolve().parents[2]) / "var" / "ssh"


def ensure_ssh_material(directory: Path) -> dict[str, Any]:
    """只保留 SSH 握手所需的服务器主机密钥，不生成客户端登录密钥。"""
    directory.mkdir(parents=True, exist_ok=True)
    host_path = directory / "host_ed25519"
    if not host_path.exists():
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(host_path))
    host_path.chmod(0o600)
    return {"host_key_path": host_path,
            "host_fingerprint": asyncssh.read_private_key(str(host_path)).get_fingerprint()}


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, *, main_agent: Any, initial_prompt: str,
                 connection_changed: Callable[[int], None], connections: set | None = None) -> None:
        self.main_agent = main_agent
        self.connection_changed = connection_changed
        self.connections = connections
        self.connection = None
        self.context = {"session_id": str(uuid4()), "prompt": initial_prompt,
                        "lock": asyncio.Lock()}

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.connection = conn
        if self.connections is not None:
            self.connections.add(conn)
        # Channel extra info falls through to its parent connection. Repeated exec
        # channels therefore retain the same world, unlike unrelated SSH connections.
        conn.set_extra_info(maze_context=self.context)
        self.connection_changed(1)

    def begin_auth(self, username: str) -> bool:
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        if self.connections is not None:
            self.connections.discard(self.connection)
        self.main_agent.release_session(self.context["session_id"])
        self.connection_changed(-1)


def write_channel(process: asyncssh.SSHServerProcess, text: str) -> None:
    """PTY 换行由 AsyncSSH line editor 处理；这里只归一化，避免 CRCRLF。"""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    process.stdout.write(normalized)


def sanitize_shell_input(raw: str) -> str:
    """去除终端颜色和控制字符，保留实际输入的命令。"""
    without_ansi = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
    return "".join(c for c in without_ansi if c in "\t\n\r" or ord(c) >= 32).strip()


async def serve_ssh_process(process: asyncssh.SSHServerProcess, *, main_agent: Any,
                            destination_port: int, initial_prompt: str) -> None:
    context = process.get_extra_info("maze_context")
    session_id = context["session_id"]
    source_ip = str(process.get_extra_info("peername")[0])

    async def run_line(payload: str) -> tuple[str, bool]:
        # A shared virtual cwd cannot be mutated concurrently by two exec channels.
        async with context["lock"]:
            result = await main_agent.handle_payload({
                "session_id": session_id, "source_ip": source_ip,
                "entry_asset_id": f"edge:ssh:{destination_port}",
                "protocol": "ssh", "destination_port": destination_port, "payload": payload,
            })
            context["prompt"] = result.get("prompt") or context["prompt"]
            return str(result.get("response") or ""), bool(result.get("close"))

    try:
        if process.command:
            payload = sanitize_shell_input(process.command)
            # SSH clients often submit a script via `bash -s`, rather than a PTY.
            # Consume that channel's stdin as virtual commands, never as host code.
            try:
                words = shlex.split(payload)
                while words and words[0].rsplit("/", 1)[-1] in {"bash", "sh"} and "-c" in words:
                    words = shlex.split(words[words.index("-c") + 1])
                if words and words[0].rsplit("/", 1)[-1] in {"bash", "sh"} and "-s" in words:
                    payload = sanitize_shell_input(await process.stdin.read())
            except (ValueError, IndexError):
                pass
            if payload:
                response, _ = await run_line(payload)
                if response:
                    write_channel(process, response.rstrip("\n") + "\n")
            process.exit(0)
            return
        write_channel(process, context["prompt"])
        async for line in process.stdin:
            payload = sanitize_shell_input(line)
            if payload:
                response, close = await run_line(payload)
                if response:
                    write_channel(process, response.rstrip("\n") + "\n")
                if close:
                    process.exit(0)
                    return
            write_channel(process, context["prompt"])
    except asyncssh.BreakReceived:
        pass
    except Exception:
        logger.exception("SSH session %s failed", session_id)
    finally:
        process.close()
