"""最外层真实 SSH 入口。

握手、主机密钥和用户认证走标准 SSH。认证通过后的 shell 只把每一行交给
主智能体，不在宿主机执行命令。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import asyncssh

SSH_USERNAME = "svc-backup"
logger = logging.getLogger(__name__)


def key_dir(root: Path | None = None) -> Path:
    base = root or Path(__file__).resolve().parents[2]
    return base / "var" / "ssh"


def ensure_ssh_material(directory: Path) -> dict[str, Any]:
    """生成或读取蜜罐自己的主机密钥和登录私钥。"""
    directory.mkdir(parents=True, exist_ok=True)
    host_path = directory / "host_ed25519"
    lure_path = directory / "lure_ed25519"
    _write_key_if_missing(host_path)
    _write_key_if_missing(lure_path)
    _tighten_key_mode(host_path)
    _tighten_key_mode(lure_path)
    host_key = asyncssh.read_private_key(str(host_path))
    lure_private = asyncssh.read_private_key(str(lure_path))
    lure_public = asyncssh.read_public_key(str(lure_path) + ".pub")
    return {
        "host_key_path": host_path,
        "lure_private_key": lure_path,
        "host_fingerprint": host_key.get_fingerprint(),
        "lure_public": lure_public,
        "lure_private": lure_private,
    }


def _tighten_key_mode(path: Path) -> None:
    if path.exists():
        path.chmod(0o600)
    pub = Path(str(path) + ".pub")
    if pub.exists():
        pub.chmod(0o644)


def _write_key_if_missing(path: Path) -> None:
    if path.exists():
        return
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(path))
    key.write_public_key(str(path) + ".pub")
    path.chmod(0o600)
    Path(str(path) + ".pub").chmod(0o644)
    logger.info("Generated honeypot SSH key %s", path.name)


class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, *, username: str, password: str, lure_public: Any) -> None:
        self._username = username
        self._password = password
        self._lure_public = lure_public

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == self._username and password == self._password

    def validate_public_key(self, username: str, key: Any) -> bool:
        if username != self._username:
            return False
        try:
            return key.get_fingerprint() == self._lure_public.get_fingerprint()
        except Exception:
            logger.debug("Rejected unreadable public key", exc_info=True)
            return False


def sanitize_shell_input(raw: str) -> str:
    without_ansi = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
    without_controls = "".join(char for char in without_ansi if char in {"\t", "\n", "\r"} or ord(char) >= 32)
    return without_controls.strip()


async def serve_ssh_process(
    process: asyncssh.SSHServerProcess,
    *,
    main_agent: Any,
    destination_port: int,
    initial_prompt: str,
) -> None:
    """一个已认证的 shell 或 exec 通道。命令只进仿真管道。"""
    peer = process.get_extra_info("peername") or ("unknown", 0)
    source_ip = str(peer[0])
    session_id = str(uuid4())
    prompt = initial_prompt
    entry_asset_id = f"edge:ssh:{destination_port}"

    async def run_line(payload: str) -> tuple[str, str, bool]:
        result = await main_agent.handle_payload(
            {
                "session_id": session_id,
                "source_ip": source_ip,
                "destination_port": destination_port,
                "protocol": "ssh",
                "payload": payload,
                "entry_asset_id": entry_asset_id,
            }
        )
        response = str(result.get("response") or "")
        next_prompt = prompt
        override = result.get("prompt")
        if isinstance(override, str) and override:
            next_prompt = override
        return response, next_prompt, bool(result.get("close"))

    try:
        command = getattr(process, "command", None)
        if command:
            payload = sanitize_shell_input(str(command))
            if payload:
                response, _, _ = await run_line(payload)
                if response:
                    process.stdout.write(response if response.endswith("\n") else response + "\n")
            process.exit(0)
            return

        process.stdout.write(f"Last login: Tue Apr 21 23:14:02 2026 from 10.0.4.8\r\n{prompt}")
        while not process.stdin.at_eof():
            line = await process.stdin.readline()
            if not line:
                break
            payload = sanitize_shell_input(line)
            if not payload:
                process.stdout.write(prompt)
                continue
            response, prompt, close = await run_line(payload)
            if response:
                process.stdout.write(response if response.endswith("\n") else response + "\n")
            if close:
                break
            process.stdout.write(prompt)
    except asyncssh.BreakReceived:
        pass
    except Exception:
        logger.exception("SSH honeypot session %s failed", session_id)
    finally:
        process.close()
