from __future__ import annotations

import asyncio
import logging
import re
from contextlib import suppress
from typing import Any
from uuid import uuid4

import asyncssh

from src.agents.main_agent import MainAgent
from src.config import AppSettings
from src.network.ssh_honeypot import (
    HoneypotSSHServer,
    SSH_USERNAME,
    ensure_ssh_material,
    key_dir,
    serve_ssh_process,
)


class TrafficEngine:
    def __init__(self, *, settings: AppSettings, main_agent: MainAgent) -> None:
        self.settings = settings
        self.main_agent = main_agent
        self.logger = logging.getLogger(self.__class__.__name__)
        self.servers: list[asyncio.AbstractServer] = []
        self.ssh_acceptors: list[asyncssh.SSHAcceptor] = []
        self.ssh_material: dict[str, Any] | None = None
        self.active_connection_count = 0

    async def start(self) -> None:
        protocols = self.settings.honeypot_protocol_list
        ports = self.settings.honeypot_ports_list
        for index, port in enumerate(ports):
            protocol = protocols[min(index, len(protocols) - 1)]
            if protocol == "ssh":
                acceptor = await self._start_ssh(port)
                self.ssh_acceptors.append(acceptor)
                sockets = ", ".join(str(sock.getsockname()) for sock in acceptor.sockets or [])
                self.logger.info(
                    "Listening for real SSH on %s fingerprint %s",
                    sockets,
                    (self.ssh_material or {}).get("host_fingerprint"),
                )
                continue
            server = await asyncio.start_server(
                lambda reader, writer, protocol=protocol: self._handle_client(reader, writer, protocol),
                host=self.settings.honeypot_bind_host,
                port=port,
            )
            self.servers.append(server)
            sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
            self.logger.info("Listening for %s traffic on %s", protocol, sockets)

    async def _start_ssh(self, port: int) -> asyncssh.SSHAcceptor:
        if self.ssh_material is None:
            self.ssh_material = ensure_ssh_material(key_dir())
        material = self.ssh_material
        username = SSH_USERNAME
        password = self.settings.honeypot_ssh_password
        lure_public = material["lure_public"]

        def server_factory() -> HoneypotSSHServer:
            return HoneypotSSHServer(username=username, password=password, lure_public=lure_public)

        async def process_factory(process: asyncssh.SSHServerProcess) -> None:
            self.active_connection_count += 1
            try:
                await serve_ssh_process(
                    process,
                    main_agent=self.main_agent,
                    destination_port=port,
                    initial_prompt=self.settings.honeypot_write_prompt,
                )
            finally:
                self.active_connection_count = max(0, self.active_connection_count - 1)

        return await asyncssh.create_server(
            server_factory,
            self.settings.honeypot_bind_host,
            port,
            server_host_keys=[str(material["host_key_path"])],
            process_factory=process_factory,
            server_version=self.settings.honeypot_ssh_banner,
            encoding="utf-8",
        )

    async def stop(self) -> None:
        for server in self.servers:
            server.close()
            await server.wait_closed()
        self.servers.clear()
        for acceptor in self.ssh_acceptors:
            acceptor.close()
            await acceptor.wait_closed()
        self.ssh_acceptors.clear()

    def ssh_public_status(self) -> dict[str, Any]:
        material = self.ssh_material or {}
        lure_path = material.get("lure_private_key")
        return {
            "ssh_username": SSH_USERNAME,
            "ssh_host_fingerprint": material.get("host_fingerprint"),
            "ssh_lure_private_key": str(lure_path) if lure_path else None,
            "ssh_password_login": bool(self.settings.honeypot_ssh_password),
        }

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        protocol: str,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        sockname = writer.get_extra_info("sockname") or ("unknown", 0)
        source_ip = str(peer[0])
        destination_port = int(sockname[1])
        session_id = str(uuid4())
        entry_asset_id = f"edge:{protocol}:{destination_port}"
        active_prompt = self.settings.honeypot_write_prompt
        close_after_write = False
        prompt_locked = False
        entry_blank_prompt_rendered = True
        self.active_connection_count += 1

        self.logger.info(
            "Accepted %s session %s from %s to port %s",
            protocol,
            session_id,
            source_ip,
            destination_port,
        )

        try:
            if protocol == "ssh":
                await self._write_line(writer, self.settings.honeypot_ssh_banner)
                client_banner = await self._safe_readline(reader)
                if client_banner:
                    self.logger.debug("Client %s banner: %s", source_ip, client_banner.strip())
                await self._write_raw(writer, b"Authorized access only.\r\n")
                await self._write_raw(writer, active_prompt.encode("utf-8"))
            else:
                await self._write_line(writer, "220 maze-tcp edge ready")

            while not reader.at_eof():
                raw = await self._safe_readline(reader)
                if raw is None:
                    break
                payload = self._sanitize_input(raw)
                if not payload:
                    if prompt_locked or not entry_blank_prompt_rendered:
                        await self._write_raw(writer, active_prompt.encode("utf-8"))
                        entry_blank_prompt_rendered = True
                    continue
                entry_blank_prompt_rendered = False

                result = await self.main_agent.handle_payload(
                    {
                        "session_id": session_id,
                        "source_ip": source_ip,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "payload": payload,
                        "entry_asset_id": entry_asset_id,
                    }
                )
                response = str(result.get("response", ""))
                close_after_write = bool(result.get("close", False))
                prompt_override = result.get("prompt")
                if isinstance(prompt_override, str) and prompt_override:
                    active_prompt = prompt_override
                    prompt_locked = True

                if response:
                    await self._write_response(writer, response)
                if not close_after_write:
                    await self._write_raw(writer, active_prompt.encode("utf-8"))
                    entry_blank_prompt_rendered = True
                else:
                    break
        except ConnectionResetError:
            self.logger.warning("Connection reset by peer %s for session %s", source_ip, session_id)
        except Exception:
            self.logger.exception("Unhandled error in session %s", session_id)
        finally:
            if close_after_write:
                with suppress(ConnectionResetError):
                    await writer.drain()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            self.active_connection_count = max(0, self.active_connection_count - 1)
            if prompt_locked:
                self.logger.debug("Released locked prompt for session %s", session_id)
            self.logger.info("Closed session %s from %s", session_id, source_ip)

    async def _safe_readline(self, reader: asyncio.StreamReader) -> str | None:
        try:
            data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.settings.honeypot_read_timeout_seconds,
            )
            if not data:
                return None
            return data.decode("utf-8", errors="ignore")
        except asyncio.TimeoutError:
            return None

    async def _write_line(self, writer: asyncio.StreamWriter, message: str) -> None:
        if not message.endswith("\n"):
            message = f"{message}\n"
        await self._write_raw(writer, message.encode("utf-8"))

    async def _write_response(self, writer: asyncio.StreamWriter, message: str) -> None:
        if message.startswith("\033"):
            await self._write_raw(writer, message.encode("utf-8"))
            return
        await self._write_line(writer, message)

    async def _write_raw(self, writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(payload)
        await writer.drain()

    def _sanitize_input(self, raw: str) -> str:
        without_ansi = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
        without_controls = "".join(
            char for char in without_ansi if char in {"\t", "\n", "\r"} or ord(char) >= 32
        )
        return without_controls.strip()

    def listener_summary(self) -> list[dict[str, Any]]:
        listeners: list[dict[str, Any]] = []
        for server in [*self.ssh_acceptors, *self.servers]:
            for sock in server.sockets or []:
                host, port = sock.getsockname()[:2]
                listeners.append({"host": host, "port": port})
        return listeners

    def metrics_snapshot(self) -> dict[str, int]:
        return {"active_connections": self.active_connection_count}
